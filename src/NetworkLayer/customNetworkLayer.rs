
use core::str;
use std::{fmt, future::Future, pin::Pin, sync::Arc, task::{Context, Poll}, time::Duration};

use crate::{dns::{gai::GaiResolver, resolve::{DnsResolverWithOverrides, DynResolver}, Resolve}, into_url::IntoUrl, Error, Method, NetworkLayer::{config::{Config, HTTPVersion}, redirect::remove_sensitive_headers, tls}, Proxy, StatusCode, Url};
use http::{header::{
    Entry, HeaderMap, HeaderValue, ACCEPT, ACCEPT_ENCODING, CONTENT_ENCODING, CONTENT_LENGTH,
    CONTENT_TYPE, LOCATION, PROXY_AUTHORIZATION, RANGE, REFERER, TRANSFER_ENCODING, USER_AGENT,
}, uri::Scheme, Uri};
use log::debug;
use pin_project_lite::pin_project;
use tokio::time::Sleep;
use super::{into_url::try_uri, request::{Request, RequestBuilder}};
use super::response::Response;
use crate::error;
use hyper_util::client::legacy::connect::HttpConnector;
use quinn::crypto::HeaderKey;
use crate::NetworkLayer::connect::Connector;
use crate::NetworkLayer::body::Body;
use super::{cookie, decoder::Accepts, redirect};

#[derive(Clone)]
pub struct Client {
    inner: Arc<ClientRef>,
}

pub struct ClientBuilder {
    config: Config
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientBuilder {
    pub fn new() -> ClientBuilder {
        ClientBuilder {
            config: Config::default()
        }
    }

    pub fn build(self) -> crate::Result<Client> {
        let config: Config = self.config;

        if let Some(err) = config.error {
            return Err(err);
        }

        // Initialize Proxies
        let mut proxies = config.proxies;
        println!("proxies: {:?}", proxies);
        let proxies = Arc::new(proxies);


        // Initialize Connector
        let mut connector = {
            // Initialize default resolver
            let mut resolver: Arc<dyn Resolve> = Arc::new(GaiResolver::new());
            if let Some(dns_resolver) = config.dns_settings.dns_resolver {
                resolver = dns_resolver;
            }
            if !config.dns_settings.dns_overrides.is_empty() {
                resolver = Arc::new(DnsResolverWithOverrides::new(
                    resolver,
                    config.dns_settings.dns_overrides,
                ));
            }
            let mut http = HttpConnector::new_with_resolver(DynResolver::new(resolver.clone()));
            http.set_connect_timeout(config.connection_settings.connect_timeout);

            use crate::NetworkLayer::tls::{IgnoreHostname, NoVerifier};

            // Set root certificates.
            let mut root_cert_store = rustls::RootCertStore::empty();
            for cert in config.tls_settings.root_certs {
                cert.add_to_rustls(&mut root_cert_store)?;
            }

            if config.tls_settings.tls_built_in_certs_webpki {
                root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            }

            if config.tls_settings.tls_built_in_certs_native {
                let mut valid_count = 0;
                let mut invalid_count = 0;
                for cert in rustls_native_certs::load_native_certs()
                    .map_err(crate::error::builder)?
                {
                    // Continue on parsing errors, as native stores often include ancient or syntactically
                    // invalid certificates, like root certificates without any X509 extensions.
                    // Inspiration: https://github.com/rustls/rustls/blob/633bf4ba9d9521a95f68766d04c22e2b01e68318/rustls/src/anchors.rs#L105-L112
                    match root_cert_store.add(cert.into()) {
                        Ok(_) => valid_count += 1,
                        Err(err) => {
                            invalid_count += 1;
                            log::debug!("rustls failed to parse DER certificate: {err:?}");
                        }
                    }
                }
                if valid_count == 0 && invalid_count > 0 {
                    return Err(crate::error::builder(
                        "zero valid certificates found in native root store",
                    ));
                }
            }

            // Set TLS versions.
            let mut versions = rustls::ALL_VERSIONS.to_vec();

            if let Some(min_tls_version) = config.tls_settings.min_tls_version {
                versions.retain(|&supported_version| {
                    match tls::Version::from_rustls(supported_version.version) {
                        Some(version) => version >= min_tls_version,
                        // Assume it's so new we don't know about it, allow it
                        // (as of writing this is unreachable)
                        None => true,
                    }
                });
            }

            if let Some(max_tls_version) = config.tls_settings.max_tls_version {
                versions.retain(|&supported_version| {
                    match tls::Version::from_rustls(supported_version.version) {
                        Some(version) => version <= max_tls_version,
                        None => false,
                    }
                });
            }

            if versions.is_empty() {
                return Err(crate::error::builder("empty supported tls versions"));
            }

            // Allow user to have installed a runtime default.
            // If not, we use ring.
            let provider = rustls::crypto::CryptoProvider::get_default()
                .map(|arc| arc.clone())
                .unwrap_or_else(|| {
                    Arc::new(rustls::crypto::ring::default_provider())
                });

            // Build TLS config
            let signature_algorithms = provider.signature_verification_algorithms;
            let config_builder = rustls::ClientConfig::builder_with_provider(provider)
                .with_protocol_versions(&versions)
                .map_err(|_| crate::error::builder("invalid TLS versions"))?;

            let config_builder = if !config.tls_settings.certs_verification {
                config_builder
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(NoVerifier))
            } else if !config.tls_settings.hostname_verification {
                config_builder
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(IgnoreHostname::new(
                        root_cert_store,
                        signature_algorithms,
                    )))
            } else {
                config_builder.with_root_certificates(root_cert_store)
            };

            // Finalize TLS config
            let mut tls = {
                config_builder.with_no_client_auth()
            };

            tls.enable_sni = config.tls_settings.tls_sni;

            // ALPN protocol
            match config.http_version {
                HTTPVersion::HTTP1 => {
                    tls.alpn_protocols = vec!["http/1.1".into()];
                }
                HTTPVersion::HTTP2 => {
                    tls.alpn_protocols = vec!["h2".into()];
                }
                HTTPVersion::HTTP3 => {
                    tls.alpn_protocols = vec!["h3".into()];
                }
                HTTPVersion::ALL => {
                    tls.alpn_protocols = vec![
                        "h2".into(),
                        "http/1.1".into(),
                    ];
                }
            }
            fn user_agent(headers: &HeaderMap) -> Option<HeaderValue> {
                headers.get(USER_AGENT).cloned()
            }
            Connector::new_rustls_tls(
                http,
                tls,
                proxies.clone(),
                user_agent(&config.headers),
                config.connection_settings.local_address,
                config.connection_settings.interface.as_deref(),
                config.connection_settings.nodelay,
                config.tls_settings.tls_info,
            )

        };
        connector.set_timeout(config.connection_settings.connect_timeout);
        connector.set_verbose(config.connection_settings.connection_verbose);

        let mut builder =
            hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new());
        if matches!(config.http_version, HTTPVersion::HTTP2) {
            builder.http2_only(true);
        }

        if let Some(http2_initial_stream_window_size) = config.http2_settings.http2_initial_stream_window_size
        {
            builder.http2_initial_stream_window_size(http2_initial_stream_window_size);
        }
        if let Some(http2_initial_connection_window_size) =
        config.http2_settings.http2_initial_connection_window_size
        {
            builder.http2_initial_connection_window_size(http2_initial_connection_window_size);
        }
        if config.http2_settings.http2_adaptive_window {
            builder.http2_adaptive_window(true);
        }
        if let Some(http2_max_frame_size) = config.http2_settings.http2_max_frame_size {
            builder.http2_max_frame_size(http2_max_frame_size);
        }
        if let Some(http2_keep_alive_interval) = config.http2_settings.http2_keep_alive_interval {
            builder.http2_keep_alive_interval(http2_keep_alive_interval);
        }
        if let Some(http2_keep_alive_timeout) = config.http2_settings.http2_keep_alive_timeout {
            builder.http2_keep_alive_timeout(http2_keep_alive_timeout);
        }
        if config.http2_settings.http2_keep_alive_while_idle {
            builder.http2_keep_alive_while_idle(true);
        }

        builder.pool_idle_timeout(config.connection_settings.pool_idle_timeout);
        builder.pool_max_idle_per_host(config.connection_settings.pool_max_idle_per_host);
        connector.set_keepalive(config.connection_settings.tcp_keepalive);

        if config.http1_settings.http09_responses {
            builder.http09_responses(true);
        }

        if config.http1_settings.http1_title_case_headers {
            builder.http1_title_case_headers(true);
        }

        if config.http1_settings.http1_allow_obsolete_multiline_headers_in_responses {
            builder.http1_allow_obsolete_multiline_headers_in_responses(true);
        }

        if config.http1_settings.http1_ignore_invalid_headers_in_responses {
            builder.http1_ignore_invalid_headers_in_responses(true);
        }

        if config.http1_settings.http1_allow_spaces_after_header_name_in_responses {
            builder.http1_allow_spaces_after_header_name_in_responses(true);
        }

        let proxies_maybe_http_auth = proxies.iter().any(|p| p.maybe_has_http_auth());

        Ok(Client {
            inner: Arc::new(ClientRef {
                accepts: config.accepts,
                cookie_store: config.cookie_settings.cookie_store,
                hyper: builder.build(connector),
                headers: config.headers,
                redirect_policy: config.redirect_settings.redirect_policy,
                referer: config.referer,
                read_timeout: config.connection_settings.read_timeout,
                request_timeout: config.connection_settings.connect_timeout,
                proxies,
                proxies_maybe_http_auth,
                https_only: config.tls_settings.https_only,
            }),
        })      
    }

    pub fn default_headers(mut self, headers: HeaderMap) -> ClientBuilder {
        for (key, value) in headers.iter() {
            self.config.headers.insert(key, value.clone());
        }
        self
    }

    pub fn cookie_store(mut self, enable: bool) -> ClientBuilder {
        if enable {
            self.cookie_provider(Arc::new(cookie::Jar::default()))
        } else {
            self.config.cookie_settings.cookie_store = None;
            self
        }
    }
    pub fn cookie_provider<C: cookie::CookieStore + 'static>(
    mut self,
        cookie_store: Arc<C>,
    ) -> ClientBuilder {
        self.config.cookie_settings.cookie_store = Some(cookie_store as _);
        self
    }
}

type HyperClient = hyper_util::client::legacy::Client<Connector, Body>;

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

impl Client {
    /// Constructs a new `Client`.
    ///
    /// # Panics
    ///
    /// This method panics if a TLS backend cannot be initialized, or the resolver
    /// cannot load the system configuration.
    ///
    /// Use `Client::builder()` if you wish to handle the failure as an `Error`
    /// instead of panicking.
    pub fn new() -> Client {
        ClientBuilder::new().build().expect("Client::new()")
    }

    /// Creates a `ClientBuilder` to configure a `Client`.
    ///
    /// This is the same as `ClientBuilder::new()`.
    pub fn builder() -> ClientBuilder {
        ClientBuilder::new()
    }

    /// Convenience method to make a `GET` request to a URL.
    ///
    /// # Errors
    ///
    /// This method fails whenever the supplied `Url` cannot be parsed.
    pub fn get<U: IntoUrl>(&self, url: U) -> RequestBuilder {
        self.request(Method::GET, url)
    }

    /// Convenience method to make a `POST` request to a URL.
    ///
    /// # Errors
    ///
    /// This method fails whenever the supplied `Url` cannot be parsed.
    pub fn post<U: IntoUrl>(&self, url: U) -> RequestBuilder {
        self.request(Method::POST, url)
    }

    /// Convenience method to make a `PUT` request to a URL.
    ///
    /// # Errors
    ///
    /// This method fails whenever the supplied `Url` cannot be parsed.
    pub fn put<U: IntoUrl>(&self, url: U) -> RequestBuilder {
        self.request(Method::PUT, url)
    }

    /// Convenience method to make a `PATCH` request to a URL.
    ///
    /// # Errors
    ///
    /// This method fails whenever the supplied `Url` cannot be parsed.
    pub fn patch<U: IntoUrl>(&self, url: U) -> RequestBuilder {
        self.request(Method::PATCH, url)
    }

    /// Convenience method to make a `DELETE` request to a URL.
    ///
    /// # Errors
    ///
    /// This method fails whenever the supplied `Url` cannot be parsed.
    pub fn delete<U: IntoUrl>(&self, url: U) -> RequestBuilder {
        self.request(Method::DELETE, url)
    }

    /// Convenience method to make a `HEAD` request to a URL.
    ///
    /// # Errors
    ///
    /// This method fails whenever the supplied `Url` cannot be parsed.
    pub fn head<U: IntoUrl>(&self, url: U) -> RequestBuilder {
        self.request(Method::HEAD, url)
    }

    /// Start building a `Request` with the `Method` and `Url`.
    ///
    /// Returns a `RequestBuilder`, which will allow setting headers and
    /// the request body before sending.
    ///
    /// # Errors
    ///
    /// This method fails whenever the supplied `Url` cannot be parsed.
    pub fn request<U: IntoUrl>(&self, method: Method, url: U) -> RequestBuilder {
        let req = url.into_url().map(move |url| Request::new(method, url));
        RequestBuilder::new(self.clone(), req)
    }

    /// Executes a `Request`.
    ///
    /// A `Request` can be built manually with `Request::new()` or obtained
    /// from a RequestBuilder with `RequestBuilder::build()`.
    ///
    /// You should prefer to use the `RequestBuilder` and
    /// `RequestBuilder::send()`.
    ///
    /// # Errors
    ///
    /// This method fails if there was an error while sending request,
    /// redirect loop was detected or redirect limit was exhausted.
    pub fn execute(
        &self,
        request: Request,
    ) -> impl Future<Output = Result<Response, crate::Error>> {
        self.execute_request(request)
    }

    pub(super) fn execute_request(&self, req: Request) -> Pending {
        let (method, url, mut headers, body, timeout, version) = req.pieces();
        if url.scheme() != "http" && url.scheme() != "https" {
            return Pending::new_err(error::url_bad_scheme(url));
        }

        // check if we're in https_only mode and check the scheme of the current URL
        if self.inner.https_only && url.scheme() != "https" {
            return Pending::new_err(error::url_bad_scheme(url));
        }

        // insert default headers in the request headers
        // without overwriting already appended headers.
        for (key, value) in &self.inner.headers {
            if let Entry::Vacant(entry) = headers.entry(key) {
                entry.insert(value.clone());
            }
        }

        // Add cookies from the cookie store.
        #[cfg(feature = "cookies")]
        {
            if let Some(cookie_store) = self.inner.cookie_store.as_ref() {
                if headers.get(crate::header::COOKIE).is_none() {
                    add_cookie_header(&mut headers, &**cookie_store, &url);
                }
            }
        }

        let accept_encoding = self.inner.accepts.as_str();

        if let Some(accept_encoding) = accept_encoding {
            if !headers.contains_key(ACCEPT_ENCODING) && !headers.contains_key(RANGE) {
                headers.insert(ACCEPT_ENCODING, HeaderValue::from_static(accept_encoding));
            }
        }

        let uri = match try_uri(&url) {
            Ok(uri) => uri,
            _ => return Pending::new_err(error::url_invalid_uri(url)),
        };

        let (reusable, body) = match body {
            Some(body) => {
                let (reusable, body) = body.try_reuse();
                (Some(reusable), body)
            }
            None => (None, Body::empty()),
        };

        self.proxy_auth(&uri, &mut headers);

        let builder = hyper::Request::builder()
            .method(method.clone())
            .uri(uri)
            .version(version);

        let in_flight = match version {
            #[cfg(feature = "http3")]
            http::Version::HTTP_3 if self.inner.h3_client.is_some() => {
                let mut req = builder.body(body).expect("valid request parts");
                *req.headers_mut() = headers.clone();
                ResponseFuture::H3(self.inner.h3_client.as_ref().unwrap().request(req))
            }
            _ => {
                let mut req = builder.body(body).expect("valid request parts");
                *req.headers_mut() = headers.clone();
                ResponseFuture::Default(self.inner.hyper.request(req))
            }
        };

        let total_timeout = timeout
            .or(self.inner.request_timeout)
            .map(tokio::time::sleep)
            .map(Box::pin);

        let read_timeout_fut = self
            .inner
            .read_timeout
            .map(tokio::time::sleep)
            .map(Box::pin);

        Pending {
            inner: PendingInner::Request(PendingRequest {
                method,
                url,
                headers,
                body: reusable,

                urls: Vec::new(),

                retry_count: 0,

                client: self.inner.clone(),

                in_flight,
                total_timeout,
                read_timeout_fut,
                read_timeout: self.inner.read_timeout,
            }),
        }
    }

    fn proxy_auth(&self, dst: &Uri, headers: &mut HeaderMap) {
        if !self.inner.proxies_maybe_http_auth {
            return;
        }

        // Only set the header here if the destination scheme is 'http',
        // since otherwise, the header will be included in the CONNECT tunnel
        // request instead.
        if dst.scheme() != Some(&Scheme::HTTP) {
            return;
        }

        if headers.contains_key(PROXY_AUTHORIZATION) {
            return;
        }

        for proxy in self.inner.proxies.iter() {
            if proxy.is_match(dst) {
                if let Some(header) = proxy.http_basic_auth(dst) {
                    headers.insert(PROXY_AUTHORIZATION, header);
                }

                break;
            }
        }
    }
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut builder = f.debug_struct("Client");
        self.inner.fmt_fields(&mut builder);
        builder.finish()
    }
}

impl tower_service::Service<Request> for Client {
    type Response = Response;
    type Error = crate::Error;
    type Future = Pending;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request) -> Self::Future {
        self.execute_request(req)
    }
}

impl tower_service::Service<Request> for &'_ Client {
    type Response = Response;
    type Error = crate::Error;
    type Future = Pending;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request) -> Self::Future {
        self.execute_request(req)
    }
}

impl fmt::Debug for ClientBuilder {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut builder = f.debug_struct("ClientBuilder");
        self.config.fmt_fields(&mut builder);
        builder.finish()
    }
}

impl Config {
    fn fmt_fields(&self, f: &mut fmt::DebugStruct<'_, '_>) {
        // Instead of deriving Debug, only print fields when their output
        // would provide relevant or interesting data.
    }
}

struct ClientRef {
    accepts: Accepts,
    cookie_store: Option<Arc<dyn cookie::CookieStore>>,
    headers: HeaderMap,
    hyper: HyperClient,
    #[cfg(feature = "http3")]
    h3_client: Option<H3Client>,
    redirect_policy: redirect::Policy,
    referer: bool,
    request_timeout: Option<Duration>,
    read_timeout: Option<Duration>,
    proxies: Arc<Vec<Proxy>>,
    proxies_maybe_http_auth: bool,
    https_only: bool,
}

impl ClientRef {
    fn fmt_fields(&self, f: &mut fmt::DebugStruct<'_, '_>) {
        // Instead of deriving Debug, only print fields when their output
        // would provide relevant or interesting data.

        #[cfg(feature = "cookies")]
        {
            if let Some(_) = self.cookie_store {
                f.field("cookie_store", &true);
            }
        }

        f.field("accepts", &self.accepts);

        if !self.proxies.is_empty() {
            f.field("proxies", &self.proxies);
        }

        if !self.redirect_policy.is_default() {
            f.field("redirect_policy", &self.redirect_policy);
        }

        if self.referer {
            f.field("referer", &true);
        }

        f.field("default_headers", &self.headers);

        if let Some(ref d) = self.request_timeout {
            f.field("timeout", d);
        }

        if let Some(ref d) = self.read_timeout {
            f.field("read_timeout", d);
        }
    }
}

pin_project! {
    pub struct Pending {
        #[pin]
        inner: PendingInner,
    }
}

enum PendingInner {
    Request(PendingRequest),
    Error(Option<crate::Error>),
}

use bytes::Bytes;

pin_project! {
    struct PendingRequest {
        method: Method,
        url: Url,
        headers: HeaderMap,
        body: Option<Option<Bytes>>,

        urls: Vec<Url>,

        retry_count: usize,

        client: Arc<ClientRef>,

        #[pin]
        in_flight: ResponseFuture,
        #[pin]
        total_timeout: Option<Pin<Box<Sleep>>>,
        #[pin]
        read_timeout_fut: Option<Pin<Box<Sleep>>>,
        read_timeout: Option<Duration>,
    }
}

type HyperResponseFuture = hyper_util::client::legacy::ResponseFuture;


enum ResponseFuture {
    Default(HyperResponseFuture),
    #[cfg(feature = "http3")]
    H3(H3ResponseFuture),
}

impl PendingRequest {
    fn in_flight(self: Pin<&mut Self>) -> Pin<&mut ResponseFuture> {
        self.project().in_flight
    }

    fn total_timeout(self: Pin<&mut Self>) -> Pin<&mut Option<Pin<Box<Sleep>>>> {
        self.project().total_timeout
    }

    fn read_timeout(self: Pin<&mut Self>) -> Pin<&mut Option<Pin<Box<Sleep>>>> {
        self.project().read_timeout_fut
    }

    fn urls(self: Pin<&mut Self>) -> &mut Vec<Url> {
        self.project().urls
    }

    fn headers(self: Pin<&mut Self>) -> &mut HeaderMap {
        self.project().headers
    }


    fn retry_error(mut self: Pin<&mut Self>, err: &(dyn std::error::Error + 'static)) -> bool {
        use log::trace;

        if !is_retryable_error(err) {
            return false;
        }

        trace!("can retry {err:?}");

        let body = match self.body {
            Some(Some(ref body)) => Body::reusable(body.clone()),
            Some(None) => {
                debug!("error was retryable, but body not reusable");
                return false;
            }
            None => Body::empty(),
        };

        if self.retry_count >= 2 {
            trace!("retry count too high");
            return false;
        }
        self.retry_count += 1;

        // If it parsed once, it should parse again
        let uri = try_uri(&self.url).expect("URL was already validated as URI");

        *self.as_mut().in_flight().get_mut() = match *self.as_mut().in_flight().as_ref() {
            #[cfg(feature = "http3")]
            ResponseFuture::H3(_) => {
                let mut req = hyper::Request::builder()
                    .method(self.method.clone())
                    .uri(uri)
                    .body(body)
                    .expect("valid request parts");
                *req.headers_mut() = self.headers.clone();
                ResponseFuture::H3(
                    self.client
                        .h3_client
                        .as_ref()
                        .expect("H3 client must exists, otherwise we can't have a h3 request here")
                        .request(req),
                )
            }
            _ => {
                let mut req = hyper::Request::builder()
                    .method(self.method.clone())
                    .uri(uri)
                    .body(body)
                    .expect("valid request parts");
                *req.headers_mut() = self.headers.clone();
                ResponseFuture::Default(self.client.hyper.request(req))
            }
        };

        true
    }
}

#[cfg(any(feature = "http2", feature = "http3"))]
fn is_retryable_error(err: &(dyn std::error::Error + 'static)) -> bool {
    // pop the legacy::Error
    let err = if let Some(err) = err.source() {
        err
    } else {
        return false;
    };

    #[cfg(feature = "http3")]
    if let Some(cause) = err.source() {
        if let Some(err) = cause.downcast_ref::<h3::Error>() {
            debug!("determining if HTTP/3 error {err} can be retried");
            // TODO: Does h3 provide an API for checking the error?
            return err.to_string().as_str() == "timeout";
        }
    }

    #[cfg(feature = "http2")]
    if let Some(cause) = err.source() {
        if let Some(err) = cause.downcast_ref::<h2::Error>() {
            // They sent us a graceful shutdown, try with a new connection!
            if err.is_go_away() && err.is_remote() && err.reason() == Some(h2::Reason::NO_ERROR) {
                return true;
            }

            // REFUSED_STREAM was sent from the server, which is safe to retry.
            // https://www.rfc-editor.org/rfc/rfc9113.html#section-8.7-3.2
            if err.is_reset() && err.is_remote() && err.reason() == Some(h2::Reason::REFUSED_STREAM)
            {
                return true;
            }
        }
    }
    false
}

impl Pending {
    pub(super) fn new_err(err: crate::Error) -> Pending {
        Pending {
            inner: PendingInner::Error(Some(err)),
        }
    }

    fn inner(self: Pin<&mut Self>) -> Pin<&mut PendingInner> {
        self.project().inner
    }
}

impl Future for Pending {
    type Output = Result<Response, crate::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let inner = self.inner();
        match inner.get_mut() {
            PendingInner::Request(ref mut req) => Pin::new(req).poll(cx),
            PendingInner::Error(ref mut err) => Poll::Ready(Err(err
                .take()
                .expect("Pending error polled more than once"))),
        }
    }
}

impl Future for PendingRequest {
    type Output = Result<Response, crate::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if let Some(delay) = self.as_mut().total_timeout().as_mut().as_pin_mut() {
            if let Poll::Ready(()) = delay.poll(cx) {
                return Poll::Ready(Err(
                    crate::error::request(crate::error::TimedOut).with_url(self.url.clone())
                ));
            }
        }

        if let Some(delay) = self.as_mut().read_timeout().as_mut().as_pin_mut() {
            if let Poll::Ready(()) = delay.poll(cx) {
                return Poll::Ready(Err(
                    crate::error::request(crate::error::TimedOut).with_url(self.url.clone())
                ));
            }
        }

        loop {
            let res = match self.as_mut().in_flight().get_mut() {
                ResponseFuture::Default(r) => match Pin::new(r).poll(cx) {
                    Poll::Ready(Err(e)) => {
                        #[cfg(feature = "http2")]
                        if self.as_mut().retry_error(&e) {
                            continue;
                        }
                        return Poll::Ready(Err(
                            crate::error::request(e).with_url(self.url.clone())
                        ));
                    }
                    Poll::Ready(Ok(res)) => res.map(super::body::boxed),
                    Poll::Pending => return Poll::Pending,
                },
                #[cfg(feature = "http3")]
                ResponseFuture::H3(r) => match Pin::new(r).poll(cx) {
                    Poll::Ready(Err(e)) => {
                        if self.as_mut().retry_error(&e) {
                            continue;
                        }
                        return Poll::Ready(Err(
                            crate::error::request(e).with_url(self.url.clone())
                        ));
                    }
                    Poll::Ready(Ok(res)) => res,
                    Poll::Pending => return Poll::Pending,
                },
            };

            #[cfg(feature = "cookies")]
            {
                if let Some(ref cookie_store) = self.client.cookie_store {
                    let mut cookies =
                        cookie::extract_response_cookie_headers(&res.headers()).peekable();
                    if cookies.peek().is_some() {
                        cookie_store.set_cookies(&mut cookies, &self.url);
                    }
                }
            }
            let should_redirect = match res.status() {
                StatusCode::MOVED_PERMANENTLY | StatusCode::FOUND | StatusCode::SEE_OTHER => {
                    self.body = None;
                    for header in &[
                        TRANSFER_ENCODING,
                        CONTENT_ENCODING,
                        CONTENT_TYPE,
                        CONTENT_LENGTH,
                    ] {
                        self.headers.remove(header);
                    }

                    match self.method {
                        Method::GET | Method::HEAD => {}
                        _ => {
                            self.method = Method::GET;
                        }
                    }
                    true
                }
                StatusCode::TEMPORARY_REDIRECT | StatusCode::PERMANENT_REDIRECT => {
                    match self.body {
                        Some(Some(_)) | None => true,
                        Some(None) => false,
                    }
                }
                _ => false,
            };
            if should_redirect {
                let loc = res.headers().get(LOCATION).and_then(|val| {
                    let loc = (|| -> Option<Url> {
                        // Some sites may send a utf-8 Location header,
                        // even though we're supposed to treat those bytes
                        // as opaque, we'll check specifically for utf8.
                        self.url.join(str::from_utf8(val.as_bytes()).ok()?).ok()
                    })();

                    // Check that the `url` is also a valid `http::Uri`.
                    //
                    // If not, just log it and skip the redirect.
                    let loc = loc.and_then(|url| {
                        if try_uri(&url).is_ok() {
                            Some(url)
                        } else {
                            None
                        }
                    });

                    if loc.is_none() {
                        debug!("Location header had invalid URI: {val:?}");
                    }
                    loc
                });
                if let Some(loc) = loc {
                    if self.client.referer {
                        if let Some(referer) = make_referer(&loc, &self.url) {
                            self.headers.insert(REFERER, referer);
                        }
                    }
                    let url = self.url.clone();
                    self.as_mut().urls().push(url);
                    let action = self
                        .client
                        .redirect_policy
                        .check(res.status(), &loc, &self.urls);

                    match action {
                        redirect::ActionKind::Follow => {
                            debug!("redirecting '{}' to '{}'", self.url, loc);

                            if loc.scheme() != "http" && loc.scheme() != "https" {
                                return Poll::Ready(Err(error::url_bad_scheme(loc)));
                            }

                            if self.client.https_only && loc.scheme() != "https" {
                                return Poll::Ready(Err(error::redirect(
                                    error::url_bad_scheme(loc.clone()),
                                    loc,
                                )));
                            }

                            self.url = loc;
                            let mut headers =
                                std::mem::replace(self.as_mut().headers(), HeaderMap::new());

                            remove_sensitive_headers(&mut headers, &self.url, &self.urls);
                            let uri = try_uri(&self.url)?;
                            let body = match self.body {
                                Some(Some(ref body)) => Body::reusable(body.clone()),
                                _ => Body::empty(),
                            };

                            // Add cookies from the cookie store.
                            #[cfg(feature = "cookies")]
                            {
                                if let Some(ref cookie_store) = self.client.cookie_store {
                                    add_cookie_header(&mut headers, &**cookie_store, &self.url);
                                }
                            }

                            *self.as_mut().in_flight().get_mut() =
                                match *self.as_mut().in_flight().as_ref() {
                                    #[cfg(feature = "http3")]
                                    ResponseFuture::H3(_) => {
                                        let mut req = hyper::Request::builder()
                                            .method(self.method.clone())
                                            .uri(uri.clone())
                                            .body(body)
                                            .expect("valid request parts");
                                        *req.headers_mut() = headers.clone();
                                        std::mem::swap(self.as_mut().headers(), &mut headers);
                                        ResponseFuture::H3(self.client.h3_client
                        .as_ref()
                        .expect("H3 client must exists, otherwise we can't have a h3 request here")
                                            .request(req))
                                    }
                                    _ => {
                                        let mut req = hyper::Request::builder()
                                            .method(self.method.clone())
                                            .uri(uri.clone())
                                            .body(body)
                                            .expect("valid request parts");
                                        *req.headers_mut() = headers.clone();
                                        std::mem::swap(self.as_mut().headers(), &mut headers);
                                        ResponseFuture::Default(self.client.hyper.request(req))
                                    }
                                };

                            continue;
                        }
                        redirect::ActionKind::Stop => {
                            debug!("redirect policy disallowed redirection to '{loc}'");
                        }
                        redirect::ActionKind::Error(err) => {
                            return Poll::Ready(Err(crate::error::redirect(err, self.url.clone())));
                        }
                    }
                }
            }

            let res = Response::new(
                res,
                self.url.clone(),
                self.client.accepts,
                self.total_timeout.take(),
                self.read_timeout,
            );
            return Poll::Ready(Ok(res));
        }
    }
}

impl fmt::Debug for Pending {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.inner {
            PendingInner::Request(ref req) => f
                .debug_struct("Pending")
                .field("method", &req.method)
                .field("url", &req.url)
                .finish(),
            PendingInner::Error(ref err) => f.debug_struct("Pending").field("error", err).finish(),
        }
    }
}

fn is_retryable_error(err: &(dyn std::error::Error + 'static)) -> bool {
    // pop the legacy::Error
    let err = if let Some(err) = err.source() {
        err
    } else {
        return false;
    };

    #[cfg(feature = "http3")]
    if let Some(cause) = err.source() {
        if let Some(err) = cause.downcast_ref::<h3::Error>() {
            debug!("determining if HTTP/3 error {err} can be retried");
            // TODO: Does h3 provide an API for checking the error?
            return err.to_string().as_str() == "timeout";
        }
    }

    if let Some(cause) = err.source() {
        if let Some(err) = cause.downcast_ref::<h2::Error>() {
            // They sent us a graceful shutdown, try with a new connection!
            if err.is_go_away() && err.is_remote() && err.reason() == Some(h2::Reason::NO_ERROR) {
                return true;
            }

            // REFUSED_STREAM was sent from the server, which is safe to retry.
            // https://www.rfc-editor.org/rfc/rfc9113.html#section-8.7-3.2
            if err.is_reset() && err.is_remote() && err.reason() == Some(h2::Reason::REFUSED_STREAM)
            {
                return true;
            }
        }
    }
    false
}


fn make_referer(next: &Url, previous: &Url) -> Option<HeaderValue> {
    if next.scheme() == "http" && previous.scheme() == "https" {
        return None;
    }

    let mut referer = previous.clone();
    let _ = referer.set_username("");
    let _ = referer.set_password(None);
    referer.set_fragment(None);
    referer.as_str().parse().ok()
}

#[cfg(feature = "cookies")]
fn add_cookie_header(headers: &mut HeaderMap, cookie_store: &dyn cookie::CookieStore, url: &Url) {
    if let Some(header) = cookie_store.cookies(url) {
        headers.insert(crate::header::COOKIE, header);
    }
}

mod test {
    use {crate::{NetworkLayer::{body, customNetworkLayer::Client}, Proxy}};
    use std::collections::HashMap;
    use serde_urlencoded;
    use serde_json;

    #[tokio::test]
    async fn basic_get_request() {
        let client = Client::new();
        let some_url = "https://google.com/";
        let r = client.get(some_url).send().await;
        println!("resp: {:?}", r.unwrap().status())
    }

    #[tokio::test]
    async fn basic_post_request() {
        let mut builder = Client::builder();
        builder.config.proxies.push(Proxy::http("http://127.0.0.1:8080").unwrap());
        let client = builder.build().unwrap();
        let some_url = "http://google.com/";
        let r = client.post(some_url).body("what=1").send().await;
        println!("resp: {:?}", r.unwrap().status())
    }
}




