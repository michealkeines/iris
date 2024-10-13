
use http::header::HeaderValue;
use http::uri::{Authority, Scheme};
use http::Uri;
use hyper::rt::{Read, ReadBufCursor, Write};
use hyper_util::client::legacy::connect::{Connected, Connection};
use hyper_util::rt::TokioIo;
use tower_service::Service;

use pin_project_lite::pin_project;
use std::future::Future;
use std::io::{self, IoSlice};
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use self::rustls_tls_conn::RustlsTlsConn;
use crate::dns::resolve::DynResolver;
use crate::error::BoxError;
use crate::NetworkLayer::proxy::{Proxy, ProxyScheme};

pub(crate) type HttpConnector = hyper_util::client::legacy::connect::HttpConnector<DynResolver>;
/*
in this we have proxy

so far what i understood is that we have this tunnel method that takes a tcpstream, host, port, this will be the stream to the proxy server, where we can send all connect call and keep reading untill, the connection is over

as this is a stream, it can be both encrypted or plain text, it will be contained by the stream itself


so the HTTPs proxy works like, we create a connection to the proxy and the proxy will hold an sock to the server, we use the proxy socket to start the tls connection

so even in https proxy, we are creating the tls connection directly to the server, but the packets will be forwards from the proxy to server


so we are actually directly connected to the server with a hop inbetween

*/
#[derive(Clone)]
pub(crate) struct Connector {
    inner: Inner,
    proxies: Arc<Vec<Proxy>>,
    verbose: verbose::Wrapper,
    timeout: Option<Duration>,
    nodelay: bool,
    tls_info: bool,
    user_agent: Option<HeaderValue>,
}

#[derive(Clone)]
enum Inner {
    Http(HttpConnector),
    RustlsTls {
        http: HttpConnector,
        tls: Arc<rustls::ClientConfig>,
        tls_proxy: Arc<rustls::ClientConfig>,
    },
}

impl Connector {
    
    pub(crate) fn new<T>(
        mut http: HttpConnector,
        proxies: Arc<Vec<Proxy>>,
        local_addr: T,
        interface: Option<&str>,
        nodelay: bool,
    ) -> Connector
    where
        T: Into<Option<IpAddr>>,
    {
        http.set_local_address(local_addr.into());
        println!("{:?}", interface);
        // if let Some(interface) = interface {
        //     http.set_interface(interface.to_owned());
        // }
        http.set_nodelay(nodelay);

        Connector {
            inner: Inner::Http(http),
            verbose: verbose::OFF,
            proxies,
            timeout: None,
            nodelay: false,
            tls_info: false,
            user_agent: None
        }
    }

    pub(crate) fn new_rustls_tls<T>(
        mut http: HttpConnector,
        tls: rustls::ClientConfig,
        proxies: Arc<Vec<Proxy>>,
        user_agent: Option<HeaderValue>,
        local_addr: T,
        interface: Option<&str>,
        nodelay: bool,
        tls_info: bool,
    ) -> Connector
    where
        T: Into<Option<IpAddr>>,
    {
        http.set_local_address(local_addr.into());
        println!("{:?}", interface);
        // if let Some(interface) = interface {
        //     http.set_interface(interface.to_owned());
        // }
        http.set_nodelay(nodelay);
        http.enforce_http(false);

        let (tls, tls_proxy) = if proxies.is_empty() {
            let tls = Arc::new(tls);
            (tls.clone(), tls)
        } else {
            let mut tls_proxy = tls.clone();
            tls_proxy.alpn_protocols.clear();
            (Arc::new(tls), Arc::new(tls_proxy))
        };

        Connector {
            inner: Inner::RustlsTls {
                http,
                tls,
                tls_proxy,
            },
            proxies,
            verbose: verbose::OFF,
            timeout: None,
            nodelay,
            tls_info,
            user_agent,
        }
    }

    pub(crate) fn set_timeout(&mut self, timeout: Option<Duration>) {
        self.timeout = timeout;
    }

    pub(crate) fn set_verbose(&mut self, enabled: bool) {
        self.verbose.0 = enabled;
    }

    async fn connect_socks(&self, dst: Uri, proxy: ProxyScheme) -> Result<Conn, BoxError> {
        let dns = match proxy {
            ProxyScheme::Socks4 { .. } => socks::DnsResolve::Local,
            ProxyScheme::Socks5 {
                remote_dns: false, ..
            } => socks::DnsResolve::Local,
            ProxyScheme::Socks5 {
                remote_dns: true, ..
            } => socks::DnsResolve::Proxy,
            ProxyScheme::Http { .. } | ProxyScheme::Https { .. } => {
                unreachable!("connect_socks is only called for socks proxies");
            }
        };

        match &self.inner {
            Inner::RustlsTls { tls, .. } => {
                if dst.scheme() == Some(&Scheme::HTTPS) {
                    use std::convert::TryFrom;
                    use tokio_rustls::TlsConnector as RustlsConnector;

                    let tls = tls.clone();
                    let host = dst.host().ok_or("no host in url")?.to_string();
                    let conn = socks::connect(proxy, dst, dns).await?;
                    let conn = TokioIo::new(conn);
                    let conn = TokioIo::new(conn);
                    let server_name =
                        rustls_pki_types::ServerName::try_from(host.as_str().to_owned())
                            .map_err(|_| "Invalid Server Name")?;
                    let io = RustlsConnector::from(tls)
                        .connect(server_name, conn)
                        .await?;
                    let io = TokioIo::new(io);
                    return Ok(Conn {
                        inner: self.verbose.wrap(RustlsTlsConn { inner: io }),
                        is_proxy: false,
                        tls_info: false,
                    });
                }
            }
            
            Inner::Http(_) => (),
        }

        socks::connect(proxy, dst, dns).await.map(|tcp| Conn {
            inner: self.verbose.wrap(TokioIo::new(tcp)),
            is_proxy: false,
            tls_info: false,
        })
    }

    async fn connect_with_maybe_proxy(self, dst: Uri, is_proxy: bool) -> Result<Conn, BoxError> {
        match self.inner {
            
            Inner::Http(mut http) => {
                let io = http.call(dst).await?;
                Ok(Conn {
                    inner: self.verbose.wrap(io),
                    is_proxy,
                    tls_info: false,
                })
            }
            Inner::RustlsTls { http, tls, .. } => {
                let mut http = http.clone();

                // Disable Nagle's algorithm for TLS handshake
                //
                // https://www.openssl.org/docs/man1.1.1/man3/SSL_connect.html#NOTES
                if !self.nodelay && (dst.scheme() == Some(&Scheme::HTTPS)) {
                    http.set_nodelay(true);
                }

                let mut http = hyper_rustls::HttpsConnector::from((http, tls.clone()));
                let io = http.call(dst).await?;

                if let hyper_rustls::MaybeHttpsStream::Https(stream) = io {
                    if !self.nodelay {
                        let (io, _) = stream.inner().get_ref();
                        io.inner().inner().set_nodelay(false)?;
                    }
                    Ok(Conn {
                        inner: self.verbose.wrap(RustlsTlsConn { inner: stream }),
                        is_proxy,
                        tls_info: self.tls_info,
                    })
                } else {
                    Ok(Conn {
                        inner: self.verbose.wrap(io),
                        is_proxy,
                        tls_info: false,
                    })
                }
            }
        }
    }

    async fn connect_via_proxy(
        self,
        dst: Uri,
        proxy_scheme: ProxyScheme,
    ) -> Result<Conn, BoxError> {
        log::debug!("proxy({proxy_scheme:?}) intercepts '{dst:?}'");

        let (proxy_dst, _auth) = match proxy_scheme {
            ProxyScheme::Http { host, auth } => (into_uri(Scheme::HTTP, host), auth),
            ProxyScheme::Https { host, auth } => (into_uri(Scheme::HTTPS, host), auth),
            ProxyScheme::Socks4 { .. } => return self.connect_socks(dst, proxy_scheme).await,
            ProxyScheme::Socks5 { .. } => return self.connect_socks(dst, proxy_scheme).await,
        };

        
        let auth = _auth;

        match &self.inner {
            Inner::RustlsTls {
                http,
                tls,
                tls_proxy,
            } => {
                if dst.scheme() == Some(&Scheme::HTTPS) {
                    use rustls_pki_types::ServerName;
                    use std::convert::TryFrom;
                    use tokio_rustls::TlsConnector as RustlsConnector;

                    let host = dst.host().ok_or("no host in url")?.to_string();
                    let port = dst.port().map(|r| r.as_u16()).unwrap_or(443);
                    let http = http.clone();
                    let mut http = hyper_rustls::HttpsConnector::from((http, tls_proxy.clone()));
                    let tls = tls.clone();
                    let conn = http.call(proxy_dst).await?;
                    log::trace!("tunneling HTTPS over proxy");
                    let maybe_server_name = ServerName::try_from(host.as_str().to_owned())
                        .map_err(|_| "Invalid Server Name");
                    let tunneled = tunnel(conn, host, port, self.user_agent.clone(), auth).await?;
                    let server_name = maybe_server_name?;
                    let io = RustlsConnector::from(tls)
                        .connect(server_name, TokioIo::new(tunneled))
                        .await?;

                    return Ok(Conn {
                        inner: self.verbose.wrap(RustlsTlsConn {
                            inner: TokioIo::new(io),
                        }),
                        is_proxy: false,
                        tls_info: false,
                    });
                }
            }
            
            Inner::Http(_) => (),
        }

        self.connect_with_maybe_proxy(proxy_dst, true).await
    }

    pub fn set_keepalive(&mut self, dur: Option<Duration>) {
        match &mut self.inner {
            Inner::RustlsTls { http, .. } => http.set_keepalive(dur),
            
            Inner::Http(http) => http.set_keepalive(dur),
        }
    }
}

fn into_uri(scheme: Scheme, host: Authority) -> Uri {
    // TODO: Should the `http` crate get `From<(Scheme, Authority)> for Uri`?
    http::Uri::builder()
        .scheme(scheme)
        .authority(host)
        .path_and_query(http::uri::PathAndQuery::from_static("/"))
        .build()
        .expect("scheme and authority is valid Uri")
}

async fn with_timeout<T, F>(f: F, timeout: Option<Duration>) -> Result<T, BoxError>
where
    F: Future<Output = Result<T, BoxError>>,
{
    if let Some(to) = timeout {
        match tokio::time::timeout(to, f).await {
            Err(_elapsed) => Err(Box::new(crate::error::TimedOut) as BoxError),
            Ok(Ok(try_res)) => Ok(try_res),
            Ok(Err(e)) => Err(e),
        }
    } else {
        f.await
    }
}

impl Service<Uri> for Connector {
    type Response = Conn;
    type Error = BoxError;
    type Future = Connecting;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        log::debug!("starting new connection: {dst:?}");
        let timeout = self.timeout;
        for prox in self.proxies.iter() {
            if let Some(proxy_scheme) = prox.intercept(&dst) {
                return Box::pin(with_timeout(
                    self.clone().connect_via_proxy(dst, proxy_scheme),
                    timeout,
                ));
            }
        }

        Box::pin(with_timeout(
            self.clone().connect_with_maybe_proxy(dst, false),
            timeout,
        ))
    }
}


trait TlsInfoFactory {
    fn tls_info(&self) -> Option<crate::NetworkLayer::tls::TlsInfo>;
}


impl TlsInfoFactory for tokio::net::TcpStream {
    fn tls_info(&self) -> Option<crate::NetworkLayer::tls::TlsInfo> {
        None
    }
}


impl<T: TlsInfoFactory> TlsInfoFactory for TokioIo<T> {
    fn tls_info(&self) -> Option<crate::NetworkLayer::tls::TlsInfo> {
        self.inner().tls_info()
    }
}


impl TlsInfoFactory for tokio_rustls::client::TlsStream<TokioIo<TokioIo<tokio::net::TcpStream>>> {
    fn tls_info(&self) -> Option<crate::NetworkLayer::tls::TlsInfo> {
        let peer_certificate = self
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|certs| certs.first())
            .map(|c| c.to_vec());
        Some(crate::NetworkLayer::tls::TlsInfo { peer_certificate })
    }
}

impl TlsInfoFactory
    for tokio_rustls::client::TlsStream<
        TokioIo<hyper_rustls::MaybeHttpsStream<TokioIo<tokio::net::TcpStream>>>,
    >
{
    fn tls_info(&self) -> Option<crate::NetworkLayer::tls::TlsInfo> {
        let peer_certificate = self
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|certs| certs.first())
            .map(|c| c.to_vec());
        Some(crate::NetworkLayer::tls::TlsInfo { peer_certificate })
    }
}

impl TlsInfoFactory for hyper_rustls::MaybeHttpsStream<TokioIo<tokio::net::TcpStream>> {
    fn tls_info(&self) -> Option<crate::NetworkLayer::tls::TlsInfo> {
        match self {
            hyper_rustls::MaybeHttpsStream::Https(tls) => tls.tls_info(),
            hyper_rustls::MaybeHttpsStream::Http(_) => None,
        }
    }
}

pub(crate) trait AsyncConn:
    Read + Write + Connection + Send + Sync + Unpin + 'static
{
}

impl<T: Read + Write + Connection + Send + Sync + Unpin + 'static> AsyncConn for T {}


trait AsyncConnWithInfo: AsyncConn + TlsInfoFactory {}


impl<T: AsyncConn + TlsInfoFactory> AsyncConnWithInfo for T {}

type BoxConn = Box<dyn AsyncConnWithInfo>;

pin_project! {
    /// Note: the `is_proxy` member means *is plain text HTTP proxy*.
    /// This tells hyper whether the URI should be written in
    /// * origin-form (`GET /just/a/path HTTP/1.1`), when `is_proxy == false`, or
    /// * absolute-form (`GET http://foo.bar/and/a/path HTTP/1.1`), otherwise.
    pub(crate) struct Conn {
        #[pin]
        inner: BoxConn,
        is_proxy: bool,
        // Only needed for __tls, but #[cfg()] on fields breaks pin_project!
        tls_info: bool,
    }
}

impl Connection for Conn {
    fn connected(&self) -> Connected {
        let mut connected = self.inner.connected().proxy(self.is_proxy);
        
        if self.tls_info {
            if let Some(tls_info) = self.inner.tls_info() {
                connected = connected.extra(tls_info);
                return connected;
            }
        }
        connected
    }
}

impl Read for Conn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.project();
        Read::poll_read(this.inner, cx, buf)
    }
}

impl Write for Conn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let this = self.project();
        Write::poll_write(this.inner, cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<Result<usize, io::Error>> {
        let this = self.project();
        Write::poll_write_vectored(this.inner, cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), io::Error>> {
        let this = self.project();
        Write::poll_flush(this.inner, cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), io::Error>> {
        let this = self.project();
        Write::poll_shutdown(this.inner, cx)
    }
}

pub(crate) type Connecting = Pin<Box<dyn Future<Output = Result<Conn, BoxError>> + Send>>;


async fn tunnel<T>(
    mut conn: T,
    host: String,
    port: u16,
    user_agent: Option<HeaderValue>,
    auth: Option<HeaderValue>,
) -> Result<T, BoxError>
where
    T: Read + Write + Unpin,
{
    use core::str;

    use hyper_util::rt::TokioIo;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut buf = format!(
        "\
         CONNECT {host}:{port} HTTP/1.1\r\n\
         Host: {host}:{port}\r\n\
         "
    )
    .into_bytes();

    // user-agent
    if let Some(user_agent) = user_agent {
        buf.extend_from_slice(b"User-Agent: ");
        buf.extend_from_slice(user_agent.as_bytes());
        buf.extend_from_slice(b"\r\n");
    }

    // proxy-authorization
    if let Some(value) = auth {
        log::debug!("tunnel to {host}:{port} using basic auth");
        buf.extend_from_slice(b"Proxy-Authorization: ");
        buf.extend_from_slice(value.as_bytes());
        buf.extend_from_slice(b"\r\n");
    }

    // headers end
    buf.extend_from_slice(b"\r\n");

    let mut tokio_conn = TokioIo::new(&mut conn);

    tokio_conn.write_all(&buf).await?;

    let mut buf = [0; 8192];
    let mut pos = 0;

    loop {
        let n = tokio_conn.read(&mut buf[pos..]).await?;

        if n == 0 {
            return Err(tunnel_eof());
        }
        pos += n;

        let recvd = &buf[..pos];
        if recvd.starts_with(b"HTTP/1.1 200") || recvd.starts_with(b"HTTP/1.0 200") {
            println!("received:{}", str::from_utf8(recvd).unwrap());
            if recvd.ends_with(b"\r\n\r\n") {
                return Ok(conn);
            }
            if pos == buf.len() {
                return Err("proxy headers too long for tunnel".into());
            }
        // else read more
        } else if recvd.starts_with(b"HTTP/1.1 407") {
            return Err("proxy authentication required".into());
        } else {
            return Err("unsuccessful tunnel".into());
        }
    }
}


fn tunnel_eof() -> BoxError {
    "unexpected eof while tunneling".into()
}

mod rustls_tls_conn {
    use super::TlsInfoFactory;
    use hyper::rt::{Read, ReadBufCursor, Write};
    use hyper_rustls::MaybeHttpsStream;
    use hyper_util::client::legacy::connect::{Connected, Connection};
    use hyper_util::rt::TokioIo;
    use pin_project_lite::pin_project;
    use std::{
        io::{self, IoSlice},
        pin::Pin,
        task::{Context, Poll},
    };
    use tokio::io::{AsyncRead, AsyncWrite};
    use tokio::net::TcpStream;
    use tokio_rustls::client::TlsStream;

    pin_project! {
        pub(super) struct RustlsTlsConn<T> {
            #[pin] pub(super) inner: TokioIo<TlsStream<T>>,
        }
    }

    impl Connection for RustlsTlsConn<TokioIo<TokioIo<TcpStream>>> {
        fn connected(&self) -> Connected {
            if self.inner.inner().get_ref().1.alpn_protocol() == Some(b"h2") {
                self.inner
                    .inner()
                    .get_ref()
                    .0
                    .inner()
                    .connected()
                    .negotiated_h2()
            } else {
                self.inner.inner().get_ref().0.inner().connected()
            }
        }
    }
    impl Connection for RustlsTlsConn<TokioIo<MaybeHttpsStream<TokioIo<TcpStream>>>> {
        fn connected(&self) -> Connected {
            if self.inner.inner().get_ref().1.alpn_protocol() == Some(b"h2") {
                self.inner
                    .inner()
                    .get_ref()
                    .0
                    .inner()
                    .connected()
                    .negotiated_h2()
            } else {
                self.inner.inner().get_ref().0.inner().connected()
            }
        }
    }

    impl<T: AsyncRead + AsyncWrite + Unpin> Read for RustlsTlsConn<T> {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context,
            buf: ReadBufCursor<'_>,
        ) -> Poll<tokio::io::Result<()>> {
            let this = self.project();
            Read::poll_read(this.inner, cx, buf)
        }
    }

    impl<T: AsyncRead + AsyncWrite + Unpin> Write for RustlsTlsConn<T> {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context,
            buf: &[u8],
        ) -> Poll<Result<usize, tokio::io::Error>> {
            let this = self.project();
            Write::poll_write(this.inner, cx, buf)
        }

        fn poll_write_vectored(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bufs: &[IoSlice<'_>],
        ) -> Poll<Result<usize, io::Error>> {
            let this = self.project();
            Write::poll_write_vectored(this.inner, cx, bufs)
        }

        fn is_write_vectored(&self) -> bool {
            self.inner.is_write_vectored()
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            cx: &mut Context,
        ) -> Poll<Result<(), tokio::io::Error>> {
            let this = self.project();
            Write::poll_flush(this.inner, cx)
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            cx: &mut Context,
        ) -> Poll<Result<(), tokio::io::Error>> {
            let this = self.project();
            Write::poll_shutdown(this.inner, cx)
        }
    }
    impl<T> TlsInfoFactory for RustlsTlsConn<T>
    where
        TokioIo<TlsStream<T>>: TlsInfoFactory,
    {
        fn tls_info(&self) -> Option<crate::NetworkLayer::tls::TlsInfo> {
            self.inner.tls_info()
        }
    }
}

mod socks {
    use std::io;
    use std::net::ToSocketAddrs;

    use http::Uri;
    use tokio::net::TcpStream;
    use tokio_socks::tcp::{Socks4Stream, Socks5Stream};

    use super::{BoxError, Scheme};
    use crate::NetworkLayer::proxy::ProxyScheme;

    pub(super) enum DnsResolve {
        Local,
        Proxy,
    }

    pub(super) async fn connect(
        proxy: ProxyScheme,
        dst: Uri,
        dns: DnsResolve,
    ) -> Result<TcpStream, BoxError> {
        let https = dst.scheme() == Some(&Scheme::HTTPS);
        let original_host = dst
            .host()
            .ok_or(io::Error::new(io::ErrorKind::Other, "no host in url"))?;
        let mut host = original_host.to_owned();
        let port = match dst.port() {
            Some(p) => p.as_u16(),
            None if https => 443u16,
            _ => 80u16,
        };

        if let DnsResolve::Local = dns {
            let maybe_new_target = (host.as_str(), port).to_socket_addrs()?.next();
            if let Some(new_target) = maybe_new_target {
                host = new_target.ip().to_string();
            }
        }

        match proxy {
            ProxyScheme::Socks4 { addr } => {
                let stream = Socks4Stream::connect(addr, (host.as_str(), port))
                    .await
                    .map_err(|e| format!("socks connect error: {e}"))?;
                Ok(stream.into_inner())
            }
            ProxyScheme::Socks5 { addr, ref auth, .. } => {
                let stream = if let Some((username, password)) = auth {
                    Socks5Stream::connect_with_password(
                        addr,
                        (host.as_str(), port),
                        &username,
                        &password,
                    )
                    .await
                    .map_err(|e| format!("socks connect error: {e}"))?
                } else {
                    Socks5Stream::connect(addr, (host.as_str(), port))
                        .await
                        .map_err(|e| format!("socks connect error: {e}"))?
                };

                Ok(stream.into_inner())
            }
            _ => unreachable!(),
        }
    }
}

mod verbose {
    use hyper::rt::{Read, ReadBufCursor, Write};
    use hyper_util::client::legacy::connect::{Connected, Connection};
    use std::cmp::min;
    use std::fmt;
    use std::io::{self, IoSlice};
    use std::pin::Pin;
    use std::task::{Context, Poll};

    pub(super) const OFF: Wrapper = Wrapper(false);

    #[derive(Clone, Copy)]
    pub(super) struct Wrapper(pub(super) bool);

    impl Wrapper {
        pub(super) fn wrap<T: super::AsyncConnWithInfo>(&self, conn: T) -> super::BoxConn {
            if self.0 && log::log_enabled!(log::Level::Trace) {
                Box::new(Verbose {
                    // truncate is fine
                    id: crate::util::fast_random() as u32,
                    inner: conn,
                })
            } else {
                Box::new(conn)
            }
        }
    }

    struct Verbose<T> {
        id: u32,
        inner: T,
    }

    impl<T: Connection + Read + Write + Unpin> Connection for Verbose<T> {
        fn connected(&self) -> Connected {
            self.inner.connected()
        }
    }

    impl<T: Read + Write + Unpin> Read for Verbose<T> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context,
            buf: ReadBufCursor<'_>,
        ) -> Poll<std::io::Result<()>> {
            match Pin::new(&mut self.inner).poll_read(cx, buf) {
                Poll::Ready(Ok(())) => {
                    /*
                    log::trace!("{:08x} read: {:?}", self.id, Escape(buf.filled()));
                    */
                    log::trace!("TODO: verbose poll_read");
                    Poll::Ready(Ok(()))
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            }
        }
    }

    impl<T: Read + Write + Unpin> Write for Verbose<T> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context,
            buf: &[u8],
        ) -> Poll<Result<usize, std::io::Error>> {
            match Pin::new(&mut self.inner).poll_write(cx, buf) {
                Poll::Ready(Ok(n)) => {
                    log::trace!("{:08x} write: {:?}", self.id, Escape(&buf[..n]));
                    Poll::Ready(Ok(n))
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            }
        }

        fn poll_write_vectored(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bufs: &[IoSlice<'_>],
        ) -> Poll<Result<usize, io::Error>> {
            match Pin::new(&mut self.inner).poll_write_vectored(cx, bufs) {
                Poll::Ready(Ok(nwritten)) => {
                    log::trace!(
                        "{:08x} write (vectored): {:?}",
                        self.id,
                        Vectored { bufs, nwritten }
                    );
                    Poll::Ready(Ok(nwritten))
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            }
        }

        fn is_write_vectored(&self) -> bool {
            self.inner.is_write_vectored()
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            cx: &mut Context,
        ) -> Poll<Result<(), std::io::Error>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context,
        ) -> Poll<Result<(), std::io::Error>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    
    impl<T: super::TlsInfoFactory> super::TlsInfoFactory for Verbose<T> {
        fn tls_info(&self) -> Option<crate::NetworkLayer::tls::TlsInfo> {
            self.inner.tls_info()
        }
    }

    struct Escape<'a>(&'a [u8]);

    impl fmt::Debug for Escape<'_> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "b\"")?;
            for &c in self.0 {
                // https://doc.rust-lang.org/reference.html#byte-escapes
                if c == b'\n' {
                    write!(f, "\\n")?;
                } else if c == b'\r' {
                    write!(f, "\\r")?;
                } else if c == b'\t' {
                    write!(f, "\\t")?;
                } else if c == b'\\' || c == b'"' {
                    write!(f, "\\{}", c as char)?;
                } else if c == b'\0' {
                    write!(f, "\\0")?;
                // ASCII printable
                } else if c >= 0x20 && c < 0x7f {
                    write!(f, "{}", c as char)?;
                } else {
                    write!(f, "\\x{c:02x}")?;
                }
            }
            write!(f, "\"")?;
            Ok(())
        }
    }

    struct Vectored<'a, 'b> {
        bufs: &'a [IoSlice<'b>],
        nwritten: usize,
    }

    impl fmt::Debug for Vectored<'_, '_> {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            let mut left = self.nwritten;
            for buf in self.bufs.iter() {
                if left == 0 {
                    break;
                }
                let n = min(left, buf.len());
                Escape(&buf[..n]).fmt(f)?;
                left -= n;
            }
            Ok(())
        }
    }
}


#[cfg(test)]
mod tests {
    use super::tunnel;

    // use crate::connect::native_tls_conn;
    use crate::NetworkLayer::proxy;
    use hyper_util::rt::TokioIo;
    // use rustls::pki_types;
    use rustls_pki_types::ServerName;
    // use rustls::pki_types;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    // use tokio_native_tls::TlsConnector;
    // use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
    use core::str;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    // use std::os::unix::net::SocketAddr;
    use std::thread;
    use tokio::net::TcpStream;
    use tokio::runtime;

    static TUNNEL_UA: &str = "tunnel-test/x.y";
    static TUNNEL_OK: &[u8] = b"\
        HTTP/1.1 200 OK\r\n\
        \r\n\
    ";

    macro_rules! mock_tunnel {
        () => {{
            mock_tunnel!(TUNNEL_OK)
        }};
        ($write:expr) => {{
            mock_tunnel!($write, "")
        }};
        ($write:expr, $auth:expr) => {{
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let connect_expected = format!(
                "\
                 CONNECT {0}:{1} HTTP/1.1\r\n\
                 Host: {0}:{1}\r\n\
                 User-Agent: {2}\r\n\
                 {3}\
                 \r\n\
                 ",
                addr.ip(),
                addr.port(),
                TUNNEL_UA,
                $auth
            )
            .into_bytes();

            thread::spawn(move || {
                let (mut sock, _) = listener.accept().unwrap();
                let mut buf = [0u8; 4096];
                let n = sock.read(&mut buf).unwrap();
                assert_eq!(&buf[..n], &connect_expected[..]);

                sock.write_all($write).unwrap();
            });
            addr
        }};
    }

    fn ua() -> Option<http::header::HeaderValue> {
        Some(http::header::HeaderValue::from_static(TUNNEL_UA))
    }

    #[test]
    fn test_tunnel() {
        let addr = mock_tunnel!();

        let rt = runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("new rt");
        let f = async move {
            let tcp = TokioIo::new(TcpStream::connect(&addr).await?);
            let host = addr.ip().to_string();
            let port = addr.port();
            tunnel(tcp, host, port, ua(), None).await
        };

        rt.block_on(f).unwrap();
    }

    #[test]
    fn test_tunnel_eof() {
        let addr = mock_tunnel!(b"HTTP/1.1 200 OK");

        let rt = runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("new rt");
        let f = async move {
            let tcp = TokioIo::new(TcpStream::connect(&addr).await?);
            let host = addr.ip().to_string();
            let port = addr.port();
            tunnel(tcp, host, port, ua(), None).await
        };

        rt.block_on(f).unwrap_err();
    }

    #[test]
    fn test_tunnel_non_http_response() {
        let addr = mock_tunnel!(b"foo bar baz hallo");

        let rt = runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("new rt");
        let f = async move {
            let tcp = TokioIo::new(TcpStream::connect(&addr).await?);
            let host = addr.ip().to_string();
            let port = addr.port();
            tunnel(tcp, host, port, ua(), None).await
        };

        rt.block_on(f).unwrap_err();
    }

    #[test]
    fn test_tunnel_proxy_unauthorized() {
        let addr = mock_tunnel!(
            b"\
            HTTP/1.1 407 Proxy Authentication Required\r\n\
            Proxy-Authenticate: Basic realm=\"nope\"\r\n\
            \r\n\
        "
        );

        let rt = runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("new rt");
        let f = async move {
            let tcp = TokioIo::new(TcpStream::connect(&addr).await?);
            let host = addr.ip().to_string();
            let port = addr.port();
            tunnel(tcp, host, port, ua(), None).await
        };

        let error = rt.block_on(f).unwrap_err();
        assert_eq!(error.to_string(), "proxy authentication required");
    }

    #[test]
    fn test_tunnel_basic_auth() {
        let addr = mock_tunnel!(
            TUNNEL_OK,
            "Proxy-Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==\r\n"
        );

        let rt = runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("new rt");
        let f = async move {
            let tcp = TokioIo::new(TcpStream::connect(&addr).await?);
            let host = addr.ip().to_string();
            let port = addr.port();
            tunnel(
                tcp,
                host,
                port,
                ua(),
                Some(proxy::encode_basic_auth("Aladdin", "open sesame")),
            )
            .await
        };

        rt.block_on(f).unwrap();
    }

    #[test]
    fn test_connect_to_proxy_http_target() {
        let rt = runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("new rt");
        let f = async move {
            let mut tcp = TcpStream::connect("127.0.0.1:8080").await.unwrap();

            tcp.write(b"GET http://www.google.com:80/ HTTP/1.1\r\nHost: www.google.com\r\n\r\n").await.unwrap();
            let mut buffer: Vec<u8> = vec![0; 1024];
            tcp.read(&mut buffer).await.unwrap();
            println!("output: {}", str::from_utf8(&buffer).unwrap());

            
        };
        rt.block_on(f);
    }

    #[test]
    fn test_connect_to_proxy_https_target() {
        let rt = runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("new rt");

        let f = async move {
            use std::sync::Arc;
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            use tokio_rustls::{rustls::ClientConfig, TlsConnector};
            let mut tcp = TcpStream::connect("127.0.0.1:8080").await.unwrap();

            // Send the CONNECT request to the proxy
            let connect_request = format!(
                "CONNECT www.google.com:443 HTTP/1.1\r\nHost: www.google.com:443\r\n\r\n"
            );
            tcp.write_all(connect_request.as_bytes()).await.unwrap();

            // Read the proxy response
            let mut buffer = vec![0; 1024];
            tcp.read(&mut buffer).await.unwrap();
            let response = String::from_utf8_lossy(&buffer);
            println!("Proxy response: {}", response);

            // Verify the proxy response is '200 Connection Established'
            if !response.contains("200") {
                eprintln!("Failed to establish a connection through the proxy.");
                return;
            }

            // Setup TLS connection
            let domain = "www.google.com";
            let mut roots = rustls::RootCertStore::empty();
            for cert in rustls_native_certs::load_native_certs().expect("could not load platform certs") {
                roots.add(cert).unwrap();
            }

            let config = ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            let connector = TlsConnector::from(Arc::new(config));

            // Wrap the TCP stream with TLS
            let domain = ServerName::try_from(domain).unwrap();
            let mut tls_stream = connector.connect(domain.clone(), tcp).await.unwrap();

            // Send HTTP request over the TLS connection
            let request = format!(
                "GET / HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n"
            );
            tls_stream.write_all(request.as_bytes()).await.unwrap();

            // Read the response
            let mut buffer = vec![0; 1024];

            tls_stream.read_to_end(&mut buffer).await.unwrap();
            println!("HTTP Response: {}", String::from_utf8_lossy(&buffer));
        };
        rt.block_on(f);
    }
}
