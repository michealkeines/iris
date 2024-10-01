use crate::NetworkLayer::cookie;
use crate::NetworkLayer::decoder::Accepts;
use crate::NetworkLayer::error::Error;
use crate::NetworkLayer::proxy::Proxy;
use crate::NetworkLayer::redirect;
use crate::NetworkLayer::tls::{self, TlsBackend, Certificate};
use crate::dns::Resolve;
use http::header::ACCEPT;
use http::{HeaderMap, HeaderValue};
use quinn::TransportConfig;
use quinn::VarInt;
use tokio::net::unix::SocketAddr;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;


// Current HTTPVersion
pub enum HTTPVersion {
    HTTP1,
    HTTP2,
    HTTP3,
    ALL,
}

pub struct ConnectionSettings {
    connect_timeout: Option<Duration>,
    connection_verbose: bool,
    pool_idle_timeout: Option<Duration>,
    pool_max_idle_per_host: usize,
    tcp_keepalive: Option<Duration>,
    read_timeout: Option<Duration>,
    nodelay: bool,
    local_address: Option<IpAddr>,
    interface: Option<String>,
}

impl Default for ConnectionSettings {
    fn default() -> Self {
        ConnectionSettings {
            connect_timeout: None,
            connection_verbose: false,
            pool_idle_timeout: Some(Duration::from_secs(90)),
            pool_max_idle_per_host: std::usize::MAX,
            tcp_keepalive: None,
            read_timeout: None,
            nodelay: true,
            local_address: None,
            interface: None,   
        }
    }
}

pub struct TLSSettings {
    hostname_verification: bool,
    certs_verification: bool,
    tls_sni: bool,
    root_certs: Vec<Certificate>,
    tls_built_in_root_certs: bool,
    tls_built_in_certs_webpki: bool,
    tls_built_in_certs_native: bool,
    min_tls_version: Option<tls::Version>,
    max_tls_version: Option<tls::Version>,
    tls_info: bool,
    https_only: bool,
}

impl Default for TLSSettings {
    fn default() -> Self {
        TLSSettings {
            hostname_verification: false,
            certs_verification: true,
            tls_sni: true,
            root_certs: Vec::new(),
            tls_built_in_root_certs: true,
            tls_built_in_certs_webpki: true,
            tls_built_in_certs_native: true,
            min_tls_version: None,
            max_tls_version: None,
            tls_info: true,
            https_only: false,
        }
    }
}

pub struct Config {
    pub accepts: Accepts,
    pub headers: HeaderMap,
    pub connection_settings: ConnectionSettings,
    pub proxies: Vec<Proxy>,
    pub referer: bool,
    pub tls: TlsBackend,
    pub http_version: HTTPVersion,
    pub tls_settings: TLSSettings,
    pub redirect_settings: RedirectSettings,
    pub http1_settings: HTTP1Settings,
    pub http2_settings: HTTP2Settings,
    pub http3_settings: HTTP3Settings,
    pub cookie_settings: CookieSettings,
    pub dns_settings: DNSSettings,
    pub error: Option<Error>,
}

impl Default for Config {
    fn default() -> Self {
        let mut headers = HeaderMap::with_capacity(2);
        headers.insert(ACCEPT, HeaderValue::from_static("*/*"));


        Config {
            accepts: Accepts,
            headers: headers,
            connection_settings: ConnectionSettings,
            proxies: Vec::new(),
            referer: true,
            tls: TlsBackend,
            http_version: HTTPVersion::ALL,
            tls_settings: TLSSettings,
            redirect_settings: RedirectSettings,
            http1_settings: HTTP1Settings,
            http2_settings: HTTP2Settings,
            http3_settings: HTTP3Settings,
            cookie_settings: CookieSettings,
            dns_settings: DNSSettings,
            error: None,
        }
    }
}


pub struct DNSSettings {
    dns_overrides: HashMap<String, Vec<SocketAddr>>,
    dns_resolver: Option<Arc<dyn Resolve>>,
}

impl Default for DNSSettings {
    fn default() -> Self {
        DNSSettings {
            dns_overrides: HashMap::new(),
            dns_resolver: None,
        }
    }
}

pub struct RedirectSettings {
    redirect_policy: redirect::Policy,
}

impl Default for RedirectSettings {
    fn default() -> Self {
        RedirectSettings {
            redirect_policy: redirect::Policy::default()
        }
    }
}

pub struct CookieSettings {
    cookie_store: Option<Arc<dyn cookie::CookieStore>>,
}

impl Default for CookieSettings {
    fn default() -> Self {
        CookieSettings {
            cookie_store: None
        }
    }
}

pub struct HTTP2Settings {
    http2_initial_stream_window_size: Option<u32>,
    http2_initial_connection_window_size: Option<u32>,
    http2_adaptive_window: bool,
    http2_max_frame_size: Option<u32>,
    http2_keep_alive_interval: Option<Duration>,
    http2_keep_alive_timeout: Option<Duration>,
    http2_keep_alive_while_idle: bool,
}

impl Default for HTTP2Settings {
    fn default() -> Self {
        HTTP2Settings {
            http2_initial_stream_window_size: None,
            http2_initial_connection_window_size: None,
            http2_adaptive_window: false,
            http2_max_frame_size: None,
            http2_keep_alive_interval: None,
            http2_keep_alive_timeout: None,
            http2_keep_alive_while_idle: false,
        }    
        }
    }
}

pub struct HTTP1Settings {
    http09_responses: bool,
    http1_title_case_headers: bool,
    http1_allow_obsolete_multiline_headers_in_responses: bool,
    http1_ignore_invalid_headers_in_responses: bool,
    http1_allow_spaces_after_header_name_in_responses: bool,
}

impl Default for HTTP1Settings {
    fn default() -> Self {
        HTTP1Settings {
            http09_responses: true,
            http1_title_case_headers: false,
            http1_allow_obsolete_multiline_headers_in_responses: false,
            http1_ignore_invalid_headers_in_responses: true,
            http1_allow_spaces_after_header_name_in_responses: true,
        }
    }
}

pub struct HTTP3Settings {
    tls_enable_early_data: bool,
    quic_max_idle_timeout: Option<Duration>,
    quic_stream_receive_window: Option<VarInt>,
    quic_receive_window: Option<VarInt>,
    quic_send_window: Option<u64>,
}

impl Default for HTTP3Settings {
    fn default() -> Self {
        HTTP3Settings {
            tls_enable_early_data: false,
            quic_max_idle_timeout: None,
            quic_stream_receive_window: None,
            quic_receive_window: None,
            quic_send_window: None,
        }
    }
}
