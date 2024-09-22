use crate::NetworkLayer::cookie;
use crate::NetworkLayer::decoder::Accepts;
use crate::NetworkLayer::error::Error;
use crate::NetworkLayer::proxy::Proxy;
use crate::NetworkLayer::redirect;
use crate::NetworkLayer::tls::{self, TlsBackend};
use crate::NetworkLayer::Certificate;
use http::HeaderMap;
use quinn::TransportConfig;
use quinn::VarInt;
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

pub struct Config {
    accepts: Accepts,
    headers: HeaderMap,
    connection_settings: ConnectionSettings,
    proxies: Vec<Proxy>,
    referer: bool,
    tls: TlsBackend,
    http_version: HTTPVersion,
    tls_settings: TLSSettings,
    redirect_settings: RedirectSettings,
    http1_settings: HTTP1Settings,
    http2_settings: HTTP2Settings,
    http3_settings: HTTP3Settings,
    cookie_settings: CookieSettings,
    dns_settings: DNSSettings,
    error: Option<Error>,
}

pub struct DNSSettings {
    dns_overrides: HashMap<String, Vec<SocketAddr>>,
    dns_resolver: Option<Arc<dyn Resolve>>,
}

pub struct RedirectSettings {
    redirect_policy: redirect::Policy,
}

pub struct CookieSettings {
    cookie_store: Option<Arc<dyn cookie::CookieStore>>,
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

pub struct HTTP1Settings {
    http09_responses: bool,
    http1_title_case_headers: bool,
    http1_allow_obsolete_multiline_headers_in_responses: bool,
    http1_ignore_invalid_headers_in_responses: bool,
    http1_allow_spaces_after_header_name_in_responses: bool,
}

pub struct HTTP3Settings {
    tls_enable_early_data: bool,
    quic_max_idle_timeout: Option<Duration>,
    quic_stream_receive_window: Option<VarInt>,
    quic_receive_window: Option<VarInt>,
    quic_send_window: Option<u64>,
}
