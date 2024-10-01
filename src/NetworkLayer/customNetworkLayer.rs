
use crate::NetworkLayer::config::Config;
use http::{header::ACCEPT, HeaderMap, HeaderValue};
use quinn::crypto::HeaderKey;

use super::decoder::Accepts;

#[derive(Clone)]
pub struct Client {
    inner: Arc<ClientRef>,
}

pub struct ClienBuilder {
    config: Config
}

impl Default for ClienBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ClienBuilder {
    pub fn new() -> ClienBuilder {
        ClienBuilder {
            config: Config
        }
    }

    pub fn build(self) -> crate::Result<Client> {

    }
}



