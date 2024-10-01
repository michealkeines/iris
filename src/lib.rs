pub mod NetworkLayer;
pub use http::header;
pub use http::Method;
pub use http::{StatusCode, Version};
pub use url::Url;
pub use NetworkLayer::into_url;
pub use NetworkLayer::error;
pub use NetworkLayer::util;
pub use NetworkLayer::proxy::Proxy;
pub mod dns;
pub use NetworkLayer::error::{Error, Result};