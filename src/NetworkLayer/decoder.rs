#[derive(Clone, Copy, Debug)]
pub struct Accepts {
    pub gzip: bool,
    pub brotli: bool,
    pub zstd: bool,
    pub deflate: bool,
}