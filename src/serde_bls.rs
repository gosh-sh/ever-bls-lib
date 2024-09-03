use serde::Serialize;
use std::path::Path;

use crate::bls::BLS_PUBLIC_KEY_LEN;
use crate::bls::BLS_SECRET_KEY_LEN;

pub struct BLSKeyPair {
    pub public: [u8; BLS_PUBLIC_KEY_LEN],
    pub secret: [u8; BLS_SECRET_KEY_LEN],
}

#[derive(Serialize)]
struct WrappedBLSKeyPair {
    public: String,
    secret: String,
}

impl WrappedBLSKeyPair {
    pub fn new(key_pair: &BLSKeyPair) -> Self {
        WrappedBLSKeyPair {
            public: hex::encode(key_pair.public),
            secret: hex::encode(key_pair.secret),
        }
    }
}

impl BLSKeyPair {
    pub fn from(data: ([u8; BLS_PUBLIC_KEY_LEN], [u8; BLS_SECRET_KEY_LEN])) -> Self {
        Self {
            public: data.0,
            secret: data.1,
        }
    }

    pub fn to_string(&self) -> anyhow::Result<String> {
        let wrapped = WrappedBLSKeyPair::new(self);
        serde_json::to_string_pretty(&wrapped)
            .map_err(|e| anyhow::format_err!("Failed to serialize BLSKeyPair: {e}"))
    }

    pub fn save_to_file(&self, path: impl AsRef<Path>) -> anyhow::Result<()> {
        std::fs::write(path, self.to_string()?)
            .map_err(|e| anyhow::format_err!("Failed to save BLSKetPait: {e}"))
    }
}
