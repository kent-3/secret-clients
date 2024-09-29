#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Custom(String),

    #[error("Address {signer_address} not found in wallet")]
    SignerError { signer_address: String },

    #[error("{0}")]
    SignatureError(String),

    #[error(transparent)]
    Bip39(#[from] bip39::Error),

    #[error(transparent)]
    Report(#[from] secretrs::ErrorReport),
}

impl Error {
    pub fn custom(value: impl std::fmt::Display) -> Self {
        Self::Custom(value.to_string())
    }
}

impl From<&str> for Error {
    fn from(value: &str) -> Self {
        Self::Custom(value.to_string())
    }
}

impl From<String> for Error {
    fn from(value: String) -> Self {
        Self::Custom(value)
    }
}
