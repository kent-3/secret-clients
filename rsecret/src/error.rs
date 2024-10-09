/// Alias for a `Result` with the error type `crate::Error`.
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// This type represents all possible errors that can occur in this crate.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Custom(String),
    #[error("Simple Error")]
    SimpleError,
    #[error("{self:?}")]
    ErrorWithData { data: String },

    #[error("{self:?}")]
    MissingField { name: &'static str },
    #[error("{self:?}")]
    InvalidAny { type_url: String },

    #[error(transparent)]
    SignerError(#[from] crate::wallet::Error),
    #[error("Unsupported {0}")]
    SignMode(&'static str),

    #[cfg(not(target_arch = "wasm32"))]
    #[error(transparent)]
    Tonic(#[from] tonic::transport::Error),
    #[error(transparent)]
    Status(#[from] tonic::Status),

    #[error(transparent)]
    ProstDecode(#[from] prost::DecodeError),
    #[error(transparent)]
    ProstEncode(#[from] prost::EncodeError),

    #[error(transparent)]
    FromUtf8(#[from] std::string::FromUtf8Error),
    #[error(transparent)]
    Utf8Error(#[from] std::str::Utf8Error),
    #[error(transparent)]
    Base64Decode(#[from] base64::DecodeError),
    #[error(transparent)]
    FromHex(#[from] hex::FromHexError),
    #[error(transparent)]
    SerdeJson(#[from] serde_json::Error),
    #[error(transparent)]
    ParseInt(#[from] std::num::ParseIntError),

    #[error(transparent)]
    SecretRs(#[from] secretrs::Error),
    #[error(transparent)]
    ErrorReport(#[from] secretrs::ErrorReport),
    #[error(transparent)]
    EncryptionUtils(#[from] secretrs::utils::Error),
    #[error(transparent)]
    Tendermint(#[from] secretrs::tendermint::Error),
    #[error(transparent)]
    Bip39(#[from] bip39::Error),
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

// impl core::fmt::Display for Error {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         write!(f, "{self:?}")
//     }
// }
//
// impl std::error::Error for Error {}
