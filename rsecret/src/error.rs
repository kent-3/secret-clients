use derive_more::From;

/// Alias for a `Result` with the error type `module::Error`.
pub type Result<T> = core::result::Result<T, Error>;

/// This type represents all possible errors that can occur in this module.
#[derive(Debug, From)]
pub enum Error {
    #[from]
    Custom(String),
    SimpleError,
    ErrorWithData {
        data: String,
    },

    #[from]
    FromUtf8(std::string::FromUtf8Error),
    #[from]
    Base64Decode(base64::DecodeError),
    #[from]
    FromHex(hex::FromHexError),
    #[from]
    SerdeJson(serde_json::Error),

    #[from]
    SecretRs(secretrs::Error),
    #[from]
    ErrorReport(secretrs::ErrorReport),
    #[from]
    Tendermint(secretrs::tendermint::Error),
    #[from]
    EncryptionUtils(secretrs::utils::Error),
    #[from]
    Bip39(bip39::Error),

    #[from]
    Tonic(tonic::transport::Error),
    #[from]
    Status(tonic::Status),
    #[from]
    ProstDecode(prost::DecodeError),
    #[from]
    ProstEncode(prost::EncodeError),
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

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for Error {}
