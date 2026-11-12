//! The crate's error type, and the mapping from the shim's numeric return codes.

use std::fmt;
use std::os::raw::c_int;
use std::path::PathBuf;

/// `Result` with this crate's [`Error`].
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Everything that can go wrong opening, sourcing or driving the CDM.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("CDM path is not valid UTF-8: {}", .0.display())]
    NonUtf8Path(PathBuf),
    #[error("CDM path contains a NUL byte: {}", .0.display())]
    NulInPath(PathBuf),
    #[error("could not load the CDM library at {}", .0.display())]
    Load(PathBuf),
    #[error("{} does not export the CDM entry points", .0.display())]
    MissingSymbols(PathBuf),
    #[error("the CDM returned no ContentDecryptionModule_11 instance")]
    CreateInstance,
    #[error("the CDM failed to initialize")]
    Initialize,
    #[error("no CDM is open")]
    NotOpen,
    #[error("the CDM rejected the request")]
    Rejected,
    #[error("the CDM produced no license challenge")]
    NoChallenge,
    #[error("the license did not change any keys")]
    NoKeyChange,
    #[error("CDM decrypt failed: {0}")]
    Decrypt(DecryptStatus),
    #[error("the CDM returned no decrypted buffer")]
    NoDecryptedBuffer,
    #[error("{call} returned unknown code {code}")]
    Unknown { call: &'static str, code: c_int },
    #[error("{context}")]
    Io {
        context: String,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "no Widevine CDM found on the system — install Chrome/Brave/Chromium, point at a \
         CDM with $WIDEVINE_CDM, or enable the `download` feature"
    )]
    NoCdmFound,
    #[cfg(feature = "download")]
    #[error("{context}")]
    Download {
        context: &'static str,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[cfg(feature = "download")]
    #[error("unexpected Chrome package contents: {0}")]
    Package(String),
}

impl Error {
    pub(crate) fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        Error::Io {
            context: context.into(),
            source,
        }
    }

    pub(crate) fn from_open(code: c_int, path: PathBuf) -> Self {
        match code {
            1 => Error::Load(path),
            2 => Error::MissingSymbols(path),
            3 => Error::CreateInstance,
            4 => Error::Initialize,
            code => Error::Unknown {
                call: "ch_open",
                code,
            },
        }
    }

    pub(crate) fn from_challenge(code: c_int) -> Self {
        match code {
            10 => Error::NotOpen,
            11 => Error::Rejected,
            12 => Error::NoChallenge,
            code => Error::Unknown {
                call: "ch_challenge",
                code,
            },
        }
    }

    pub(crate) fn from_update(code: c_int) -> Self {
        match code {
            20 => Error::NotOpen,
            21 => Error::Rejected,
            22 => Error::NoKeyChange,
            code => Error::Unknown {
                call: "ch_update",
                code,
            },
        }
    }

    pub(crate) fn from_decrypt(code: c_int) -> Self {
        // The shim returns 31 + cdm::Status for a failed Decrypt().
        match code {
            30 => Error::NotOpen,
            40 => Error::NoDecryptedBuffer,
            code => match code.checked_sub(31).and_then(DecryptStatus::from_raw) {
                Some(status) => Error::Decrypt(status),
                None => Error::Unknown {
                    call: "ch_decrypt",
                    code,
                },
            },
        }
    }
}

/// A non-success `cdm::Status` from `ContentDecryptionModule_11::Decrypt`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DecryptStatus {
    NeedMoreData,
    NoKey,
    InitializationError,
    DecryptError,
    DecodeError,
    DeferredInitialization,
}

impl DecryptStatus {
    fn from_raw(status: c_int) -> Option<Self> {
        Some(match status {
            1 => Self::NeedMoreData,
            2 => Self::NoKey,
            3 => Self::InitializationError,
            4 => Self::DecryptError,
            5 => Self::DecodeError,
            6 => Self::DeferredInitialization,
            _ => return None,
        })
    }
}

impl fmt::Display for DecryptStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NeedMoreData => "need more data",
            Self::NoKey => "no key",
            Self::InitializationError => "initialization error",
            Self::DecryptError => "decrypt error",
            Self::DecodeError => "decode error",
            Self::DeferredInitialization => "deferred initialization",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decrypt_codes_map_to_status() {
        assert!(matches!(
            Error::from_decrypt(33),
            Error::Decrypt(DecryptStatus::NoKey)
        ));
        assert!(matches!(Error::from_decrypt(30), Error::NotOpen));
        assert!(matches!(Error::from_decrypt(40), Error::NoDecryptedBuffer));
        assert!(matches!(
            Error::from_decrypt(31),
            Error::Unknown {
                call: "ch_decrypt",
                code: 31
            }
        ));
    }

    #[test]
    fn unknown_codes_are_kept() {
        assert!(matches!(
            Error::from_update(99),
            Error::Unknown {
                call: "ch_update",
                code: 99
            }
        ));
    }
}
