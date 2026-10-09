//! Structured failures from read-only firmware inspection.

/// A firmware shape the inspector cannot establish safely.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The image uses an unsupported instruction or structure.
    Unsupported {
        /// Structure or proof that was not recognized.
        context: &'static str,
    },
    /// More than one candidate satisfies the recognizer.
    Ambiguous {
        /// Structure being discovered.
        context: &'static str,
        /// Number of competing candidates.
        candidates: usize,
    },
    /// A recognized structure contains invalid fields.
    Malformed {
        /// Invalid structure or field.
        context: &'static str,
    },
    /// An address or size cannot be represented or lies outside the image.
    OutOfRange {
        /// Address or size being resolved.
        context: &'static str,
    },
    /// An instruction is not supported by the bounded ABI proof.
    Instruction {
        /// CPU address of the instruction.
        address: u32,
    },
    /// A bounded inspection reached its resource limit.
    Limit {
        /// Limit that prevented further inspection.
        context: &'static str,
    },
}

impl crate::CodedError for Error {
    fn code(&self) -> &'static str {
        match self {
            Self::Unsupported { .. } => "pioneer.firmware.unsupported",
            Self::Ambiguous { .. } => "pioneer.firmware.ambiguous",
            Self::Malformed { .. } => "pioneer.firmware.malformed",
            Self::OutOfRange { .. } => "pioneer.firmware.out_of_range",
            Self::Instruction { .. } => "pioneer.firmware.instruction",
            Self::Limit { .. } => "pioneer.firmware.limit",
        }
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unsupported { context } => write!(f, "unsupported firmware: {context}"),
            Self::Ambiguous {
                context,
                candidates,
            } => write!(f, "ambiguous {context}: {candidates} candidates"),
            Self::Malformed { context } => write!(f, "malformed firmware: {context}"),
            Self::OutOfRange { context } => write!(f, "firmware range error: {context}"),
            Self::Instruction { address } => {
                write!(f, "unsupported ABI instruction at {address:#x}")
            }
            Self::Limit { context } => write!(f, "firmware inspection limit: {context}"),
        }
    }
}
impl std::error::Error for Error {}
impl From<crate::comp_streams::StreamError> for Error {
    fn from(error: crate::comp_streams::StreamError) -> Self {
        use crate::comp_streams::StreamError;
        match error {
            StreamError::Directory => Self::Malformed {
                context: "COMP directory",
            },
            StreamError::Invalid => Self::Malformed {
                context: "COMP streams",
            },
            StreamError::Ambiguous => Self::Ambiguous {
                context: "COMP image base",
                candidates: 2,
            },
            StreamError::Limit => Self::Limit {
                context: "COMP expansion",
            },
            StreamError::Cancelled => Self::Limit {
                context: "COMP inspection cancelled",
            },
        }
    }
}
impl From<core::num::TryFromIntError> for Error {
    fn from(_: core::num::TryFromIntError) -> Self {
        Self::OutOfRange {
            context: "integer conversion",
        }
    }
}

pub(crate) trait Context<T> {
    fn context(self, context: &'static str) -> Result<T, Error>;
}
impl<T> Context<T> for Option<T> {
    fn context(self, context: &'static str) -> Result<T, Error> {
        self.ok_or(Error::OutOfRange { context })
    }
}
impl<T> Context<T> for Result<T, core::num::TryFromIntError> {
    fn context(self, context: &'static str) -> Result<T, Error> {
        self.map_err(|_| Error::OutOfRange { context })
    }
}

pub(crate) fn unique<T>(mut values: Vec<T>, context: &'static str) -> Result<T, Error> {
    match values.len() {
        0 => Err(Error::Unsupported { context }),
        1 => Ok(values.remove(0)),
        candidates => Err(Error::Ambiguous {
            context,
            candidates,
        }),
    }
}

macro_rules! ensure {
    ($condition:expr, $context:literal $(,)?) => {
        if !$condition {
            return Err(crate::firmware::Error::Unsupported { context: $context });
        }
    };
}
pub(crate) use ensure;
