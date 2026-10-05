//! Error type for envelope construction, validation and signing.

use core::fmt;

/// Why an envelope could not be built, validated or signed.
///
/// Decoding functions return `Option` instead: an unrecognized envelope is an
/// expected outcome there, not a failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Error {
    /// The embedded filename is too long or not ASCII.
    InvalidFilename,
    /// The envelope `ID` string has no model token.
    MissingModel,
    /// A header field is too long or holds non-printable bytes.
    HeaderFieldsDoNotFit,
    /// The Kernel image does not have the expected H8/SAT structure.
    KernelStructure,
    /// The Kernel image or drive identity is missing required fields.
    KernelIncomplete,
    /// The Kernel dispatcher does not identify a unique envelope layout.
    AmbiguousKernelLayout,
    /// A raw Kernel key must be exactly 0x1000 bytes.
    RawKeyLength,
    /// A derived-key Kernel needs an LCG seed, not raw key bytes.
    RawKeyNotAllowed,
    /// Encoding the Kernel image failed.
    KernelEncode,
    /// The Normal and Kernel images do not have the expected H8/SAT structure.
    ImageStructure,
    /// The Normal image or drive identity is missing required fields.
    ImageIncomplete,
    /// The Normal build date is not valid.
    InvalidDate,
    /// The Kernel XOR exception policy is not unique.
    XorPolicyNotUnique,
    /// A Kernel XOR exception lies outside the Normal image.
    XorExceptionOutOfRange,
    /// Encoding the Normal image failed.
    NormalEncode,
    /// The Kernel authentication policy is not recognized.
    UnknownAuthentication,
    /// The supplied OEM Normal signature block is not exactly 0x50 bytes.
    SignatureBlockLength,
    /// The envelope size or Normal signature is not valid.
    InvalidSignedEnvelope,
    /// The Kernel body is not the expected 64 KiB.
    KernelBodySize {
        /// Actual length received.
        got: usize,
    },
    /// The Kernel generation marker is not `0x00`, `0x01` or `0xFF`; the body is
    /// almost certainly corrupt.
    UnknownMarker {
        /// The marker byte found at offset `0xFE`.
        marker: u8,
    },
    /// The Normal requires Kernel entry points the Kernel does not provide.
    AbiMismatch,
    /// The Kernel envelope cannot be decoded.
    KernelUndecodable,
    /// The Normal envelope cannot be decoded with the Kernel's receiver rules.
    NormalUndecodable,
    /// Decoding the built envelopes does not reproduce the input images.
    RoundTripMismatch,
    /// The input is not a Normal envelope that can be signed.
    NotSignableNormal,
    /// A firmware identity field is not ASCII.
    NotAscii,
    /// The operating system could not supply entropy.
    EntropyUnavailable,
    /// Sampling a signing scalar or nonce failed.
    Randomness,
    /// An elliptic-curve intermediate value was invalid.
    InvalidPoint,
    /// An ECDSA operand exceeds 160 bits.
    OperandTooLarge,
    /// The freshly produced signature failed verification.
    SelfVerification,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::InvalidFilename => "invalid embedded filename",
            Error::MissingModel => "envelope ID has no model",
            Error::HeaderFieldsDoNotFit => "Pioneer header fields do not fit",
            Error::KernelStructure => "Kernel image does not satisfy Pioneer H8/SAT structure",
            Error::KernelIncomplete => "Kernel image or drive identity is incomplete",
            Error::AmbiguousKernelLayout => {
                "Kernel receiver dispatcher does not identify a unique envelope layout"
            }
            Error::RawKeyLength => "raw Kernel key must be exactly 0x1000 bytes",
            Error::RawKeyNotAllowed => "derived-key Kernel requires an LCG seed, not raw key bytes",
            Error::KernelEncode => "Kernel encode failed",
            Error::ImageStructure => "images do not satisfy Pioneer H8/SAT image structure",
            Error::ImageIncomplete => "image or drive identity is incomplete",
            Error::InvalidDate => "Normal build date is invalid",
            Error::XorPolicyNotUnique => "Kernel XOR exception policy is not unique",
            Error::XorExceptionOutOfRange => "Kernel XOR exception is outside Normal image",
            Error::NormalEncode => "Normal encode failed",
            Error::UnknownAuthentication => "Kernel authentication policy is unknown",
            Error::SignatureBlockLength => "OEM Normal signature block must be exactly 0x50 bytes",
            Error::InvalidSignedEnvelope => "envelope size or Normal signature is invalid",
            Error::KernelBodySize { got } => {
                return write!(
                    f,
                    "Kernel body is {got} bytes, expected {}",
                    crate::image::KERNEL_LEN
                );
            }
            Error::UnknownMarker { marker } => {
                return write!(f, "unrecognized generation marker {marker:#04x}");
            }
            Error::AbiMismatch => "Normal requires Kernel entry points the Kernel does not provide",
            Error::KernelUndecodable => "Kernel envelope cannot be decoded",
            Error::NormalUndecodable => "Normal envelope cannot be receiver-decoded",
            Error::RoundTripMismatch => "envelope round trip differs from the input images",
            Error::NotSignableNormal => "invalid Normal envelope",
            Error::NotAscii => "firmware identity is not ASCII",
            Error::EntropyUnavailable => "OS entropy unavailable",
            Error::Randomness => "failed to sample a valid signing value",
            Error::InvalidPoint => "invalid curve point",
            Error::OperandTooLarge => "ECDSA operand exceeds 160 bits",
            Error::SelfVerification => "self-signed envelope failed verification",
        })
    }
}

impl std::error::Error for Error {}

/// Result alias for envelope construction and signing.
pub type Result<T, E = Error> = core::result::Result<T, E>;

#[cfg(test)]
mod display_tests {
    use super::*;
    use std::string::ToString;

    #[test]
    fn display_is_the_documented_text() {
        assert_eq!(
            Error::InvalidFilename.to_string(),
            "invalid embedded filename"
        );
        assert_eq!(
            Error::SelfVerification.to_string(),
            "self-signed envelope failed verification"
        );
        assert_eq!(
            Error::UnknownMarker { marker: 0x7 }.to_string(),
            "unrecognized generation marker 0x07"
        );
        assert!(Error::KernelBodySize { got: 5 }
            .to_string()
            .starts_with("Kernel body is 5 bytes, expected "));
    }
}
