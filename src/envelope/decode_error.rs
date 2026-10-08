//! Typed failures from automatic envelope recognition.

/// Why an envelope could not be loaded. No variant implies drive compatibility.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DecodeError {
    /// The literal header is absent, truncated or lacks a component kind.
    InvalidHeader,
    /// No supported codec recognizes the file structure.
    UnsupportedLayout,
    /// Multiple non-equivalent codecs or payload positions recognize the file.
    AmbiguousLayout,
    /// A recognized payload cannot be decoded consistently with its metadata.
    InvalidPayload,
    /// The supplied Kernel does not prove a unique decoding policy for this Normal.
    ReceiverPolicy {
        /// Detected Kernel envelope layout.
        kernel_layout: super::Layout,
        /// Detected Normal envelope layout.
        normal_layout: super::Layout,
    },
    /// The stored payload is not a whole number of codec words.
    PayloadAlignment {
        /// Recognized codec.
        layout: super::Layout,
        /// Required word size in bytes.
        alignment: usize,
        /// Actual payload size in bytes.
        actual: usize,
    },
    /// The envelope's stored checksum does not match its payload.
    ChecksumMismatch {
        /// Recognized codec.
        layout: super::Layout,
        /// File offset of the checksum word.
        checksum_offset: usize,
        /// Checksum stored in the envelope.
        stored: u32,
        /// Checksum calculated from the payload.
        calculated: u32,
    },
    /// A decoded format-defined additive checksum is not zero.
    DecodedChecksum {
        /// Recognized codec.
        layout: super::Layout,
        /// Additive checksum word width in bits.
        word_bits: u8,
        /// Observed wrapping sum; zero was required.
        sum: u32,
    },
    /// A recognized payload declares a different size from the decoded bytes.
    PayloadLengthMismatch {
        /// Codec that recognized the envelope.
        layout: super::Layout,
        /// Start of the encoded payload in the input file.
        payload_offset: usize,
        /// Size recorded by the payload header, in bytes.
        declared: usize,
        /// Number of decoded bytes actually available.
        actual: usize,
    },
}
impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidHeader => f.write_str("invalid firmware envelope header"),
            Self::UnsupportedLayout => f.write_str("unsupported firmware envelope layout"),
            Self::AmbiguousLayout => f.write_str("ambiguous firmware envelope layout"),
            Self::InvalidPayload => f.write_str("invalid firmware envelope payload"),
            Self::ReceiverPolicy { kernel_layout, normal_layout } => write!(f,
                "Kernel {kernel_layout} does not establish a unique receiver decoding policy for Normal {normal_layout}"),
            Self::PayloadAlignment { layout, alignment, actual } => write!(f,
                "firmware envelope {layout} payload size {actual:#x} is not aligned to {alignment} bytes"),
            Self::ChecksumMismatch { layout, checksum_offset, stored, calculated } => write!(f,
                "firmware envelope {layout} checksum at file offset {checksum_offset:#x}: stored {stored:#010x}, calculated {calculated:#010x}"),
            Self::DecodedChecksum { layout, word_bits, sum } => write!(f,
                "firmware envelope {layout} decoded {word_bits}-bit checksum is {sum:#x}; expected zero"),
            Self::PayloadLengthMismatch { layout, payload_offset, declared, actual } => write!(f,
                "firmware envelope {layout:?} payload at file offset {payload_offset:#x} declares {declared:#x} bytes, but decoded {actual:#x} bytes"),
        }
    }
}
impl std::error::Error for DecodeError {}
