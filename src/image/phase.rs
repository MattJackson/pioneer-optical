//! Phase vocabulary shared by the native recognizers in [`super::peripheral`]
//! and the phase owner in `crate::filters::phase`, which re-exports it.

/// Assignment of the two source words to the two output channels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Assignment {
    /// Source word zero goes to the first output channel.
    Direct,
    /// Source word zero goes to the second output channel.
    Swapped,
}

/// A Normal-only phase correction could not be established.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CorrectionError {
    /// A complete unambiguous binding with an execution-preserving correction
    /// is unavailable. A program can remain observable without such a correction.
    Unresolved,
    /// Normal header, declared length or additive checksum is invalid.
    InvalidNormal,
    /// The corrected bytes did not reproduce the requested native assignment.
    VerificationFailed,
}

