//! The owner contract vocabulary: the firmware an owner inspects, the
//! corrections it may authorize and why a required proof failed. The planner
//! (`compatibility`) composes owners through these types; it re-exports them.

/// Firmware context from structured metadata and the exact associated Kernel.
#[derive(Clone, Copy)]
pub struct Firmware<'a> {
    /// Exact hardware tag; never inferred from a model name.
    pub hardware: &'a str,
    /// Decoded Normal bytes.
    pub normal: &'a [u8],
    /// Exact associated decoded Kernel, when available.
    pub kernel: Option<&'a [u8]>,
}

/// A required proof for a firmware correction failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A required identity input could not be established.
    UnresolvedIdentity,
    /// At least one noncorrectable filter differs.
    Incompatible,
    /// Target Normal occupies addresses needed for retained parameter records.
    /// A primary-address operand rewrite cannot preserve both byte contents.
    PersistentLayoutOverlap {
        /// Installed absolute record-region start, inclusive.
        start: u32,
        /// End of the traced installed record region, exclusive.
        end: u32,
    },
    /// No supported correction connects the established identities.
    Unsupported,
    /// Native phase correction or Normal checksum validation failed.
    Phase(crate::image::phase::CorrectionError),
    /// Corrected firmware did not reproduce the installed identity.
    VerificationFailed,
    /// Envelope components differ from the firmware used to make the plan.
    ComponentMismatch,
    /// Corrected firmware could not be rebuilt and decoded exactly.
    Representation,
    /// Required envelope authentication could not be produced or verified.
    Authentication,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnresolvedIdentity => {
                f.write_str("required firmware identity evidence is unresolved")
            }
            Self::Incompatible => {
                f.write_str("a required hardware filter differs without a supported correction")
            }
            Self::PersistentLayoutOverlap { start, end } => write!(f,
                "target Normal occupies retained parameter-record addresses {start:#08x}..{end:#08x}; changing the primary address alone cannot preserve these records"),
            Self::Unsupported => f.write_str("this native firmware correction is unsupported"),
            Self::Phase(error) => write!(f, "native phase correction failed: {error:?}"),
            Self::VerificationFailed => {
                f.write_str("prepared firmware did not reproduce the required identity")
            }
            Self::ComponentMismatch => {
                f.write_str("firmware components do not match the correction plan")
            }
            Self::Representation => {
                f.write_str("prepared firmware could not be rebuilt and decoded exactly")
            }
            Self::Authentication => {
                f.write_str("prepared Normal does not satisfy Kernel authentication")
            }
        }
    }
}
impl std::error::Error for Error {}

impl crate::CodedError for Error {
    fn code(&self) -> &'static str {
        match self {
            Self::UnresolvedIdentity => "pioneer.compatibility.unresolved_identity",
            Self::Incompatible => "pioneer.compatibility.incompatible",
            Self::PersistentLayoutOverlap { .. } => {
                "pioneer.compatibility.persistent_layout_overlap"
            }
            Self::Unsupported => "pioneer.compatibility.unsupported_correction",
            Self::Phase(_) => "pioneer.compatibility.phase_correction",
            Self::VerificationFailed => "pioneer.compatibility.verification_failed",
            Self::ComponentMismatch => "pioneer.compatibility.component_mismatch",
            Self::Representation => "pioneer.compatibility.representation_failed",
            Self::Authentication => "pioneer.compatibility.authentication_failed",
        }
    }
}

/// A native firmware difference with a supported correction.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Correction {
    /// A correction supplied by a registered filter without central dispatch.
    Registered {
        /// Stable identifier of the owner authorizing the correction.
        filter: &'static str,
        /// Native facts in the requested firmware before correction.
        from: crate::filters::Finding,
        /// Required native facts after correction.
        to: crate::filters::Finding,
    },
    /// Change target output assignment to the installed hardware assignment.
    Phase {
        /// Assignment currently encoded in target Normal.
        from: crate::image::phase::Assignment,
        /// Required installed assignment.
        to: crate::image::phase::Assignment,
    },
}

