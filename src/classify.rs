//! Pair verdicts and their vocabulary. Nothing here materializes an image:
//! these are the facts a flasher, a `--why` explanation or a catalogue graph
//! use to say whether, and why, firmware `B` may replace firmware `A`.
//!
//! The full admission decision runs through `crate::prepare::Receiver`;
//! its refusals are this module's `Error`.

/// A refused or unresolved compatibility decision.
pub use crate::receiver::Error;

/// Hardware family fingerprint and the scheme it is computed under.
pub use crate::filters::family::{Family, MATRIX_FAMILY_SCHEME};

/// Kernel handoff and receiver-generation facts that decide a route's class.
pub use crate::image::{kernel_marker_policy, KernelHandoffError, KernelMarkerPolicy};

/// The controller platform named by a hardware tag (`SAT xxxx`, `REC xxxx`).
pub use crate::image::matrix::SatPlatform;

/// Field-by-field explanation of why two firmwares land in different families.
pub use crate::filters::identity::{candidate_key_diff, FieldDiff, KeyDiff};

/// Device words a prepared correction sets before the first transfer.
pub use crate::filters::prerequisites::{OwnedWord, Word};
