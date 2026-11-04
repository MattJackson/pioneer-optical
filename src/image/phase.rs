//! Compatibility entry points for the registered phase owner.
//! Native recognition, corrections and templates live together under filters/phase.
#[cfg(test)]
pub(crate) use crate::filters::phase::native::tests;
pub use crate::filters::phase::native::*;
