//! Compatibility aliases for reviewed mechanism correction owned with phase.
//! Implementation, recipes and native evidence live under filters/phase.
pub(crate) use crate::filters::phase::mechanism::HardwareGuard;
#[cfg(test)]
pub(crate) use crate::filters::phase::mechanism::{digest, phase, phase_at, reviewed_recipe_image};
pub use crate::filters::phase::mechanism::{
    hardware_rules, has_corrections, Contract, Error, Requirement,
};
