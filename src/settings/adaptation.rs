//! Compatibility aliases for mechanism corrections now owned by the planner.
pub use crate::compatibility::mechanism::{hardware_rules, Error, Requirement};
/// Whether the binary contains reviewed mechanism correction contracts.
pub fn has_profiles() -> bool {
    crate::compatibility::mechanism::has_corrections()
}
