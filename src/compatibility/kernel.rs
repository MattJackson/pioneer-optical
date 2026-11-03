//! Firmware-derived ordering of the existing temporary Kernel bridge effects.
use crate::image::{self, KernelHandoffError, KernelMarkerPolicy};
use alloc::vec::Vec;

/// One required step in a complete Kernel replacement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KernelStep {
    /// Install the source Kernel with its programmer restart redirected to the
    /// target startup. The source Kernel's own startup is preserved.
    Handoff {
        /// Restart address used by the installed programming routine.
        from: u32,
        /// Required startup address in the target Kernel.
        to: u32,
    },
    /// Install a temporary target Kernel marker accepted by its receiver.
    ReceiverMarker {
        /// Original target marker, restored by the final OEM stage.
        from: u8,
        /// Temporary marker value.
        to: u8,
    },
    /// Install the unmodified requested target Kernel.
    Target,
}

/// A Kernel transition lacks the native evidence required to build its stages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KernelPlanningError {
    /// The installed Kernel's incoming-marker policy is unknown.
    UnknownInstalledPolicy,
    /// A supported post-programming handoff could not be established.
    Handoff(KernelHandoffError),
    /// The source bridge would carry a marker rejected by its own receiver.
    RejectedBridgeMarker,
    /// The target does not establish acceptance of its pristine final stage.
    UnsupportedRestoration,
}

impl core::fmt::Display for KernelPlanningError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnknownInstalledPolicy => {
                f.write_str("installed Kernel marker policy is unsupported")
            }
            Self::Handoff(error) => error.fmt(f),
            Self::RejectedBridgeMarker => {
                f.write_str("source Kernel bridge marker is rejected by its receiver")
            }
            Self::UnsupportedRestoration => f.write_str(
                "target Kernel does not establish acceptance of its pristine final stage",
            ),
        }
    }
}
impl std::error::Error for KernelPlanningError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Handoff(error) => Some(error),
            _ => None,
        }
    }
}
impl crate::CodedError for KernelPlanningError {
    fn code(&self) -> &'static str {
        match self {
            Self::UnknownInstalledPolicy => "pioneer.preparation.unknown_installed_kernel",
            Self::Handoff(error) => error.code(),
            Self::RejectedBridgeMarker => "pioneer.preparation.rejected_marker",
            Self::UnsupportedRestoration => "pioneer.preparation.unsupported_restoration",
        }
    }
}

/// Ordered Kernel effects bound to the exact decoded component inputs.
/// Planning performs no mutation or device I/O. Each stage must still be built,
/// checksum-validated, decoded and admitted against its receiving firmware.
pub struct KernelTransitionPlan<'a> {
    installed: &'a [u8],
    target: &'a [u8],
    steps: Vec<KernelStep>,
}
impl KernelTransitionPlan<'_> {
    /// Required steps, ending in the unmodified target.
    pub fn steps(&self) -> &[KernelStep] {
        &self.steps
    }
    /// Reject component substitution when materializing the planned stages.
    pub fn matches_components(&self, installed: &[u8], target: &[u8]) -> bool {
        self.installed == installed && self.target == target
    }
    /// Whether an intermediate marker must be restored by the final stage.
    pub fn restores_marker(&self) -> bool {
        self.steps
            .iter()
            .any(|s| matches!(s, KernelStep::ReceiverMarker { .. }))
    }
    pub(crate) fn into_steps(self) -> Vec<KernelStep> {
        self.steps
    }
}

fn rejected_marker(policy: KernelMarkerPolicy, kernel: &[u8]) -> bool {
    policy == KernelMarkerPolicy::RejectZeroAndErased
        && matches!(
            kernel.get(crate::envelope::KERNEL_MARKER_OFFSET),
            Some(0 | 0xff)
        )
}

/// Evaluate the existing handoff and marker rules for any supplied A-to-B pair.
/// Native signatures and actual operands select the steps; no model, SAT-pair
/// recipe or version ordering participates in this decision.
pub fn plan_kernel<'a>(
    installed: &'a [u8],
    target: &'a [u8],
) -> Result<KernelTransitionPlan<'a>, KernelPlanningError> {
    let policy = image::kernel_marker_policy(installed)
        .ok_or(KernelPlanningError::UnknownInstalledPolicy)?;
    let mut steps = Vec::new();
    match image::check_kernel_handoff(installed, target) {
        Ok(()) => {}
        Err(KernelHandoffError::Mismatch {
            installed: from,
            target: to,
        }) => {
            let own_startup = image::kernel_startup_entry(installed).ok_or(
                KernelPlanningError::Handoff(KernelHandoffError::UnknownInstalled),
            )?;
            if own_startup != from {
                return Err(KernelPlanningError::Handoff(KernelHandoffError::Mismatch {
                    installed: from,
                    target: own_startup,
                }));
            }
            if rejected_marker(policy, installed) {
                return Err(KernelPlanningError::RejectedBridgeMarker);
            }
            steps.push(KernelStep::Handoff { from, to });
        }
        Err(error) => return Err(KernelPlanningError::Handoff(error)),
    }
    if rejected_marker(policy, target) {
        if image::kernel_marker_policy(target) != Some(KernelMarkerPolicy::NoMarkerCheck) {
            return Err(KernelPlanningError::UnsupportedRestoration);
        }
        steps.push(KernelStep::ReceiverMarker {
            from: target[crate::envelope::KERNEL_MARKER_OFFSET],
            to: 1,
        });
    }
    steps.push(KernelStep::Target);
    Ok(KernelTransitionPlan {
        installed,
        target,
        steps,
    })
}

#[cfg(test)]
#[path = "kernel_tests.rs"]
mod tests;
