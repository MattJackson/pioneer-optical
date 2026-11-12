//! Prepared transitions. Adapters choose bytes; execution consumes stages.
use super::{PreparationError, Receiver};
use crate::envelope::{Envelope, Update};

/// Why an intermediate image is needed. This does not select an executor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum BridgeKind {
    /// Temporary target marker accepted by the installed receiver.
    ReceiverMarker,
    /// Source programmer adapted to the target's recognized startup entry.
    KernelHandoff,
}

/// One immutable transition, including its receiving firmware and settings.
#[derive(Clone, Debug)]
pub struct PreparedStage {
    pub(super) receiver: Receiver,
    pub(super) kernel: Option<Envelope>,
    pub(super) kernel_bytes: Option<Vec<u8>>,
    pub(super) normal: Envelope,
    pub(super) normal_bytes: Vec<u8>,
    pub(super) settings: crate::settings::update::Plan,
    pub(super) bridge: Option<BridgeKind>,
    #[cfg(feature = "drive")]
    pub(super) normal_region: Option<crate::envelope::NormalRegion>,
}

impl PreparedStage {
    pub(super) fn pair(
        receiver: Receiver,
        target: &Update,
        settings: crate::settings::update::Plan,
        bridge: Option<BridgeKind>,
    ) -> Result<Self, PreparationError> {
        let policy = settings
            .startup_plan()
            .map_or(crate::startup::checks::Policy::CompatibleBanks, |plan| {
                plan.policy()
            });
        let startup_checks = receiver.prepare_startup_with_policy(
            &target.normal().image,
            Some(&target.kernel().image),
            policy,
        )?;
        // Retain the evidence for the actual stage, including a temporary
        // marker/handoff Kernel, rather than the pristine final target.
        let settings = settings.with_startup_checks(startup_checks);
        let installed = receiver
            .installed_kernel()
            .ok_or(PreparationError::MissingInstalledKernel)?;
        crate::image::check_kernel_handoff(&installed.image, &target.kernel().image)
            .map_err(PreparationError::KernelHandoff)?;
        if matches!(
            receiver.kernel_policy,
            Some(crate::image::KernelMarkerPolicy::RejectZeroAndErased)
        ) && matches!(
            target
                .kernel()
                .image
                .get(crate::envelope::KERNEL_MARKER_OFFSET),
            Some(0 | 0xff)
        ) {
            return Err(PreparationError::RejectedMarker);
        }
        let stage = Self {
            #[cfg(feature = "drive")]
            normal_region: super::preparation::normal_region(
                target.kernel(),
                &target.normal().image,
            ),
            receiver,
            kernel: Some(target.kernel().clone()),
            kernel_bytes: Some(target.kernel_transfer().to_vec()),
            normal: target.normal().clone(),
            normal_bytes: target.normal_transfer().to_vec(),
            settings,
            bridge,
        };
        stage.validate_transfer()?;
        Ok(stage)
    }

    pub(super) fn validate_transfer(&self) -> Result<(), PreparationError> {
        #[cfg(feature = "drive")]
        {
            let installed = self
                .receiver
                .installed_kernel()
                .ok_or(PreparationError::MissingInstalledKernel)?;
            installed
                .update_dialect()
                .ok_or(PreparationError::UnsupportedDialect)?;
            let mut storage = [crate::drive::Segment::PLACEHOLDER; 3];
            super::transport::plan(
                self.kernel_transfer(),
                self.normal_transfer(),
                super::transport::detect(&installed.image),
                &mut storage,
            )
            .map_err(|_| PreparationError::UnsupportedTransport)?;
        }
        Ok(())
    }

    /// Adaptation implemented by this intermediate, if any.
    pub fn bridge(&self) -> Option<BridgeKind> {
        self.bridge
    }
    /// Firmware component expected after this stage; absent for Normal-only.
    pub fn kernel_image(&self) -> Option<&[u8]> {
        self.kernel.as_ref().map(|k| k.image.as_slice())
    }
    /// Kernel bytes prepared for this stage's installed receiver.
    pub fn kernel_transfer(&self) -> Option<&[u8]> {
        self.kernel_bytes.as_deref()
    }
    /// Normal bytes authenticated for the Kernel that will receive them.
    pub fn normal_transfer(&self) -> &[u8] {
        &self.normal_bytes
    }
    /// Exact decoded Normal expected after this stage.
    pub fn normal_image(&self) -> &[u8] {
        &self.normal.image
    }
    /// Target identity for display and startup verification.
    pub fn target_info(&self) -> &crate::envelope::EnvelopeInfo {
        self.normal.info()
    }
    /// Settings applied at this transition, including startup-word migration.
    pub fn settings(&self) -> &crate::settings::update::Plan {
        &self.settings
    }
}

/// Static firmware stages, ending in the pristine target.
#[derive(Debug)]
pub struct PreparedUpdate {
    pub(super) stages: Vec<PreparedStage>,
    pub(super) target: Update,
    pub(super) kernel_steps: Vec<crate::compatibility::KernelStep>,
}

impl PreparedUpdate {
    /// Native Kernel actions selected for this exact A-to-B transition.
    /// These correspond in order to `stages()` and end in the pristine target.
    pub fn kernel_steps(&self) -> &[crate::compatibility::KernelStep] {
        &self.kernel_steps
    }
    /// Static transitions, including marker/handoff bridges and final OEM pass.
    pub fn stages(&self) -> &[PreparedStage] {
        &self.stages
    }
    /// Advertised final target identity.
    pub fn target_info(&self) -> &crate::envelope::EnvelopeInfo {
        self.target.normal().info()
    }
    /// Final target's startup setting; execution applies each stage's own plan.
    pub fn startup_setting(&self) -> Option<crate::startup::Setting> {
        self.settings().startup_setting()
    }
    /// Final target's settings. Inspect `stages()` for intermediate settings.
    pub fn settings(&self) -> &crate::settings::update::Plan {
        self.stages.last().expect("prepared stage").settings()
    }
    /// First static Kernel transfer.
    pub fn kernel_transfer(&self) -> &[u8] {
        self.stages[0].kernel_transfer().expect("complete pair")
    }
    /// First static stage's Normal transfer.
    pub fn normal_transfer(&self) -> &[u8] {
        self.stages[0].normal_transfer()
    }
    /// Exact initial Kernel readback expectation.
    pub fn first_kernel_image(&self) -> &[u8] {
        self.stages[0].kernel_image().expect("complete pair")
    }
    /// Final OEM transfer when an intermediate precedes it.
    pub fn final_stage_kernel_transfer(&self) -> Option<&[u8]> {
        (self.stages.len() > 1)
            .then(|| self.stages.last().expect("final stage").kernel_transfer())
            .flatten()
    }
    /// Receiver for the final transition after an intermediate.
    pub fn final_stage_receiver(&self) -> Option<&Receiver> {
        (self.stages.len() > 1).then(|| &self.stages.last().expect("final stage").receiver)
    }
    /// Exact final Kernel readback expectation.
    pub fn final_kernel_image(&self) -> &[u8] {
        &self.target.kernel().image
    }
}

/// A Normal-only update uses the same stage model without a Kernel transfer.
#[derive(Debug)]
pub struct PreparedNormal {
    pub(super) stage: PreparedStage,
}
impl PreparedNormal {
    /// The single prepared transition.
    pub fn stage(&self) -> &PreparedStage {
        &self.stage
    }
    /// Advertised target identity.
    pub fn target_info(&self) -> &crate::envelope::EnvelopeInfo {
        self.stage.target_info()
    }
    /// Target-derived startup migration.
    pub fn startup_setting(&self) -> Option<crate::startup::Setting> {
        self.settings().startup_setting()
    }
    /// Settings required for this transition.
    pub fn settings(&self) -> &crate::settings::update::Plan {
        self.stage.settings()
    }
    /// Authenticated Normal transfer.
    pub fn normal_transfer(&self) -> &[u8] {
        self.stage.normal_transfer()
    }
    /// Exact decoded Normal expectation.
    pub fn normal_image(&self) -> &[u8] {
        self.stage.normal_image()
    }
}
