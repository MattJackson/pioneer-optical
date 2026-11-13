//! Immutable component preparation; no transport or device I/O.

use alloc::sync::Arc;

use super::{BridgeKind, Error, PreparedNormal, PreparedStage, PreparedUpdate, Receiver};
use crate::envelope::{downgrade_patch, Envelope, Update, UpdateError, KERNEL_MARKER_OFFSET};

/// A receiver could not prepare all required update passes.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PreparationError {
    /// Persistent storage requirements differ or could not be recovered.
    Startup(crate::startup::checks::Error),
    /// More than one startup comparison prevents selecting a target value.
    /// Retained for compatibility; preparation reports ambiguous startup words
    /// as [`Self::Startup`] and unresolved ones as [`Self::PhaseCorrection`].
    AmbiguousStartup,
    /// An observed startup comparison is not bound to a proven parameter getter.
    /// Retained for compatibility; preparation reports it as
    /// [`Self::PhaseCorrection`].
    UnresolvedStartup,
    /// The native compatibility plan or its prepared correction was refused.
    /// The historical variant name also covers non-phase filter failures.
    PhaseCorrection(crate::compatibility::Error),
    /// Target requires a setting but the installed write surface is unknown.
    /// Retained for compatibility; preparation no longer produces it, since
    /// startup word writes belong to the verified correction plan.
    UnknownStartupAccess,
    /// Installed updater cannot hand control to the replacement Kernel.
    KernelHandoff(crate::image::KernelHandoffError),
    /// Target validation failed against the installed Kernel.
    Target(UpdateError),
    /// Normal-only preparation requires the captured installed Kernel.
    MissingInstalledKernel,
    /// The captured Kernel cannot reproduce its envelope for pair validation.
    InstalledKernelRepresentation,
    /// Installed/target hardware compatibility could not be established.
    Compatibility(Error),
    /// The installed Kernel's marker handling is not recognized.
    UnknownInstalledKernel,
    /// A prepared intermediate still carries a marker rejected by its receiver.
    RejectedMarker,
    /// The target Kernel cannot be proven to accept the final target stage.
    UnsupportedFinalStage,
    /// The target Normal's entry requirements could not be established.
    FinalStageEntry(Error),
    /// A required pass has no firmware-derived entry dialect.
    UnsupportedDialect,
    /// A required pass has no valid transfer layout.
    UnsupportedTransport,
    /// A patched Kernel could not be encoded in the required transfer format.
    PatchedRepresentation,
    /// A patched bridge's owned Normal transfer copy could not be signed.
    PatchedSigning(crate::envelope::Error),
}

impl core::fmt::Display for PreparationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Startup(error) => error.fmt(f),
            Self::PhaseCorrection(error) => error.fmt(f),
            Self::UnresolvedStartup => f.write_str("startup comparison is not bound to its native parameter getter"),
            Self::AmbiguousStartup => f.write_str("target startup checks are ambiguous; no startup setting can be selected"),
            Self::UnknownStartupAccess => f.write_str("startup-setting migration is required but the installed firmware's parameter write command is unrecognized; no firmware was written"),
            Self::KernelHandoff(error) => write!(f, "Kernel replacement: {error}"),
            Self::Target(error) => write!(f, "target preparation: {error}"),
            Self::MissingInstalledKernel => {
                f.write_str("Normal-only preparation requires captured installed Kernel evidence")
            }
            Self::InstalledKernelRepresentation => {
                f.write_str("captured installed Kernel cannot be represented for pair validation")
            }
            Self::Compatibility(error) => write!(f, "update compatibility: {error}"),
            Self::UnknownInstalledKernel => {
                f.write_str("installed Kernel marker policy is unsupported or unavailable")
            }
            Self::RejectedMarker => f.write_str("prepared Kernel marker is rejected by its receiving firmware"),
            Self::UnsupportedFinalStage => f.write_str(
                "target Kernel does not establish a supported final stage",
            ),
            Self::FinalStageEntry(error) => write!(f, "final stage entry: {error}"),
            Self::UnsupportedDialect => f.write_str("a required receiver has no unique update-entry dialect signature"),
            Self::UnsupportedTransport => f.write_str("a required receiver transfer layout is unsupported"),
            Self::PatchedRepresentation => {
                f.write_str("temporarily patched Kernel cannot be represented for transfer")
            }
            Self::PatchedSigning(error) => {
                write!(f, "temporarily patched Kernel transfer cannot be signed: {error}")
            }
        }
    }
}
impl std::error::Error for PreparationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Startup(error) => Some(error),
            Self::PhaseCorrection(error) => Some(error),
            Self::KernelHandoff(error) => Some(error),
            Self::Target(error) => Some(error),
            Self::Compatibility(error) | Self::FinalStageEntry(error) => Some(error),
            Self::PatchedSigning(error) => Some(error),
            _ => None,
        }
    }
}

impl Receiver {
    /// Plan every startup check, independently of hardware-family overrides.
    pub fn prepare_startup(
        &self,
        normal: &[u8],
        kernel: Option<&[u8]>,
    ) -> Result<crate::startup::checks::Plan, PreparationError> {
        self.prepare_startup_with_policy(
            normal,
            kernel,
            crate::startup::checks::Policy::CompatibleBanks,
        )
    }
    pub(super) fn prepare_startup_with_policy(
        &self,
        normal: &[u8],
        kernel: Option<&[u8]>,
        policy: crate::startup::checks::Policy,
    ) -> Result<crate::startup::checks::Plan, PreparationError> {
        // Persistent banks must match under every policy, including the
        // Recovery family override. No bank format conversion exists.
        let target = crate::startup::checks::Checks::discover(normal, kernel);
        self.startup
            .plan_to_with_policy(target, policy)
            .map_err(PreparationError::Startup)
    }
    fn prepare_corrections(
        &self,
        normal: &Envelope,
        kernel: &Envelope,
        check_family: bool,
    ) -> Result<Option<crate::compatibility::PreparedCorrection>, PreparationError> {
        if !check_family {
            self.prepare_startup_with_policy(
                &normal.image,
                Some(&kernel.image),
                crate::startup::checks::Policy::ExplicitCrossflash,
            )?;
        }
        let plan = self.plan_native_correction(normal, kernel, check_family)?;
        let required_words = plan
            .required_words()
            .map_err(PreparationError::PhaseCorrection)?;
        let word_writes = plan
            .word_writes()
            .map_err(PreparationError::PhaseCorrection)?;
        let image = plan
            .prepare_image(normal, Some(kernel))
            .map_err(PreparationError::PhaseCorrection)?;
        // A live-word obligation still needs a receiver handoff even if no bytes change.
        Ok(image
            .or_else(|| {
                (!required_words.is_empty() || !word_writes.is_empty())
                    .then(|| normal.image.clone())
            })
            .map(|image| {
                crate::compatibility::PreparedCorrection::native(
                    image,
                    plan.corrections(),
                    required_words,
                    word_writes,
                )
            }))
    }

    fn plan_native_correction<'a>(
        &self,
        target: &'a Envelope,
        kernel: &'a Envelope,
        check_family: bool,
    ) -> Result<crate::compatibility::CorrectionPlan<'a>, PreparationError> {
        use crate::compatibility::{self as correction, Firmware};
        let installed = self
            .installed_normal
            .as_ref()
            .ok_or(PreparationError::Compatibility(
                Error::UnknownInstalledFamily,
            ))?;
        let policy = if check_family {
            crate::filters::runner::Policy::Strict
        } else {
            crate::filters::runner::Policy::FamilyOverride
        };
        correction::plan_with_policy(
            Firmware {
                hardware: &installed.info().hardware_version,
                normal: &installed.image,
                kernel: self.installed_kernel.as_ref().map(|k| k.image.as_slice()),
            },
            Firmware {
                hardware: &target.info().hardware_version,
                normal: &target.image,
                kernel: Some(&kernel.image),
            },
            policy,
        )
        .map_err(|error| {
            if check_family
                && matches!(
                    error,
                    correction::Error::Incompatible | correction::Error::UnresolvedIdentity
                )
            {
                if let Err(family_error) = self.check_family_with_kernel(target, kernel) {
                    return PreparationError::Compatibility(family_error);
                }
            }
            PreparationError::PhaseCorrection(error)
        })
    }

    fn encode_correction(
        &self,
        normal: &Envelope,
        corrected: &crate::compatibility::PreparedCorrection,
        kernel: &Envelope,
    ) -> Result<Vec<u8>, PreparationError> {
        crate::compatibility::rebuild_normal(normal, Some(kernel), &corrected.image)
            .map_err(PreparationError::PhaseCorrection)
    }

    #[cfg(test)]
    fn startup_selection_for(
        context: &crate::filters::Context<'_>,
    ) -> Result<Option<crate::startup::selection::Plan>, PreparationError> {
        crate::filters::startup::selection(context).map_err(|_| {
            match crate::filters::startup::inspect(context).finding {
                crate::filters::Finding::Conflicting(_) => PreparationError::AmbiguousStartup,
                _ => PreparationError::UnresolvedStartup,
            }
        })
    }

    #[cfg(test)]
    fn startup_plan_for(
        &self,
        firmware: crate::compatibility::Firmware<'_>,
    ) -> Result<Option<crate::startup::selection::Plan>, PreparationError> {
        Self::startup_selection_for(&crate::filters::Context::new(firmware))
    }

    fn settings_plan_for(
        &self,
        normal: &Envelope,
        kernel: &Envelope,
        restore: bool,
    ) -> Result<crate::settings::update::Plan, PreparationError> {
        let info = normal.info();
        let context = crate::filters::Context::new(crate::compatibility::Firmware {
            hardware: &info.hardware_version,
            normal: &normal.image,
            kernel: Some(&kernel.image),
        });
        let actions = crate::filters::parameter_actions(&context)
            .map_err(PreparationError::PhaseCorrection)?;
        // Startup adaptation belongs to the verified correction plan, which
        // compares both images; a target observation alone never writes a word.
        if !actions.is_empty() {
            return Err(PreparationError::PhaseCorrection(
                crate::compatibility::Error::Unsupported,
            ));
        }
        Ok(crate::settings::update::Plan::from_startup(None, restore))
    }
    #[cfg(test)]
    fn startup_setting_for(
        &self,
        normal: &[u8],
    ) -> Result<Option<crate::startup::Setting>, PreparationError> {
        let installed = self
            .installed_normal
            .as_ref()
            .ok_or(PreparationError::UnresolvedStartup)?;
        self.startup_plan_for(crate::compatibility::Firmware {
            hardware: &installed.info().hardware_version,
            normal,
            kernel: self
                .installed_kernel
                .as_ref()
                .map(|kernel| kernel.image.as_slice()),
        })
        .map(|plan| plan.map(|plan| plan.setting()))
    }
    /// Prepare a Normal-only update using captured installed Kernel evidence.
    pub fn prepare_normal(&self, target: &[u8]) -> Result<PreparedNormal, PreparationError> {
        self.prepare_normal_inner(target, true)
    }

    /// Prepare Normal-only with a deliberate caller override of family comparison.
    ///
    /// Component compatibility, integrity and installed-Kernel authentication
    /// remain mandatory. Persistent banks must remain compatible.
    pub fn prepare_normal_without_family_check(
        &self,
        target: &[u8],
    ) -> Result<PreparedNormal, PreparationError> {
        self.prepare_normal_inner(target, false)
    }

    fn prepare_normal_inner(
        &self,
        bytes: &[u8],
        check_family: bool,
    ) -> Result<PreparedNormal, PreparationError> {
        let kernel = self
            .installed_kernel
            .as_ref()
            .ok_or(PreparationError::MissingInstalledKernel)?;
        let kernel_bytes = kernel
            .repack(&kernel.image)
            .ok_or(PreparationError::InstalledKernelRepresentation)?;
        let mut pair = Update::load(&kernel_bytes, bytes).map_err(PreparationError::Target)?;
        let correction = self.prepare_corrections(pair.normal(), pair.kernel(), check_family)?;
        if let Some(corrected) = &correction {
            let normal = self.encode_correction(pair.normal(), corrected, kernel)?;
            let prepared =
                Update::load(&kernel_bytes, &normal).map_err(PreparationError::Target)?;
            pair = prepared;
            if check_family {
                self.check_family_with_kernel(pair.normal(), pair.kernel())
                    .map_err(PreparationError::Compatibility)?;
            }
        }
        let startup_checks = self.prepare_startup(&pair.normal().image, Some(&kernel.image))?;
        let settings = self
            .settings_plan_for(pair.normal(), kernel, false)?
            .with_startup_checks(startup_checks)
            .with_correction(correction);
        let (normal, normal_bytes) = pair.into_normal();
        Ok(PreparedNormal {
            stage: PreparedStage {
                #[cfg(feature = "drive")]
                normal_region: normal_region(kernel, &normal.image),
                receiver: self.clone(),
                kernel: None,
                kernel_bytes: None,
                normal,
                normal_bytes,
                settings,
                bridge: None,
            },
        })
    }

    /// Prepare both passes of a complete update before issuing any commands.
    ///
    /// Requires captured installed Kernel evidence from [`Self::from_installed`].
    /// Family compatibility is checked first. Unknown marker handling never
    /// authorizes either an unmodified or a temporarily patched Kernel write.
    pub fn prepare(&self, target: Update) -> Result<PreparedUpdate, PreparationError> {
        self.prepare_inner(target, true)
    }

    /// Prepare with an explicit caller override of the hardware family gate.
    ///
    /// Intended for applications exposing a deliberate force option. This may
    /// target incompatible hardware. Persistent banks must remain compatible;
    /// no bank format conversion exists. Target integrity, marker policy and
    /// restoration still apply.
    pub fn prepare_without_family_check(
        &self,
        target: Update,
    ) -> Result<PreparedUpdate, PreparationError> {
        self.prepare_inner(target, false)
    }

    fn prepare_inner(
        &self,
        mut target: Update,
        check_family: bool,
    ) -> Result<PreparedUpdate, PreparationError> {
        let correction =
            self.prepare_corrections(target.normal(), target.kernel(), check_family)?;
        if self.kernel_policy.is_none() {
            return Err(PreparationError::UnknownInstalledKernel);
        }
        if let Some(corrected) = &correction {
            let normal = self.encode_correction(target.normal(), corrected, target.kernel())?;
            let kernel = target
                .kernel()
                .repack(&target.kernel().image)
                .ok_or(PreparationError::InstalledKernelRepresentation)?;
            let prepared = Update::load(&kernel, &normal).map_err(PreparationError::Target)?;
            target = prepared;
        }
        if check_family {
            self.check_family_with_kernel(target.normal(), target.kernel())
                .map_err(PreparationError::Compatibility)?;
        }
        // The family override is also the explicit crossflash startup policy;
        // persistent banks still require identical storage contracts.
        let startup_policy = if check_family {
            crate::startup::checks::Policy::CompatibleBanks
        } else {
            crate::startup::checks::Policy::ExplicitCrossflash
        };
        let startup_checks = self.prepare_startup_with_policy(
            &target.normal().image,
            Some(&target.kernel().image),
            startup_policy,
        )?;
        let installed = self
            .installed_kernel
            .as_ref()
            .ok_or(PreparationError::MissingInstalledKernel)?;
        use crate::compatibility::{plan_kernel, KernelPlanningError, KernelStep};
        let transition =
            plan_kernel(&installed.image, &target.kernel().image).map_err(|error| match error {
                KernelPlanningError::UnknownInstalledPolicy => {
                    PreparationError::UnknownInstalledKernel
                }
                KernelPlanningError::Handoff(error) => PreparationError::KernelHandoff(error),
                KernelPlanningError::RejectedBridgeMarker => PreparationError::RejectedMarker,
                KernelPlanningError::UnsupportedRestoration => {
                    PreparationError::UnsupportedFinalStage
                }
            })?;
        if !transition.matches_components(&installed.image, &target.kernel().image) {
            return Err(PreparationError::PatchedRepresentation);
        }
        let kernel_steps = transition.steps().to_vec();
        let settings = self
            .settings_plan_for(
                target.normal(),
                target.kernel(),
                transition.restores_marker(),
            )?
            .with_startup_checks(startup_checks)
            .with_correction(correction);
        let mut stages = Vec::new();
        let mut receiver = self.clone();
        for step in transition.into_steps() {
            match step {
                KernelStep::Handoff { .. } => {
                    let bridge = super::handoff_bridge::prepare(self, target.kernel())?;
                    // This stage retains the source Normal's startup decision and
                    // carries no correction. The executor checks the final
                    // correction's read-only prerequisites across all stages
                    // before installing any bridge firmware, and refuses a final
                    // correction word write here: it could only run after the
                    // bridge transfer.
                    let bridge_settings = self
                        .settings_plan_for(bridge.normal(), bridge.kernel(), false)?
                        .with_startup_checks(self.prepare_startup_with_policy(
                            &bridge.normal().image,
                            Some(&bridge.kernel().image),
                            startup_policy,
                        )?);
                    stages.push(PreparedStage::pair(
                        receiver.clone(),
                        &bridge,
                        bridge_settings,
                        Some(BridgeKind::KernelHandoff),
                    )?);
                    receiver.installed_kernel = Some(Arc::new(bridge.kernel().clone()));
                    receiver.startup = crate::startup::checks::Checks::discover(
                        &bridge.normal().image,
                        Some(&bridge.kernel().image),
                    );
                }
                KernelStep::ReceiverMarker { from, to } => {
                    if target.kernel().image.get(KERNEL_MARKER_OFFSET).copied() != Some(from) {
                        return Err(PreparationError::PatchedRepresentation);
                    }
                    let image = downgrade_patch(&target.kernel().image)
                        .map_err(|_| PreparationError::PatchedRepresentation)?
                        .0;
                    if image.get(KERNEL_MARKER_OFFSET).copied() != Some(to) {
                        return Err(PreparationError::PatchedRepresentation);
                    }
                    let kernel = target
                        .kernel()
                        .repack(&image)
                        .ok_or(PreparationError::PatchedRepresentation)?;
                    let normal = target
                        .normal()
                        .repack(&target.normal().image)
                        .ok_or(PreparationError::PatchedRepresentation)?;
                    let intermediate =
                        Update::load(&kernel, &normal).map_err(PreparationError::Target)?;
                    stages.push(PreparedStage::pair(
                        receiver,
                        &intermediate,
                        settings.clone(),
                        Some(BridgeKind::ReceiverMarker),
                    )?);
                    receiver = Receiver::from_installed(&intermediate)
                        .map_err(PreparationError::FinalStageEntry)?;
                }
                KernelStep::Target => {
                    stages.push(PreparedStage::pair(receiver, &target, settings, None)?);
                    break;
                }
            }
        }
        if stages.len() != kernel_steps.len()
            || stages.last().and_then(|stage| stage.kernel_image())
                != Some(target.kernel().image.as_slice())
        {
            return Err(PreparationError::PatchedRepresentation);
        }
        Ok(PreparedUpdate {
            stages,
            target,
            kernel_steps,
        })
    }
}

#[cfg(test)]
#[path = "preparation_tests.rs"]
pub(super) mod tests;

#[cfg(feature = "drive")]
pub(super) fn normal_region(
    kernel: &Envelope,
    normal: &[u8],
) -> Option<crate::envelope::NormalRegion> {
    let layout = kernel.normal_layout().ok()?;
    layout.validate(normal).ok()?;
    layout.resolve(normal).ok()
}
