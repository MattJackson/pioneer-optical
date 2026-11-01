//! Immutable component preparation; no transport or device I/O.

use super::{BridgeKind, Error, PreparedNormal, PreparedStage, PreparedUpdate, Receiver};
use crate::envelope::{downgrade_patch, Envelope, Update, UpdateError, KERNEL_MARKER_OFFSET};
use crate::image::{kernel_marker_policy, KernelMarkerPolicy};

/// A receiver could not prepare all required update passes.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PreparationError {
    /// More than one startup comparison prevents selecting a target value.
    AmbiguousStartup,
    /// Required configuration is unresolved or has no validated conversion.
    Settings(crate::settings::update::Error),
    /// A compiled-in settings adaptation failed its exact firmware guards.
    Adaptation(crate::settings::adaptation::Error),
    /// Target requires a setting but the installed write surface is unknown.
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
}

impl core::fmt::Display for PreparationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Settings(error) => error.fmt(f),
            Self::Adaptation(error) => error.fmt(f),
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
        }
    }
}
impl std::error::Error for PreparationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Settings(error) => Some(error),
            Self::Adaptation(error) => Some(error),
            Self::KernelHandoff(error) => Some(error),
            Self::Target(error) => Some(error),
            Self::Compatibility(error) | Self::FinalStageEntry(error) => Some(error),
            _ => None,
        }
    }
}

impl Receiver {
    /// Retained for source compatibility. Certified conversions are selected
    /// by the firmware pair; live setting prerequisites are checked at execution.
    pub fn with_original_parameters(self, _parameters: &[u8]) -> Self {
        self
    }

    fn adapt_normal(
        &self,
        normal: &Envelope,
    ) -> Result<Option<crate::settings::adaptation::Adapted>, PreparationError> {
        #[cfg(test)]
        let result = if let Some(profiles) = &self.adaptation_profiles {
            crate::settings::adaptation::prepare_documents(
                profiles,
                &self.settings_contract,
                &normal.image,
                &normal.info().model,
            )
        } else {
            crate::settings::adaptation::prepare(
                &self.settings_contract,
                &normal.image,
                &normal.info().model,
            )
        };
        #[cfg(not(test))]
        let result = crate::settings::adaptation::prepare(
            &self.settings_contract,
            &normal.image,
            &normal.info().model,
        );
        let adapted = result.map_err(PreparationError::Adaptation)?;
        // A stock-return profile authorizes only its exact OEM image and
        // original factory mechanism; native reverse routes are not inferred.
        if let Some(a) = &adapted {
            self.settings_contract
                .check_resolving(
                    &crate::settings::update::Contract::discover(&a.image),
                    Some(&a.resolves_issue),
                )
                .map_err(PreparationError::Settings)?;
        } else {
            self.check_settings(&normal.image)?;
        }
        Ok(adapted)
    }

    fn encode_adapted(
        &self,
        normal: &Envelope,
        adapted: &crate::settings::adaptation::Adapted,
        kernel: &Envelope,
    ) -> Result<Vec<u8>, PreparationError> {
        use crate::envelope::{
            builder::{
                normal_authentication_from_kernel, normal_authentication_valid,
                NormalAuthentication,
            },
            signature::SigningKey,
        };
        let failure =
            || PreparationError::Adaptation(crate::settings::adaptation::Error::Representation);
        let mut bytes = normal.repack(&adapted.image).ok_or_else(failure)?;
        if !adapted.stock_return() {
            let signer = SigningKey::random().map_err(|_| failure())?;
            match normal_authentication_from_kernel(&kernel.image) {
                Some(NormalAuthentication::KeyAndCiphertext) => signer.sign_normal(&mut bytes),
                Some(NormalAuthentication::CiphertextOnly) => {
                    signer.sign_normal_ciphertext_only(&mut bytes)
                }
                _ => return Err(failure()),
            }
            .map_err(|_| failure())?;
        }
        if !normal_authentication_valid(&bytes, &kernel.image) {
            return Err(failure());
        }
        let decoded = Envelope::load_with_kernel(&bytes, kernel).map_err(|_| failure())?;
        if decoded.image != adapted.image {
            return Err(failure());
        }
        Ok(bytes)
    }

    /// Independent required-settings gate; hardware overrides never waive it.
    pub fn check_settings(&self, normal: &[u8]) -> Result<(), PreparationError> {
        self.settings_contract
            .check(&crate::settings::update::Contract::discover(normal))
            .map_err(PreparationError::Settings)
    }
    fn startup_setting_for(
        &self,
        normal: &[u8],
    ) -> Result<Option<crate::startup::Setting>, PreparationError> {
        crate::startup::setting(normal)
            .map(Some)
            .map_err(|_| PreparationError::AmbiguousStartup)
    }
    /// Prepare a Normal-only update using captured installed Kernel evidence.
    pub fn prepare_normal(&self, target: &[u8]) -> Result<PreparedNormal, PreparationError> {
        self.prepare_normal_inner(target, true)
    }

    /// Prepare Normal-only with a deliberate caller override of family comparison.
    ///
    /// Component compatibility, integrity and installed-Kernel authentication
    /// remain mandatory. This may target incompatible hardware.
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
        if check_family {
            self.check_family(pair.normal())
                .map_err(PreparationError::Compatibility)?;
        }
        let adaptation = self.adapt_normal(pair.normal())?;
        if let Some(adapted) = &adaptation {
            let normal = self.encode_adapted(pair.normal(), adapted, kernel)?;
            pair = Update::load(&kernel_bytes, &normal).map_err(PreparationError::Target)?;
            if check_family {
                self.check_family(pair.normal())
                    .map_err(PreparationError::Compatibility)?;
            }
        }
        let settings = crate::settings::update::Plan::target(
            self.startup_setting_for(&pair.normal().image)?,
            false,
        )
        .with_adaptation(adaptation);
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
        self.check_family(target.normal())
            .map_err(PreparationError::Compatibility)?;
        self.prepare_without_family_check(target)
    }

    /// Prepare with an explicit caller override of the hardware family gate.
    ///
    /// Intended for applications exposing a deliberate force option. This may
    /// target incompatible hardware; it waives only family comparison. Target
    /// integrity, installed marker policy and restoration checks still apply.
    pub fn prepare_without_family_check(
        &self,
        mut target: Update,
    ) -> Result<PreparedUpdate, PreparationError> {
        let policy = self
            .kernel_policy
            .ok_or(PreparationError::UnknownInstalledKernel)?;
        let adaptation = self.adapt_normal(target.normal())?;
        if let Some(adapted) = &adaptation {
            let normal = self.encode_adapted(target.normal(), adapted, target.kernel())?;
            let kernel = target
                .kernel()
                .repack(&target.kernel().image)
                .ok_or(PreparationError::InstalledKernelRepresentation)?;
            let family = target.family();
            target = Update::load(&kernel, &normal).map_err(PreparationError::Target)?;
            if target.family() != family {
                return Err(PreparationError::Adaptation(
                    crate::settings::adaptation::Error::Guard,
                ));
            }
        }
        let installed = self
            .installed_kernel
            .as_ref()
            .ok_or(PreparationError::MissingInstalledKernel)?;
        let mut stages = Vec::new();
        let mut receiver = self.clone();
        match crate::image::check_kernel_handoff(&installed.image, &target.kernel().image) {
            Ok(()) => {}
            Err(crate::image::KernelHandoffError::Mismatch { .. }) => {
                // A source bridge is a real intermediate, with its own Normal
                // and receiver. It never borrows the final target's settings.
                let bridge = super::handoff_bridge::prepare(self, target.kernel())?;
                let settings = crate::settings::update::Plan::target(
                    self.startup_setting_for(&bridge.normal().image)?,
                    false,
                );
                stages.push(PreparedStage::pair(
                    receiver.clone(),
                    &bridge,
                    settings,
                    Some(BridgeKind::KernelHandoff),
                )?);
                receiver.installed_kernel = Some(bridge.kernel().clone());
            }
            Err(error) => return Err(PreparationError::KernelHandoff(error)),
        }
        let patch = needs_patch(
            policy,
            target.kernel().image.get(KERNEL_MARKER_OFFSET).copied(),
        );
        let settings = crate::settings::update::Plan::target(
            receiver.startup_setting_for(&target.normal().image)?,
            patch,
        )
        .with_adaptation(adaptation);
        if patch {
            if kernel_marker_policy(&target.kernel().image)
                != Some(KernelMarkerPolicy::NoMarkerCheck)
            {
                return Err(PreparationError::UnsupportedFinalStage);
            }
            let image = downgrade_patch(&target.kernel().image)
                .map_err(|_| PreparationError::PatchedRepresentation)?
                .0;
            let kernel = target
                .kernel()
                .repack(&image)
                .ok_or(PreparationError::PatchedRepresentation)?;
            let normal = target
                .normal()
                .repack(&target.normal().image)
                .ok_or(PreparationError::PatchedRepresentation)?;
            let intermediate = Update::load(&kernel, &normal).map_err(PreparationError::Target)?;
            stages.push(PreparedStage::pair(
                receiver,
                &intermediate,
                settings.clone(),
                Some(BridgeKind::ReceiverMarker),
            )?);
            receiver = Receiver::from_installed(&intermediate)
                .map_err(PreparationError::FinalStageEntry)?;
        }
        stages.push(PreparedStage::pair(receiver, &target, settings, None)?);
        Ok(PreparedUpdate { stages, target })
    }
}

fn needs_patch(policy: KernelMarkerPolicy, marker: Option<u8>) -> bool {
    matches!(policy, KernelMarkerPolicy::RejectZeroAndErased) && matches!(marker, Some(0 | 0xff))
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
