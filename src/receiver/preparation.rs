//! Immutable component preparation; no transport or device I/O.

use super::{Control, Error, Receiver};
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
    /// The target Kernel cannot be proven to accept its pristine restoration.
    UnsupportedRestoration,
    /// The target Normal's entry requirements could not be established.
    RestorationEntry(Error),
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
            Self::UnsupportedRestoration => f.write_str(
                "target Kernel does not establish a supported pristine restoration path",
            ),
            Self::RestorationEntry(error) => write!(f, "pristine restoration entry: {error}"),
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
            Self::KernelHandoff(error) => Some(error),
            Self::Target(error) => Some(error),
            Self::Compatibility(error) | Self::RestorationEntry(error) => Some(error),
            _ => None,
        }
    }
}

/// A validated Normal-only transfer for the captured installed Kernel.
///
/// Preparation does not issue commands. No Kernel transfer or restoration pass
/// is selected; the resident Kernel remains the receiving implementation.
#[derive(Debug)]
pub struct PreparedNormal {
    #[cfg(feature = "drive")]
    pub(super) control: Control,
    pub(super) normal: Envelope,
    transfer: Vec<u8>,
    pub(super) settings: crate::settings::update::Plan,
    pub(super) installed_kernel: Option<Envelope>,
    #[cfg(feature = "drive")]
    pub(super) initial_class: Option<crate::DriveClass>,
    #[cfg(feature = "drive")]
    pub(super) normal_region: Option<crate::envelope::NormalRegion>,
}

impl PreparedNormal {
    /// Advertised target identity, for presentation rather than startup gating.
    pub fn target_info(&self) -> &crate::envelope::EnvelopeInfo {
        self.normal.info()
    }

    /// Target-derived startup migration to verify on the live drive before transfer.
    pub fn startup_setting(&self) -> Option<crate::startup::Setting> {
        self.settings.startup_setting()
    }
    /// Typed settings prepared alongside the OEM firmware.
    pub fn settings(&self) -> &crate::settings::update::Plan {
        &self.settings
    }
    /// Normal bytes validated under the installed Kernel's authentication rules.
    pub fn normal_transfer(&self) -> &[u8] {
        &self.transfer
    }

    /// Exact decoded target Normal, available for receiver-specific verification.
    pub fn normal_image(&self) -> &[u8] {
        &self.normal.image
    }
}

/// Complete-pair component bytes and mandatory Kernel readback expectations.
///
/// Preparation performs no device I/O. With the `drive` feature, `flash` binds
/// live descriptors, executes the protocol and verifies each Kernel before
/// proceeding. The complete executor also verifies target startup and records
/// whether Normal readback was available. Success requires the final Kernel
/// readback to match the pristine target.
#[derive(Debug)]
pub struct PreparedUpdate {
    #[cfg(feature = "drive")]
    pub(super) control: Control,
    #[cfg(feature = "drive")]
    pub(super) initial_receive: Option<super::transport::KernelReceive>,
    #[cfg(feature = "drive")]
    pub(super) target_class: Option<crate::DriveClass>,
    pub(super) target: Update,
    restoration: Option<Restoration>,
    pub(super) settings: crate::settings::update::Plan,
    pub(super) installed_kernel: Option<Envelope>,
    #[cfg(feature = "drive")]
    pub(super) initial_class: Option<crate::DriveClass>,
    #[cfg(feature = "drive")]
    pub(super) normal_region: Option<crate::envelope::NormalRegion>,
}

#[derive(Debug)]
struct Restoration {
    first_kernel: Vec<u8>,
    first_image: Vec<u8>,
    receiver: Receiver,
}

impl PreparedUpdate {
    /// Advertised target identity, for presentation rather than startup gating.
    pub fn target_info(&self) -> &crate::envelope::EnvelopeInfo {
        self.target.normal().info()
    }

    /// Target-derived startup migration, shared by both prepared passes.
    pub fn startup_setting(&self) -> Option<crate::startup::Setting> {
        self.settings.startup_setting()
    }
    /// Typed settings prepared alongside the OEM firmware.
    pub fn settings(&self) -> &crate::settings::update::Plan {
        &self.settings
    }
    /// Kernel transfer bytes for the first update pass.
    pub fn kernel_transfer(&self) -> &[u8] {
        self.restoration.as_ref().map_or_else(
            || self.target.kernel_transfer(),
            |restore| restore.first_kernel.as_slice(),
        )
    }
    /// Normal transfer bytes, shared by both passes when restoration is needed.
    pub fn normal_transfer(&self) -> &[u8] {
        self.target.normal_transfer()
    }
    /// Exact decoded Kernel required after the first pass.
    pub fn first_kernel_image(&self) -> &[u8] {
        self.restoration.as_ref().map_or_else(
            || self.target.kernel().image.as_slice(),
            |restore| restore.first_image.as_slice(),
        )
    }
    /// Pristine Kernel transfer bytes for the mandatory second pass, if any.
    pub fn restoration_kernel_transfer(&self) -> Option<&[u8]> {
        self.restoration
            .as_ref()
            .map(|_| self.target.kernel_transfer())
    }
    /// Receiver whose live descriptor must be checked before the second pass.
    pub fn restoration_receiver(&self) -> Option<&Receiver> {
        self.restoration.as_ref().map(|restore| &restore.receiver)
    }
    /// Exact decoded Kernel required before reporting final success.
    pub fn final_kernel_image(&self) -> &[u8] {
        &self.target.kernel().image
    }
}

impl Receiver {
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
        target: &[u8],
        check_family: bool,
    ) -> Result<PreparedNormal, PreparationError> {
        let kernel = self
            .installed_kernel
            .as_ref()
            .ok_or(PreparationError::MissingInstalledKernel)?;
        let mut prepared = self.codec.prepare_normal(kernel, target, self.control())?;
        if check_family {
            self.check_family(&prepared.normal)
                .map_err(PreparationError::Compatibility)?;
        }
        self.check_settings(&prepared.normal.image)?;
        prepared.settings = crate::settings::update::Plan::target(
            self.startup_setting_for(&prepared.normal.image)?,
            false,
        );
        prepared.installed_kernel = Some(kernel.clone());
        #[cfg(feature = "drive")]
        {
            // Normal-only codec preparation does not require Kernel marker
            // semantics. A complete live execution still requires a recognized
            // entry dialect before any parameter or firmware mutation.
            prepared.initial_class = kernel.update_dialect();
            prepared.normal_region = normal_region(kernel, &prepared.normal.image);
        }
        Ok(prepared)
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
        target: Update,
    ) -> Result<PreparedUpdate, PreparationError> {
        let policy = self
            .kernel_policy
            .ok_or(PreparationError::UnknownInstalledKernel)?;
        let mut prepared = self.codec.prepare(policy, target, self.control())?;
        self.check_settings(&prepared.target.normal().image)?;
        prepared.settings = crate::settings::update::Plan::target(
            self.startup_setting_for(&prepared.target.normal().image)?,
            prepared.restoration.is_some(),
        );
        let installed = self
            .installed_kernel
            .as_ref()
            .ok_or(PreparationError::UnknownInstalledKernel)?;
        prepared.installed_kernel = Some(installed.clone());
        #[cfg(feature = "drive")]
        {
            prepared.initial_receive = Some(super::transport::detect(&installed.image));
            prepared.initial_class = Some(
                installed
                    .update_dialect()
                    .ok_or(PreparationError::UnsupportedDialect)?,
            );
            prepared.target_class = prepared.target.kernel().update_dialect();
            prepared.normal_region =
                normal_region(prepared.target.kernel(), &prepared.target.normal().image);
        }
        crate::image::check_kernel_handoff(&installed.image, prepared.first_kernel_image())
            .map_err(PreparationError::KernelHandoff)?;
        if prepared.restoration.is_some() {
            crate::image::check_kernel_handoff(
                prepared.first_kernel_image(),
                prepared.final_kernel_image(),
            )
            .map_err(PreparationError::KernelHandoff)?;
        }
        #[cfg(feature = "drive")]
        {
            let mut storage = [crate::drive::Segment::PLACEHOLDER; 3];
            super::transport::plan(
                Some(prepared.kernel_transfer()),
                prepared.normal_transfer(),
                prepared.initial_receive.expect("prepared receive layout"),
                &mut storage,
            )
            .map_err(|_| PreparationError::UnsupportedTransport)?;
            if let Some(kernel) = prepared.restoration_kernel_transfer() {
                prepared
                    .target_class
                    .ok_or(PreparationError::UnsupportedDialect)?;
                let mut storage = [crate::drive::Segment::PLACEHOLDER; 3];
                super::transport::plan(
                    Some(kernel),
                    prepared.normal_transfer(),
                    super::transport::detect(prepared.first_kernel_image()),
                    &mut storage,
                )
                .map_err(|_| PreparationError::UnsupportedTransport)?;
            }
        }
        Ok(prepared)
    }
}

pub(super) fn prepare_normal_oem(
    kernel: &Envelope,
    target: &[u8],
    _control: Control,
) -> Result<PreparedNormal, PreparationError> {
    let bytes = kernel
        .repack(&kernel.image)
        .ok_or(PreparationError::InstalledKernelRepresentation)?;
    let prepared = Update::load(&bytes, target).map_err(PreparationError::Target)?;
    let (normal, transfer) = prepared.into_normal();
    Ok(PreparedNormal {
        #[cfg(feature = "drive")]
        control: _control,
        normal,
        transfer,
        settings: crate::settings::update::Plan::default(),
        installed_kernel: None,
        #[cfg(feature = "drive")]
        initial_class: None,
        #[cfg(feature = "drive")]
        normal_region: None,
    })
}

pub(super) fn prepare_oem(
    policy: KernelMarkerPolicy,
    target: Update,
    _control: Control,
) -> Result<PreparedUpdate, PreparationError> {
    let patch = needs_patch(
        policy,
        target.kernel().image.get(KERNEL_MARKER_OFFSET).copied(),
    );
    let restoration = if patch {
        if kernel_marker_policy(&target.kernel().image) != Some(KernelMarkerPolicy::NoMarkerCheck) {
            return Err(PreparationError::UnsupportedRestoration);
        }
        let receiver =
            Receiver::from_installed(&target).map_err(PreparationError::RestorationEntry)?;
        let mut kernel = target.kernel().clone();
        kernel.image = downgrade_patch(&kernel.image)
            .map_err(|_| PreparationError::PatchedRepresentation)?
            .0;
        let transfer = kernel
            .kernel_transfer_image()
            .ok_or(PreparationError::PatchedRepresentation)?;
        Some(Restoration {
            first_kernel: transfer,
            first_image: kernel.image,
            receiver,
        })
    } else {
        None
    };
    Ok(PreparedUpdate {
        #[cfg(feature = "drive")]
        control: _control,
        #[cfg(feature = "drive")]
        initial_receive: None,
        #[cfg(feature = "drive")]
        target_class: None,
        target,
        restoration,
        settings: crate::settings::update::Plan::default(),
        installed_kernel: None,
        #[cfg(feature = "drive")]
        initial_class: None,
        #[cfg(feature = "drive")]
        normal_region: None,
    })
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
