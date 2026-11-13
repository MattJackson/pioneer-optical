//! Firmware-derived receiver requirements.
//!
//! Detection performs no device I/O. Entry control alone does not establish
//! hardware compatibility, component acceptance, or a complete flash plan.

use alloc::sync::Arc;

use crate::envelope::Envelope;
use crate::filters::family::Family;
use crate::image::{receiver_control_with_kernel, ReceiverControl};
use crate::{cdb, ComponentKind};

pub mod normal_transfer;
mod preparation;
pub use preparation::PreparationError;
mod stages;
pub use stages::{BridgeKind, PreparedNormal, PreparedStage, PreparedUpdate};
#[cfg(feature = "drive")]
mod execution;
#[cfg(feature = "drive")]
mod execution_safe;
mod handoff_bridge {
    //! Source-Kernel bridge, derived from the two recognized handoff contracts.
    use super::{PreparationError, Receiver};
    use crate::envelope::{Envelope, Update, KERNEL_CHECKSUM_WORD_OFFSET};
    use crate::image::{kernel_handoff_contract, kernel_startup_entry, KernelHandoffError};

    pub(super) fn prepare(receiver: &Receiver, target: &Envelope) -> Result<Update, PreparationError> {
        let source = receiver
            .installed_kernel()
            .ok_or(PreparationError::MissingInstalledKernel)?;
        let normal = receiver
            .installed_normal
            .as_ref()
            .ok_or(PreparationError::PatchedRepresentation)?;
        let refused = |error| PreparationError::KernelHandoff(error);
        let contract = kernel_handoff_contract(&source.image)
            .ok_or_else(|| refused(KernelHandoffError::UnknownInstalled))?;
        let startup = kernel_startup_entry(&source.image)
            .ok_or_else(|| refused(KernelHandoffError::UnknownInstalled))?;
        let destination = kernel_startup_entry(&target.image)
            .ok_or_else(|| refused(KernelHandoffError::UnknownTarget))?;
        // The installed updater must be able to start the bridge, whose startup
        // code stays untouched. Already-adapted or inconsistent sources refuse.
        if contract.entry != startup || startup == destination {
            return Err(refused(KernelHandoffError::Mismatch {
                installed: contract.entry,
                target: destination,
            }));
        }
        let mut image = source.image.clone();
        let sum = |bytes: &[u8]| {
            bytes.chunks_exact(4).fold(0u32, |sum, word| {
                sum.wrapping_add(u32::from_be_bytes(word.try_into().expect("word")))
            })
        };
        if image.len() % 4 != 0 || sum(&image) != 0 {
            return Err(PreparationError::PatchedRepresentation);
        }
        for at in &contract.operands {
            // No programmer operand may overlap the fixed Kernel checksum field.
            if *at < KERNEL_CHECKSUM_WORD_OFFSET + 4 && at + 3 > KERNEL_CHECKSUM_WORD_OFFSET {
                return Err(PreparationError::PatchedRepresentation);
            }
            image[*at..*at + 3].copy_from_slice(&destination.to_be_bytes()[1..]);
        }
        let checksum = KERNEL_CHECKSUM_WORD_OFFSET;
        let before = u32::from_be_bytes(image[checksum..checksum + 4].try_into().expect("checksum"));
        let adjusted = before.wrapping_sub(sum(&image));
        image[checksum..checksum + 4].copy_from_slice(&adjusted.to_be_bytes());
        let patched = kernel_handoff_contract(&image).ok_or(PreparationError::PatchedRepresentation)?;
        if patched.entry != destination
            || patched.operands != contract.operands
            || kernel_startup_entry(&image) != Some(startup)
            || sum(&image) != 0
        {
            return Err(PreparationError::PatchedRepresentation);
        }
        let kernel = source
            .repack(&image)
            .ok_or(PreparationError::PatchedRepresentation)?;
        let mut normal_bytes = normal
            .repack(&normal.image)
            .ok_or(PreparationError::PatchedRepresentation)?;
        let mut loaded = Update::load(&kernel, &normal_bytes);
        // A live capture may carry an empty signature. Authenticate an owned
        // transfer copy only after every other Update gate accepted that pair.
        // A nonzero invalid signature is never repaired or treated as unsigned.
        if matches!(loaded, Err(crate::envelope::UpdateError::Authentication))
            && normal_bytes
                .get(0x170..0x1c0)
                .is_some_and(|signature| signature.iter().all(|byte| *byte == 0))
        {
            use crate::envelope::{
                builder::{normal_authentication_from_kernel, NormalAuthentication},
                signature::SigningKey,
            };
            let signer = SigningKey::random().map_err(signing_failure)?;
            match normal_authentication_from_kernel(&image) {
                Some(NormalAuthentication::KeyAndCiphertext) => signer.sign_normal(&mut normal_bytes),
                Some(NormalAuthentication::CiphertextOnly) => {
                    signer.sign_normal_ciphertext_only(&mut normal_bytes)
                }
                _ => return Err(PreparationError::PatchedRepresentation),
            }
            .map_err(signing_failure)?;
            loaded = Update::load(&kernel, &normal_bytes);
        }
        let bridge = loaded.map_err(PreparationError::Target)?;
        if bridge.kernel().image != image || bridge.normal().image != normal.image {
            return Err(PreparationError::PatchedRepresentation);
        }
        Ok(bridge)
    }

    /// Keep the signing cause instead of reporting a bare representation failure.
    fn signing_failure(error: crate::envelope::Error) -> PreparationError {
        PreparationError::PatchedSigning(error)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::error_codes::CodedError;

        #[test]
        fn signing_failure_preserves_the_envelope_cause() {
            use crate::envelope::Error as E;
            for cause in [E::EntropyUnavailable, E::Randomness, E::SelfVerification] {
                let error = signing_failure(cause);
                assert_ne!(error, PreparationError::PatchedRepresentation);
                let source = std::error::Error::source(&error)
                    .and_then(|s| s.downcast_ref::<E>())
                    .copied();
                assert_eq!(source, Some(cause));
                // Pre-write refusal: code and host category are unchanged.
                assert_eq!(error.code(), "pioneer.prepare.patched_representation");
                assert_eq!(error.kind(), crate::operation::IssueKind::InvalidFirmware);
            }
        }
    }
}
#[cfg(feature = "drive")]
pub use execution_safe::{
    ExecutionError, ExecutionMode, ExecutionRuntime, FlashOutcome, PlanError, PlanReason,
};
#[cfg(feature = "drive")]
pub mod transport;
#[cfg(feature = "drive")]
pub use execution::{FlashError, FlashRuntime, FlashStage, FlashTransport};

type Control = [u8; cdb::CONTROL_LEN as usize];

/// Bytes compared by the resident Normal's update-entry handler.
pub const DESCRIPTOR_LEN: usize = 16;
const KEY_END: usize = DESCRIPTOR_LEN + 4;

/// Why receiver requirements could not be established.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// The supplied envelope is not a Normal component.
    Component {
        /// Component actually supplied.
        actual: ComponentKind,
    },
    /// Kernel evidence carries another component role.
    KernelComponent {
        /// Component actually supplied as the installed Kernel.
        actual: ComponentKind,
    },
    /// Captured components disagree on their declared hardware or Kernel tag.
    InstalledPairMismatch,
    /// The resident image has no valid entry descriptor.
    InvalidDescriptor,
    /// No unique supported entry handler was recovered from the image.
    Unsupported,
    /// The live descriptor differs from the captured installed firmware.
    DescriptorMismatch,
    /// The installed image does not establish a hardware family.
    UnknownInstalledFamily,
    /// The target image does not establish a hardware family.
    UnknownTargetFamily,
    /// The installed and target images describe different hardware families.
    FamilyMismatch {
        /// Family recovered from installed firmware.
        installed: Family,
        /// Family recovered from the target firmware.
        target: Family,
    },
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Component { actual } => write!(
                f,
                "receiver detection requires a Normal component, got {actual:?}"
            ),
            Self::KernelComponent { actual } => write!(f, "installed Kernel evidence requires a Kernel component, got {actual}"),
            Self::InstalledPairMismatch => f.write_str("installed Kernel and Normal hardware or Kernel tags do not match"),
            Self::InvalidDescriptor => f.write_str("invalid resident Pioneer control descriptor"),
            Self::Unsupported => f.write_str("receiver entry control is unsupported or ambiguous"),
            Self::UnknownInstalledFamily => f.write_str("could not determine the installed firmware family"),
            Self::UnknownTargetFamily => f.write_str("could not determine the target firmware family"),
            Self::FamilyMismatch { installed, target } => write!(f, "family mismatch: installed firmware is family {installed}, target is family {target}"),
            Self::DescriptorMismatch => {
                f.write_str("installed firmware does not match the live receiver descriptor")
            }
        }
    }
}
impl std::error::Error for Error {}

/// Firmware-derived update requirements bound to the installed receiver.
///
/// Construct from the captured installed Normal, decoded with its Kernel when
/// needed. A target envelope must not be substituted for installed evidence.
/// Normal-only detection establishes entry requirements and the hardware family
/// gate. [`Self::from_installed`] also enables complete-pair preparation using
/// the installed Kernel's code. With the `drive` feature, execute the prepared
/// operation to apply migrations, sequence transfers and verify completion.
/// Callers own backup, consent and exclusive access; preparation performs no I/O.
#[derive(Clone, Debug)]
pub struct Receiver {
    descriptor: [u8; DESCRIPTOR_LEN],
    policy: ReceiverControl,
    family: Option<Family>,
    startup: crate::startup::checks::Checks,
    kernel_policy: Option<crate::image::KernelMarkerPolicy>,
    // Arc-shared so per-pair `self.clone()` in preparation is a refcount bump,
    // not a ~1MB Envelope copy (the whole-catalogue crossflash-scan hot path).
    installed_kernel: Option<Arc<Envelope>>,
    installed_normal: Option<Arc<Envelope>>,
    codec: &'static dyn ReceiverCodec,
}

trait ReceiverCodec: core::fmt::Debug + Sync {
    fn detect(&self, image: &[u8], kernel: Option<&[u8]>) -> Option<ReceiverControl>;
    fn control(
        &self,
        descriptor: &[u8; DESCRIPTOR_LEN],
        policy: ReceiverControl,
    ) -> [u8; cdb::CONTROL_LEN as usize];
}

#[derive(Debug)]
struct Oem;
impl ReceiverCodec for Oem {
    fn detect(&self, image: &[u8], kernel: Option<&[u8]>) -> Option<ReceiverControl> {
        receiver_control_with_kernel(image, kernel)
    }
    fn control(
        &self,
        descriptor: &[u8; DESCRIPTOR_LEN],
        policy: ReceiverControl,
    ) -> [u8; cdb::CONTROL_LEN as usize] {
        let mut control = [0; cdb::CONTROL_LEN as usize];
        control[..DESCRIPTOR_LEN].copy_from_slice(descriptor);
        match policy {
            ReceiverControl::DescriptorOnly => {}
            ReceiverControl::Key(key) => control[DESCRIPTOR_LEN..KEY_END].copy_from_slice(&key),
        }
        control
    }
}
const CODECS: &[&dyn ReceiverCodec] = &[&Oem];

impl Receiver {
    /// Recover entry requirements from decoded installed firmware instructions.
    ///
    /// File-derived only: this performs no device I/O.
    pub fn from_firmware(normal: &Envelope) -> Result<Self, Error> {
        Self::detect_components(normal, None)
    }

    fn detect_components(normal: &Envelope, kernel: Option<&Envelope>) -> Result<Self, Error> {
        if normal.info().kind != ComponentKind::Normal {
            return Err(Error::Component {
                actual: normal.info().kind,
            });
        }
        let mut receiver = Self::from_image_with_kernel(
            &normal.image,
            kernel.map(|kernel| kernel.image.as_slice()),
        )?;
        receiver.family = match kernel {
            Some(kernel) => normal.family_with_kernel(kernel),
            None => normal.family(),
        };
        receiver.installed_normal = Some(Arc::new(normal.clone()));
        Ok(receiver)
    }

    #[cfg(test)]
    fn from_image(image: &[u8]) -> Result<Self, Error> {
        Self::from_image_with_kernel(image, None)
    }

    fn from_image_with_kernel(image: &[u8], kernel: Option<&[u8]>) -> Result<Self, Error> {
        let descriptor: [u8; DESCRIPTOR_LEN] = image
            .get(..DESCRIPTOR_LEN)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(Error::InvalidDescriptor)?;
        // The descriptor is opaque OEM branding, not a permission token.
        // Native receiver policy and the exact live descriptor still gate entry.
        if !descriptor.iter().any(u8::is_ascii_graphic)
            || !descriptor
                .iter()
                .all(|b| *b == 0 || b.is_ascii_graphic() || *b == b' ')
        {
            return Err(Error::InvalidDescriptor);
        }
        let mut candidates = CODECS
            .iter()
            .filter_map(|&codec| codec.detect(image, kernel).map(|policy| (codec, policy)));
        let (codec, policy) = candidates.next().ok_or(Error::Unsupported)?;
        if candidates.next().is_some() {
            return Err(Error::Unsupported);
        }
        Ok(Self {
            descriptor,
            policy,
            family: None,
            startup: crate::startup::checks::Checks::discover(image, kernel),
            kernel_policy: None,
            installed_kernel: None,
            installed_normal: None,
            codec,
        })
    }

    /// Detect a receiver from a validated captured Kernel/Normal pair.
    ///
    /// Unlike Normal-only detection, this also retains the installed Kernel's
    /// recognized marker policy for complete-pair preparation.
    pub fn from_installed(installed: &crate::envelope::Update) -> Result<Self, Error> {
        Self::from_firmware_with_kernel(installed.normal(), installed.kernel())
    }

    /// Detect from decoded Normal and Kernel captured from the same drive.
    ///
    /// Captured firmware need not retain the original update-file signature.
    /// This inspects installed code, not permission to transfer these envelopes.
    /// The caller must bind both images to its capture; header agreement alone
    /// cannot prove they are currently installed on a physical device.
    pub fn from_firmware_with_kernel(normal: &Envelope, kernel: &Envelope) -> Result<Self, Error> {
        if normal.info().kind != ComponentKind::Normal {
            return Self::from_firmware(normal);
        }
        if kernel.info().kind != ComponentKind::Kernel {
            return Err(Error::KernelComponent {
                actual: kernel.info().kind,
            });
        }
        for (a, b) in [
            (
                &normal.info().hardware_version,
                &kernel.info().hardware_version,
            ),
            (&normal.info().kernel_version, &kernel.info().kernel_version),
        ] {
            if a.is_empty() || a != b {
                return Err(Error::InstalledPairMismatch);
            }
        }
        let mut receiver = Self::detect_components(normal, Some(kernel))?;
        receiver.kernel_policy = crate::image::kernel_marker_policy(&kernel.image);
        receiver.installed_kernel = Some(Arc::new(kernel.clone()));
        Ok(receiver)
    }

    /// Hardware family recovered from the captured installed image.
    pub fn family(&self) -> Option<Family> {
        self.family
    }

    /// All recognized startup requirements belonging to this receiver.
    pub fn startup_checks(&self) -> crate::startup::checks::Checks {
        self.startup
    }

    /// The already decoded installed Kernel supplied during receiver detection.
    ///
    /// This is captured file evidence, not proof of the live drive's identity.
    pub fn installed_kernel(&self) -> Option<&Envelope> {
        self.installed_kernel.as_deref()
    }

    /// Require the target Normal to describe the same hardware family.
    ///
    /// This is the hardware compatibility gate. A matching family does not
    /// validate envelope integrity or complete the receiver's transfer plan.
    pub fn check_family(&self, target: &Envelope) -> Result<Family, Error> {
        if target.info().kind != ComponentKind::Normal {
            return Err(Error::Component {
                actual: target.info().kind,
            });
        }
        self.compare_family(target.family().or_else(|| {
            self.installed_kernel
                .as_deref()
                .and_then(|k| target.family_with_kernel(k))
        }))
    }

    /// Compare against a target Normal using its exact associated Kernel.
    /// This is required for target identity evidence implemented in resident code.
    pub fn check_family_with_kernel(
        &self,
        target: &Envelope,
        kernel: &Envelope,
    ) -> Result<Family, Error> {
        if target.info().kind != ComponentKind::Normal {
            return Err(Error::Component {
                actual: target.info().kind,
            });
        }
        self.compare_family(target.family_with_kernel(kernel))
    }

    fn compare_family(&self, target: Option<Family>) -> Result<Family, Error> {
        let installed = self.family.ok_or(Error::UnknownInstalledFamily)?;
        let target = target.ok_or(Error::UnknownTargetFamily)?;
        if installed != target {
            return Err(Error::FamilyMismatch { installed, target });
        }
        Ok(installed)
    }

    fn control(&self) -> Control {
        self.codec.control(&self.descriptor, self.policy)
    }

    /// Construct entry/finish control after checking the live descriptor.
    ///
    /// Descriptor equality binds this buffer to the supplied firmware evidence;
    /// it is not a full-image readback or permission to issue update commands.
    pub fn entry_control(
        &self,
        live_descriptor: &[u8],
    ) -> Result<[u8; cdb::CONTROL_LEN as usize], Error> {
        if live_descriptor != self.descriptor {
            return Err(Error::DescriptorMismatch);
        }
        Ok(self.control())
    }
}

#[cfg(test)]
#[path = "receiver_tests.rs"]
mod tests;
