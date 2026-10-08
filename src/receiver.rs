//! Firmware-derived receiver requirements.
//!
//! Detection performs no device I/O. Entry control alone does not establish
//! hardware compatibility, component acceptance, or a complete flash plan.

use crate::envelope::Envelope;
use crate::image::{family, receiver_control, Family, ReceiverControl};
use crate::{cdb, ComponentKind};

mod preparation;
pub use preparation::{PreparationError, PreparedNormal, PreparedUpdate};

/// Bytes compared by the resident Normal's update-entry handler.
pub const DESCRIPTOR_LEN: usize = 16;
const KEY_END: usize = DESCRIPTOR_LEN + 4;
const DESCRIPTOR_PREFIX: &[u8] = b"PIONEER ";

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
/// the installed Kernel's code. Callers still own transport sequencing and
/// readback verification; preparation performs no device I/O.
#[derive(Debug)]
pub struct Receiver {
    descriptor: [u8; DESCRIPTOR_LEN],
    policy: ReceiverControl,
    family: Option<Family>,
    kernel_policy: Option<crate::image::KernelMarkerPolicy>,
    installed_kernel: Option<Envelope>,
    codec: &'static dyn ReceiverCodec,
}

trait ReceiverCodec: core::fmt::Debug + Sync {
    fn detect(&self, image: &[u8]) -> Option<ReceiverControl>;
    fn prepare_normal(
        &self,
        kernel: &Envelope,
        target: &[u8],
    ) -> Result<PreparedNormal, PreparationError>;
    fn prepare(
        &self,
        policy: crate::image::KernelMarkerPolicy,
        target: crate::envelope::Update,
    ) -> Result<PreparedUpdate, PreparationError>;
    fn control(
        &self,
        descriptor: &[u8; DESCRIPTOR_LEN],
        policy: ReceiverControl,
    ) -> [u8; cdb::CONTROL_LEN as usize];
}

#[derive(Debug)]
struct Oem;
impl ReceiverCodec for Oem {
    fn detect(&self, image: &[u8]) -> Option<ReceiverControl> {
        receiver_control(image)
    }
    fn prepare_normal(
        &self,
        kernel: &Envelope,
        target: &[u8],
    ) -> Result<PreparedNormal, PreparationError> {
        preparation::prepare_normal_oem(kernel, target)
    }
    fn prepare(
        &self,
        policy: crate::image::KernelMarkerPolicy,
        target: crate::envelope::Update,
    ) -> Result<PreparedUpdate, PreparationError> {
        preparation::prepare_oem(policy, target)
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
    pub fn detect(normal: &Envelope) -> Result<Self, Error> {
        if normal.info().kind != ComponentKind::Normal {
            return Err(Error::Component {
                actual: normal.info().kind,
            });
        }
        Self::from_image(&normal.image)
    }

    fn from_image(image: &[u8]) -> Result<Self, Error> {
        let descriptor: [u8; DESCRIPTOR_LEN] = image
            .get(..DESCRIPTOR_LEN)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(Error::InvalidDescriptor)?;
        if !descriptor.starts_with(DESCRIPTOR_PREFIX)
            || !descriptor
                .iter()
                .all(|b| *b == 0 || b.is_ascii_graphic() || *b == b' ')
        {
            return Err(Error::InvalidDescriptor);
        }
        let mut candidates = CODECS
            .iter()
            .filter_map(|&codec| codec.detect(image).map(|policy| (codec, policy)));
        let (codec, policy) = candidates.next().ok_or(Error::Unsupported)?;
        if candidates.next().is_some() {
            return Err(Error::Unsupported);
        }
        Ok(Self {
            descriptor,
            policy,
            family: family(image),
            kernel_policy: None,
            installed_kernel: None,
            codec,
        })
    }

    /// Detect a receiver from a validated captured Kernel/Normal pair.
    ///
    /// Unlike Normal-only detection, this also retains the installed Kernel's
    /// recognized marker policy for complete-pair preparation.
    pub fn from_installed(installed: &crate::envelope::Update) -> Result<Self, Error> {
        Self::detect_with_kernel(installed.normal(), installed.kernel())
    }

    /// Detect from decoded Normal and Kernel captured from the same drive.
    ///
    /// Captured firmware need not retain the original update-file signature.
    /// This inspects installed code, not permission to transfer these envelopes.
    /// The caller must bind both images to its capture; header agreement alone
    /// cannot prove they are currently installed on a physical device.
    pub fn detect_with_kernel(normal: &Envelope, kernel: &Envelope) -> Result<Self, Error> {
        let mut receiver = Self::detect(normal)?;
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
        receiver.kernel_policy = crate::image::kernel_marker_policy(&kernel.image);
        receiver.installed_kernel = Some(kernel.clone());
        Ok(receiver)
    }

    /// Hardware family recovered from the captured installed image.
    pub fn family(&self) -> Option<Family> {
        self.family
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
        self.compare_family(target.family())
    }

    fn compare_family(&self, target: Option<Family>) -> Result<Family, Error> {
        let installed = self.family.ok_or(Error::UnknownInstalledFamily)?;
        let target = target.ok_or(Error::UnknownTargetFamily)?;
        if installed != target {
            return Err(Error::FamilyMismatch { installed, target });
        }
        Ok(installed)
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
        Ok(self.codec.control(&self.descriptor, self.policy))
    }
}

#[cfg(test)]
#[path = "receiver_tests.rs"]
mod tests;
