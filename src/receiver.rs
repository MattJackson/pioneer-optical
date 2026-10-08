//! Firmware-derived receiver requirements.
//!
//! Detection performs no device I/O. Entry control alone does not establish
//! hardware compatibility, component acceptance, or a complete flash plan.

use crate::envelope::Envelope;
use crate::image::{receiver_control, ReceiverControl};
use crate::{cdb, ComponentKind};

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
    /// The resident image has no valid entry descriptor.
    InvalidDescriptor,
    /// No unique supported entry handler was recovered from the image.
    Unsupported,
    /// The live descriptor differs from the captured installed firmware.
    DescriptorMismatch,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Component { actual } => write!(
                f,
                "receiver detection requires a Normal component, got {actual:?}"
            ),
            Self::InvalidDescriptor => f.write_str("invalid resident Pioneer control descriptor"),
            Self::Unsupported => f.write_str("receiver entry control is unsupported or ambiguous"),
            Self::DescriptorMismatch => {
                f.write_str("installed firmware does not match the live receiver descriptor")
            }
        }
    }
}
impl std::error::Error for Error {}

/// A receiver's detected entry requirements, bound to its installed firmware.
///
/// Construct from the captured installed Normal, decoded with its Kernel when
/// needed. A target envelope must not be substituted for installed evidence.
/// This object currently establishes entry control only; callers must validate
/// family, components, transfer sequencing and verification before any write.
#[derive(Debug)]
pub struct Receiver {
    descriptor: [u8; DESCRIPTOR_LEN],
    policy: ReceiverControl,
    codec: &'static dyn ReceiverCodec,
}

trait ReceiverCodec: core::fmt::Debug + Sync {
    fn detect(&self, image: &[u8]) -> Option<ReceiverControl>;
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
            codec,
        })
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
