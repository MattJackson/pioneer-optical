//! Immutable component preparation; no transport or device I/O.

use super::{Error, Receiver};
use crate::envelope::{downgrade_patch, Update, KERNEL_MARKER_OFFSET};
use crate::image::{kernel_marker_policy, KernelMarkerPolicy};

/// A receiver could not prepare all required update passes.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PreparationError {
    /// Installed/target hardware compatibility could not be established.
    Compatibility(Error),
    /// The installed Kernel's marker handling is not recognized.
    UnknownInstalledKernel,
    /// The target Kernel cannot be proven to accept its pristine restoration.
    UnsupportedRestoration,
    /// The target Normal's entry requirements could not be established.
    RestorationEntry(Error),
    /// A patched Kernel could not be encoded in the required transfer format.
    PatchedRepresentation,
}

impl core::fmt::Display for PreparationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Compatibility(error) => write!(f, "update compatibility: {error}"),
            Self::UnknownInstalledKernel => {
                f.write_str("installed Kernel marker policy is unsupported or unavailable")
            }
            Self::UnsupportedRestoration => f.write_str(
                "target Kernel does not establish a supported pristine restoration path",
            ),
            Self::RestorationEntry(error) => write!(f, "pristine restoration entry: {error}"),
            Self::PatchedRepresentation => {
                f.write_str("temporarily patched Kernel cannot be represented for transfer")
            }
        }
    }
}
impl std::error::Error for PreparationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Compatibility(error) | Self::RestorationEntry(error) => Some(error),
            _ => None,
        }
    }
}

/// Complete-pair component bytes and mandatory Kernel readback expectations.
///
/// This is preparation, not an executed flash or a complete transport schedule.
/// The executor must bind live entry descriptors, perform protocol transitions,
/// and verify the first Kernel before starting any required restoration pass.
/// Success requires the final Kernel readback to match the pristine target.
#[derive(Debug)]
pub struct PreparedUpdate {
    target: Update,
    restoration: Option<Restoration>,
}

#[derive(Debug)]
struct Restoration {
    first_kernel: Vec<u8>,
    first_image: Vec<u8>,
    receiver: Receiver,
}

impl PreparedUpdate {
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
    /// Prepare both passes of a complete update before issuing any commands.
    ///
    /// Requires captured installed Kernel evidence from [`Self::from_installed`].
    /// Family compatibility is checked first. Unknown marker handling never
    /// authorizes either an unmodified or a temporarily patched Kernel write.
    pub fn prepare(&self, target: Update) -> Result<PreparedUpdate, PreparationError> {
        self.check_family(target.normal())
            .map_err(PreparationError::Compatibility)?;
        let policy = self
            .kernel_policy
            .ok_or(PreparationError::UnknownInstalledKernel)?;
        self.codec.prepare(policy, target)
    }
}

pub(super) fn prepare_oem(
    policy: KernelMarkerPolicy,
    target: Update,
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
        target,
        restoration,
    })
}

fn needs_patch(policy: KernelMarkerPolicy, marker: Option<u8>) -> bool {
    matches!(policy, KernelMarkerPolicy::RejectZeroAndErased) && matches!(marker, Some(0 | 0xff))
}

#[cfg(test)]
#[path = "preparation_tests.rs"]
mod tests;
