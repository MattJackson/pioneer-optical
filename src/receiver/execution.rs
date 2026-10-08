//! Execute receiver plans with descriptor binding and Kernel verification.
use super::{Control, PreparedNormal, PreparedUpdate, DESCRIPTOR_LEN};
use crate::drive::{self, Transport, UpdateOptions, UpdateRuntime, UpdateTransfer};

const DESCRIPTOR_ADDRESS: u32 = 0x0041_0000;
const READ_CHUNK: usize = 0x8000;

/// Which update pass was active when an operation failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlashPass {
    /// Initial target transfer, possibly with a temporary Kernel patch.
    Initial,
    /// Required transfer restoring the unmodified target Kernel.
    Restoration,
}

/// Host policy and progress for a prepared flash.
///
/// The policy runs before each pass, including restoration. Implementations can
/// check the tray and current identity without surrendering ownership of these
/// application decisions to the firmware codec.
pub trait FlashRuntime<E>: UpdateRuntime {
    /// Check that this pass may proceed and select its live update dialect.
    /// Returning an error prevents entry into this pass.
    fn prepare_pass(&mut self, pass: FlashPass) -> Result<UpdateOptions, E>;
}

/// Read and strict-update adapters accessing the same physical drive.
///
/// Separate adapters preserve read-unlock handling without weakening firmware
/// write errors. They must report the same error type. Prevent concurrent device
/// access throughout the operation.
pub struct FlashTransport<'a, R, W> {
    /// Memory reads, including the extended-read unlock command.
    pub reads: &'a mut R,
    /// Update commands; firmware writes must never be retried by this adapter.
    pub writes: &'a mut W,
}

/// A failed prepared flash, retaining its pass and command-level cause.
#[derive(Debug)]
#[non_exhaustive]
pub enum FlashError<E> {
    /// Host policy refused a pass before update entry.
    Preflight {
        /// Pass that was refused.
        pass: FlashPass,
        /// Host policy error.
        source: E,
    },
    /// A descriptor could not be read in full.
    DescriptorRead {
        /// Pass being entered.
        pass: FlashPass,
        /// Underlying read error.
        source: drive::Error<E>,
    },
    /// Descriptor changed between consecutive reads; no entry attempted.
    DescriptorChanged {
        /// Pass being entered.
        pass: FlashPass,
    },
    /// Descriptor differs from captured evidence; no entry attempted.
    DescriptorMismatch {
        /// Pass being entered.
        pass: FlashPass,
    },
    /// Update sequence failed; firmware may already have been modified.
    Update {
        /// Failed update pass.
        pass: FlashPass,
        /// Exact sequence stage and command failure.
        source: drive::UpdateError<E>,
    },
    /// Kernel readback failed after the update completed.
    Readback {
        /// Pass being verified.
        pass: FlashPass,
        /// Underlying read error.
        source: drive::Error<E>,
    },
    /// Kernel bytes differ from the prepared expectation.
    ReadbackMismatch {
        /// Pass being verified.
        pass: FlashPass,
        /// Address of the first differing byte.
        address: u32,
    },
}
impl<E: core::fmt::Debug> core::fmt::Display for FlashError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Preflight { pass, source } => write!(f, "{pass:?} preflight: {source:?}"),
            Self::DescriptorRead { pass, source } => {
                write!(f, "{pass:?} receiver descriptor read: {source}")
            }
            Self::DescriptorChanged { pass } => {
                write!(f, "{pass:?} receiver descriptor changed between reads")
            }
            Self::DescriptorMismatch { pass } => write!(
                f,
                "{pass:?} live receiver descriptor does not match captured firmware"
            ),
            Self::Update { pass, source } => write!(f, "{pass:?} update: {source}"),
            Self::Readback { pass, source } => write!(f, "{pass:?} Kernel readback: {source}"),
            Self::ReadbackMismatch { pass, address } => {
                write!(f, "{pass:?} Kernel readback differs at {address:#x}")
            }
        }
    }
}
impl<E: core::fmt::Debug + 'static> std::error::Error for FlashError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::DescriptorRead { source, .. } | Self::Readback { source, .. } => Some(source),
            Self::Update { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl PreparedUpdate {
    /// Execute both prepared passes when needed, verifying each Kernel readback.
    ///
    /// First capture a backup, enforce tray/consent policy, establish the entry
    /// dialect and exclude other device users. Both adapters must address the
    /// drive from which receiver evidence was captured. A failed step stops
    /// immediately; no automatic recovery writes or rollback are attempted.
    pub fn flash<R, W, H>(
        &self,
        io: FlashTransport<'_, R, W>,
        runtime: &mut H,
    ) -> Result<(), FlashError<W::Error>>
    where
        W: Transport,
        R: Transport<Error = W::Error>,
        H: FlashRuntime<W::Error>,
    {
        let options =
            runtime
                .prepare_pass(FlashPass::Initial)
                .map_err(|source| FlashError::Preflight {
                    pass: FlashPass::Initial,
                    source,
                })?;
        bind(io.reads, &self.control, FlashPass::Initial)?;
        drive::execute_update(
            io.writes,
            runtime,
            &self.control,
            UpdateTransfer {
                kernel: Some(self.kernel_transfer()),
                normal: self.normal_transfer(),
            },
            options,
        )
        .map_err(|source| FlashError::Update {
            pass: FlashPass::Initial,
            source,
        })?;
        verify(io.reads, self.first_kernel_image(), FlashPass::Initial)?;
        if let Some(kernel) = self.restoration_kernel_transfer() {
            let receiver = self
                .restoration_receiver()
                .expect("prepared restoration receiver");
            let options = runtime
                .prepare_pass(FlashPass::Restoration)
                .map_err(|source| FlashError::Preflight {
                    pass: FlashPass::Restoration,
                    source,
                })?;
            let control = receiver.control();
            bind(io.reads, &control, FlashPass::Restoration)?;
            drive::execute_update(
                io.writes,
                runtime,
                &control,
                UpdateTransfer {
                    kernel: Some(kernel),
                    normal: self.normal_transfer(),
                },
                options,
            )
            .map_err(|source| FlashError::Update {
                pass: FlashPass::Restoration,
                source,
            })?;
            verify(io.reads, self.final_kernel_image(), FlashPass::Restoration)?;
        }
        Ok(())
    }
}
impl PreparedNormal {
    /// Execute Normal-only after binding the live descriptor to captured evidence.
    ///
    /// First capture a backup, enforce tray/consent policy, establish the entry
    /// dialect and exclude other device users. No Kernel is written.
    pub fn flash<R, W, H>(
        &self,
        io: FlashTransport<'_, R, W>,
        runtime: &mut H,
    ) -> Result<(), FlashError<W::Error>>
    where
        W: Transport,
        R: Transport<Error = W::Error>,
        H: FlashRuntime<W::Error>,
    {
        let options =
            runtime
                .prepare_pass(FlashPass::Initial)
                .map_err(|source| FlashError::Preflight {
                    pass: FlashPass::Initial,
                    source,
                })?;
        bind(io.reads, &self.control, FlashPass::Initial)?;
        drive::execute_update(
            io.writes,
            runtime,
            &self.control,
            UpdateTransfer {
                kernel: None,
                normal: self.normal_transfer(),
            },
            options,
        )
        .map_err(|source| FlashError::Update {
            pass: FlashPass::Initial,
            source,
        })
    }
}
fn exact<T: Transport>(
    transport: &mut T,
    address: u32,
    bytes: &mut [u8],
) -> Result<(), drive::Error<T::Error>> {
    let actual = drive::read_memory(transport, address, bytes)?;
    if actual != bytes.len() {
        return Err(drive::Error::Short {
            expected: bytes.len(),
            actual,
        });
    }
    Ok(())
}
fn bind<T: Transport>(
    transport: &mut T,
    control: &Control,
    pass: FlashPass,
) -> Result<(), FlashError<T::Error>> {
    let mut first = [0; DESCRIPTOR_LEN];
    let mut second = [0; DESCRIPTOR_LEN];
    exact(transport, DESCRIPTOR_ADDRESS, &mut first)
        .map_err(|source| FlashError::DescriptorRead { pass, source })?;
    exact(transport, DESCRIPTOR_ADDRESS, &mut second)
        .map_err(|source| FlashError::DescriptorRead { pass, source })?;
    if first != second {
        return Err(FlashError::DescriptorChanged { pass });
    }
    if first != control[..DESCRIPTOR_LEN] {
        return Err(FlashError::DescriptorMismatch { pass });
    }
    Ok(())
}
fn verify<T: Transport>(
    transport: &mut T,
    expected: &[u8],
    pass: FlashPass,
) -> Result<(), FlashError<T::Error>> {
    let mut buffer = [0; READ_CHUNK];
    for (index, chunk) in expected.chunks(READ_CHUNK).enumerate() {
        let address = crate::image::KERNEL_BASE + (index * READ_CHUNK) as u32;
        let actual = &mut buffer[..chunk.len()];
        exact(transport, address, actual)
            .map_err(|source| FlashError::Readback { pass, source })?;
        if let Some(offset) = actual.iter().zip(chunk).position(|(a, b)| a != b) {
            return Err(FlashError::ReadbackMismatch {
                pass,
                address: address + offset as u32,
            });
        }
    }
    Ok(())
}
#[cfg(test)]
#[path = "execution_tests.rs"]
mod tests;
