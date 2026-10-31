//! Execute receiver plans with descriptor binding and Kernel verification.
use super::transport;
use super::{Control, PreparedNormal, PreparedStage, PreparedUpdate, DESCRIPTOR_LEN};
use crate::drive::{self, Segment, Transport, UpdateOptions, UpdateRuntime};

const DESCRIPTOR_ADDRESS: u32 = 0x0041_0000;
const READ_CHUNK: usize = 0x8000;

/// Which update pass was active when an operation failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlashPass {
    /// Initial target transfer, possibly with a temporary Kernel patch.
    Initial,
    /// Required transfer restoring the unmodified target Kernel.
    Restoration,
    /// A bridge transition identified by its zero-based stage index.
    Continuation(usize),
}
impl FlashPass {
    pub(super) fn at(index: usize, previous: Option<super::BridgeKind>) -> Self {
        match index {
            0 => Self::Initial,
            1 if previous == Some(super::BridgeKind::ReceiverMarker) => Self::Restoration,
            n => Self::Continuation(n),
        }
    }
    /// Number of earlier stages already completed.
    pub fn completed_stages(self) -> usize {
        match self {
            Self::Initial => 0,
            Self::Restoration => 1,
            Self::Continuation(n) => n,
        }
    }
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
    /// The installed loader's kernel receive transport could not be satisfied;
    /// no entry was attempted, so no firmware was written.
    UnsupportedTransport {
        /// Pass being prepared.
        pass: FlashPass,
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
            Self::UnsupportedTransport { pass } => write!(
                f,
                "{pass:?} installed loader kernel receive transport is unsupported for this image"
            ),
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
    /// Low-level transfer with an independently established parameter migration.
    /// Complete application operations must use `execute` for all stage settings.
    pub fn transfer_with_parameter_unchecked<R, W, H>(
        &self,
        io: FlashTransport<'_, R, W>,
        runtime: &mut H,
        parameter: u16,
        target: u16,
    ) -> Result<(), crate::startup::migration::Error<W::Error, FlashError<W::Error>>>
    where
        W: Transport,
        R: Transport<Error = W::Error>,
        H: FlashRuntime<W::Error>,
    {
        let stages = self.stages();
        runtime.prepare_pass(FlashPass::Initial).map_err(|source| {
            crate::startup::migration::Error::Preflight(FlashError::Preflight {
                pass: FlashPass::Initial,
                source,
            })
        })?;
        bind(io.reads, &stages[0].receiver.control(), FlashPass::Initial)
            .map_err(crate::startup::migration::Error::Preflight)?;
        crate::startup::migration::execute(io.writes, parameter, target, |writes| {
            transfer_stages(
                stages,
                FlashTransport {
                    reads: io.reads,
                    writes,
                },
                runtime,
            )
        })
    }
    /// Transfer prepared stages with mandatory Kernel verification only.
    /// This omits startup settings and Normal/runtime checks; use `execute`.
    pub fn transfer_unchecked<R, W, H>(
        &self,
        io: FlashTransport<'_, R, W>,
        runtime: &mut H,
    ) -> Result<(), FlashError<W::Error>>
    where
        W: Transport,
        R: Transport<Error = W::Error>,
        H: FlashRuntime<W::Error>,
    {
        transfer_stages(self.stages(), io, runtime)
    }
}
impl PreparedNormal {
    /// Low-level transfer with an independently established parameter migration.
    /// Complete application operations must use `execute` for all stage settings.
    pub fn transfer_with_parameter_unchecked<R, W, H>(
        &self,
        io: FlashTransport<'_, R, W>,
        runtime: &mut H,
        parameter: u16,
        target: u16,
    ) -> Result<(), crate::startup::migration::Error<W::Error, FlashError<W::Error>>>
    where
        W: Transport,
        R: Transport<Error = W::Error>,
        H: FlashRuntime<W::Error>,
    {
        let stages = std::slice::from_ref(self.stage());
        runtime.prepare_pass(FlashPass::Initial).map_err(|source| {
            crate::startup::migration::Error::Preflight(FlashError::Preflight {
                pass: FlashPass::Initial,
                source,
            })
        })?;
        bind(io.reads, &stages[0].receiver.control(), FlashPass::Initial)
            .map_err(crate::startup::migration::Error::Preflight)?;
        crate::startup::migration::execute(io.writes, parameter, target, |writes| {
            transfer_stages(
                stages,
                FlashTransport {
                    reads: io.reads,
                    writes,
                },
                runtime,
            )
        })
    }
    /// Transfer prepared stages with mandatory Kernel verification only.
    /// This omits startup settings and Normal/runtime checks; use `execute`.
    pub fn transfer_unchecked<R, W, H>(
        &self,
        io: FlashTransport<'_, R, W>,
        runtime: &mut H,
    ) -> Result<(), FlashError<W::Error>>
    where
        W: Transport,
        R: Transport<Error = W::Error>,
        H: FlashRuntime<W::Error>,
    {
        transfer_stages(std::slice::from_ref(self.stage()), io, runtime)
    }
}
fn transfer_stages<R, W, H>(
    stages: &[PreparedStage],
    io: FlashTransport<'_, R, W>,
    runtime: &mut H,
) -> Result<(), FlashError<W::Error>>
where
    W: Transport,
    R: Transport<Error = W::Error>,
    H: FlashRuntime<W::Error>,
{
    for (index, stage) in stages.iter().enumerate() {
        let pass = FlashPass::at(index, index.checked_sub(1).and_then(|i| stages[i].bridge()));
        let options = runtime
            .prepare_pass(pass)
            .map_err(|source| FlashError::Preflight { pass, source })?;
        let control = stage.receiver.control();
        bind(io.reads, &control, pass)?;
        let installed = stage
            .receiver
            .installed_kernel()
            .expect("prepared installed Kernel");
        let mut storage = [Segment::PLACEHOLDER; 3];
        let plan = transport::plan(
            stage.kernel_transfer(),
            stage.normal_transfer(),
            transport::detect(&installed.image),
            &mut storage,
        )
        .map_err(|_| FlashError::UnsupportedTransport { pass })?;
        drive::execute_plan(io.writes, runtime, &control, plan, options)
            .map_err(|source| FlashError::Update { pass, source })?;
        if let Some(kernel) = stage.kernel_image() {
            verify(io.reads, kernel, pass)?;
        }
    }
    Ok(())
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
pub(super) fn bind<T: Transport>(
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
pub(super) fn verify<T: Transport>(
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
        if let crate::envelope::ByteComparison::Different { offset, .. } =
            crate::envelope::compare_bytes(chunk, actual)
        {
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
