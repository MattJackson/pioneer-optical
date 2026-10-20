//! Complete receiver-owned execution. Host callbacks enforce host policy only.
use super::{
    execution, transport, FlashError, FlashPass, FlashTransport, PreparedNormal, PreparedUpdate,
};
use crate::drive::{self, Segment, Transport, UpdateOptions, UpdateRuntime};
use crate::envelope::Envelope;
use crate::{DriveClass, Identity};

/// Deliberate host policy for a prepared operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionMode {
    /// Require the captured running receiver and perform all startup migration.
    Flash,
    /// Also permit an identified loader, whose Normal parameter command is unavailable.
    Recovery,
}

/// Host checks and progress. Protocol selection belongs to the prepared firmware.
pub trait ExecutionRuntime<E>: UpdateRuntime {
    /// Check host conditions (for example, an empty tray) before each pass.
    fn check_pass(&mut self, pass: FlashPass) -> Result<(), E>;
    /// A component could not be fully read back. This is evidence for a
    /// qualified outcome, never permission to ignore a readable mismatch.
    fn verification_unavailable(
        &mut self,
        _pass: FlashPass,
        _role: crate::Role,
        _address: Option<u32>,
        _reason: &dyn core::fmt::Debug,
    ) {
    }
}

/// Evidence retained only after the requested firmware has started.
#[derive(Debug)]
pub struct FlashOutcome {
    /// Exact Kernel bytes were read back. False for a Normal-only update.
    pub kernel_verified: bool,
    /// Exact Normal bytes were read back; false if reads were unavailable.
    pub normal_verified: bool,
    /// Number of completed passes, including required pristine restoration.
    pub completed_passes: usize,
    /// Observed identity checked against the target firmware.
    pub identity: Identity,
}

/// Failure of a complete operation. A readable mismatch is never downgraded to
/// limited verification. No failing write is retried.
#[derive(Debug)]
#[non_exhaustive]
pub enum ExecutionError<E> {
    /// Firmware did not establish an unambiguous executable plan.
    Plan(&'static str),
    /// Identity could not be obtained at a required boundary.
    IdentityRead {
        /// Pass whose boundary could not be checked.
        pass: FlashPass,
        /// Whether this was post-transfer target confirmation.
        target: bool,
        /// Command failure.
        source: drive::Error<E>,
    },
    /// Identity did not match the firmware expected at this boundary.
    IdentityMismatch {
        /// Pass whose boundary did not match.
        pass: FlashPass,
        /// Actual device identity.
        observed: Identity,
        /// Whether this was post-transfer target confirmation.
        target: bool,
    },
    /// Host policy, descriptor binding, transfer or mandatory Kernel verification failed.
    Flash(FlashError<E>),
    /// Startup setting migration failed, retaining its rollback boundary.
    Startup(Box<crate::startup::migration::Error<E, ExecutionError<E>>>),
    /// Normal readback returned bytes different from the requested target.
    NormalMismatch {
        /// Pass being verified.
        pass: FlashPass,
        /// First differing drive address.
        address: u32,
    },
}
impl<E: core::fmt::Debug> core::fmt::Display for ExecutionError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Plan(reason) => {
                write!(f, "update plan refused before firmware transfer: {reason}")
            }
            Self::IdentityRead { pass, source, .. } => {
                write!(f, "{pass:?} required identity read: {source}")
            }
            Self::IdentityMismatch {
                pass,
                observed,
                target,
            } => write!(
                f,
                "{pass:?} {} identity mismatch: {} revision {}, platform {}, Kernel {}, Normal {}",
                if *target {
                    "target startup"
                } else {
                    "receiver"
                },
                observed.product(),
                observed.revision(),
                observed.platform(),
                observed.kernel_tag(),
                observed.normal_tag()
            ),
            Self::Flash(source) => source.fmt(f),
            Self::Startup(source) => source.fmt(f),
            Self::NormalMismatch { pass, address } => {
                write!(f, "{pass:?} target Normal readback differs at {address:#x}")
            }
        }
    }
}
impl<E: core::fmt::Debug + 'static> std::error::Error for ExecutionError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::IdentityRead { source, .. } => Some(source),
            Self::Flash(source) => Some(source),
            Self::Startup(source) => Some(source),
            _ => None,
        }
    }
}

impl<E> ExecutionError<E> {
    /// Firmware transfer may have been attempted; conservative for uncertain entry failures.
    pub fn firmware_write_started(&self) -> bool {
        match self {
            Self::Plan(_) => false,
            Self::IdentityRead { pass, target, .. }
            | Self::IdentityMismatch { pass, target, .. } => {
                *target || *pass == FlashPass::Restoration
            }
            Self::NormalMismatch { .. } => true,
            Self::Flash(error) => match error {
                FlashError::Preflight { pass, .. }
                | FlashError::DescriptorRead { pass, .. }
                | FlashError::DescriptorChanged { pass }
                | FlashError::DescriptorMismatch { pass }
                | FlashError::UnsupportedTransport { pass } => *pass == FlashPass::Restoration,
                FlashError::Update {
                    source: drive::UpdateError::InvalidSpan { .. },
                    pass,
                } => *pass == FlashPass::Restoration,
                _ => true,
            },
            Self::Startup(error) => match error.as_ref() {
                crate::startup::migration::Error::Preflight(source)
                | crate::startup::migration::Error::Flash { source, .. } => {
                    source.firmware_write_started()
                }
                _ => false,
            },
        }
    }
    /// Any device mutation may have been attempted, including startup settings.
    pub fn write_started(&self) -> bool {
        if let Self::Startup(error) = self {
            return match error.as_ref() {
                crate::startup::migration::Error::Change { .. } => true,
                crate::startup::migration::Error::Flash {
                    original,
                    target,
                    source,
                    ..
                } => original != target || source.write_started(),
                crate::startup::migration::Error::Preflight(source) => source.write_started(),
                _ => false,
            };
        }
        self.firmware_write_started()
    }
    /// The boundary which failed, suitable for operation diagnostics.
    pub fn phase(&self) -> &'static str {
        match self {
            Self::Plan(_) => "preflight",
            Self::IdentityRead { target, .. } | Self::IdentityMismatch { target, .. } => {
                if *target {
                    "target startup"
                } else {
                    "receiver binding"
                }
            }
            Self::NormalMismatch { .. } => "Normal readback",
            Self::Flash(error) => match error {
                FlashError::Readback { .. } | FlashError::ReadbackMismatch { .. } => {
                    "Kernel readback"
                }
                FlashError::Update { .. } => "firmware transfer",
                _ => "preflight",
            },
            Self::Startup(error) => match error.as_ref() {
                crate::startup::migration::Error::Flash { source, .. } => source.phase(),
                _ => "startup setting",
            },
        }
    }
}
impl<E> crate::CodedError for ExecutionError<E> {
    fn code(&self) -> &'static str {
        match self {
            Self::Plan(_) => "pioneer.execute.plan",
            Self::IdentityRead { .. } => "pioneer.execute.identity_read",
            Self::IdentityMismatch { .. } => "pioneer.execute.identity_mismatch",
            Self::Flash(error) => error.code(),
            Self::Startup(error) => error.code(),
            Self::NormalMismatch { .. } => "pioneer.execute.normal_mismatch",
        }
    }
}

fn class<E>(class: Option<DriveClass>) -> Result<DriveClass, ExecutionError<E>> {
    class.ok_or(ExecutionError::Plan(
        "Kernel has no unique update dialect signature",
    ))
}
fn identity<T: Transport>(
    t: &mut T,
    pass: FlashPass,
    target: bool,
) -> Result<Identity, ExecutionError<T::Error>> {
    drive::identify(t).map_err(|source| ExecutionError::IdentityRead {
        pass,
        source,
        target,
    })
}
fn optical(id: &Identity) -> bool {
    id.device_type() == 5 && id.vendor() == "PIONEER"
}
fn loader(id: &Identity) -> bool {
    optical(id)
        && id.revision() == "0000"
        && id.normal_tag().is_empty()
        && !id.kernel_tag().is_empty()
}
fn receiver_matches(id: &Identity, kernel: &Envelope) -> bool {
    let info = kernel.info();
    optical(id) && id.platform() == info.hardware_version && id.kernel_tag() == info.kernel_version
}
fn check_receiver<T: Transport>(
    t: &mut T,
    kernel: &Envelope,
    control: &super::Control,
    mode: ExecutionMode,
    pass: FlashPass,
) -> Result<bool, ExecutionError<T::Error>> {
    let id = identity(t, pass, false)?;
    // Loader mode may expose a partially installed Kernel identity. Recovery
    // uses explicit Current firmware evidence for that loader's protocol.
    if mode == ExecutionMode::Recovery && loader(&id) {
        return Ok(true);
    }
    if !receiver_matches(&id, kernel)
        || id.revision().starts_with("000")
        || id.normal_tag().is_empty()
    {
        return Err(ExecutionError::IdentityMismatch {
            pass,
            observed: id,
            target: false,
        });
    }
    execution::bind(t, control, pass).map_err(ExecutionError::Flash)?;
    Ok(false)
}
fn target_identity<T: Transport>(
    t: &mut T,
    target: &Envelope,
    pass: FlashPass,
) -> Result<Identity, ExecutionError<T::Error>> {
    let id = identity(t, pass, true)?;
    let info = target.info();
    // Revision is display evidence here, not the source of dialect/compatibility.
    // The descriptor and readback below identify the actual target bytes.
    if !optical(&id)
        || !target.targets(&id)
        || id.revision() != info.revision
        || id.revision().starts_with("000")
        || id.normal_tag() != info.kernel_version
    {
        return Err(ExecutionError::IdentityMismatch {
            pass,
            observed: id,
            target: true,
        });
    }
    Ok(id)
}
fn normal_readback<T: Transport, H: ExecutionRuntime<T::Error>>(
    t: &mut T,
    expected: &[u8],
    region: Option<crate::envelope::NormalRegion>,
    pass: FlashPass,
    runtime: &mut H,
) -> Result<bool, ExecutionError<T::Error>> {
    let Some(region) = region else {
        runtime.verification_unavailable(
            pass,
            crate::Role::Normal,
            None,
            &"Kernel does not establish a supported Normal readback region",
        );
        return Ok(false);
    };
    verify_normal_at(t, expected, region.address(), pass, runtime)
}
fn verify_normal_at<T: Transport, H: ExecutionRuntime<T::Error>>(
    t: &mut T,
    expected: &[u8],
    base: u32,
    pass: FlashPass,
    runtime: &mut H,
) -> Result<bool, ExecutionError<T::Error>> {
    let mut buffer = [0; 0x8000];
    let mut complete = true;
    for (index, chunk) in expected.chunks(buffer.len()).enumerate() {
        let address = base + (index * buffer.len()) as u32;
        let actual = &mut buffer[..chunk.len()];
        match drive::read_memory(t, address, actual) {
            Ok(n) => {
                // Even a short read must not hide a readable mismatch. Continue
                // later spans after inaccessible spans so all readable bytes count.
                let n = n.min(actual.len());
                if let Some(offset) = actual[..n].iter().zip(chunk).position(|(a, b)| a != b) {
                    return Err(ExecutionError::NormalMismatch {
                        pass,
                        address: address + offset as u32,
                    });
                }
                if n != chunk.len() {
                    runtime.verification_unavailable(
                        pass,
                        crate::Role::Normal,
                        Some(address),
                        &drive::Error::<T::Error>::Short {
                            expected: chunk.len(),
                            actual: n,
                        },
                    );
                    complete = false;
                }
            }
            Err(error) => {
                runtime.verification_unavailable(pass, crate::Role::Normal, Some(address), &error);
                complete = false;
            }
        }
    }
    Ok(complete)
}
fn plan<'a, E>(
    kernel: Option<&'a [u8]>,
    normal: &'a [u8],
    receive: transport::KernelReceive,
    storage: &'a mut [Segment<'a>; 3],
) -> Result<drive::Plan<'a>, ExecutionError<E>> {
    let plan = transport::plan(kernel, normal, receive, storage)
        .map_err(|_| ExecutionError::Plan("receiver transfer layout is unsupported"))?;
    drive::validate_plan::<E>(plan)
        .map_err(|_| ExecutionError::Plan("transfer span exceeds the command address space"))?;
    Ok(plan)
}

impl PreparedUpdate {
    /// Flash through the complete receiver-owned procedure. Required migrations
    /// and verification cannot be omitted through this high-level entry point.
    pub fn flash<R, W, H>(
        &self,
        io: FlashTransport<'_, R, W>,
        runtime: &mut H,
    ) -> Result<FlashOutcome, ExecutionError<W::Error>>
    where
        W: Transport,
        R: Transport<Error = W::Error>,
        H: ExecutionRuntime<W::Error>,
    {
        self.execute(io, runtime, ExecutionMode::Flash)
    }

    /// Execute the complete firmware-derived operation, including startup
    /// migration, both required passes, Kernel readbacks and target startup.
    /// The caller owns consent, backup and exclusive access to the physical drive.
    pub fn execute<R, W, H>(
        &self,
        io: FlashTransport<'_, R, W>,
        runtime: &mut H,
        mode: ExecutionMode,
    ) -> Result<FlashOutcome, ExecutionError<W::Error>>
    where
        W: Transport,
        R: Transport<Error = W::Error>,
        H: ExecutionRuntime<W::Error>,
    {
        let installed = self.installed_kernel.as_ref().ok_or(ExecutionError::Plan(
            "installed Kernel evidence unavailable",
        ))?;
        class::<W::Error>(self.initial_class)?;
        // Validate every pass before any parameter or firmware write.
        let mut first = [Segment::PLACEHOLDER; 3];
        plan::<W::Error>(
            Some(self.kernel_transfer()),
            self.normal_transfer(),
            self.initial_receive
                .ok_or(ExecutionError::Plan("installed receiver unavailable"))?,
            &mut first,
        )?;
        if let Some(kernel) = self.restoration_kernel_transfer() {
            class::<W::Error>(self.target_class)?;
            let mut second = [Segment::PLACEHOLDER; 3];
            plan::<W::Error>(
                Some(kernel),
                self.normal_transfer(),
                transport::detect(self.first_kernel_image()),
                &mut second,
            )?;
        }
        runtime.check_pass(FlashPass::Initial).map_err(|source| {
            ExecutionError::Flash(FlashError::Preflight {
                pass: FlashPass::Initial,
                source,
            })
        })?;
        let updating =
            check_receiver(io.reads, installed, &self.control, mode, FlashPass::Initial)?;
        if !updating {
            if let Some(setting) = self.startup_setting {
                return crate::startup::migration::execute(
                    io.writes,
                    setting.parameter,
                    setting.value,
                    |writes| {
                        self.execute_passes(
                            FlashTransport {
                                reads: io.reads,
                                writes,
                            },
                            runtime,
                            false,
                        )
                    },
                )
                .map_err(|source| ExecutionError::Startup(Box::new(source)));
            }
        }
        self.execute_passes(io, runtime, updating)
    }

    fn execute_passes<R, W, H>(
        &self,
        io: FlashTransport<'_, R, W>,
        runtime: &mut H,
        updating: bool,
    ) -> Result<FlashOutcome, ExecutionError<W::Error>>
    where
        W: Transport,
        R: Transport<Error = W::Error>,
        H: ExecutionRuntime<W::Error>,
    {
        let installed = self
            .installed_kernel
            .as_ref()
            .expect("checked installed Kernel");
        // Host conditions can change during parameter migration. Recheck them
        // before any update command so a refusal can still restore the setting.
        runtime.check_pass(FlashPass::Initial).map_err(|source| {
            ExecutionError::Flash(FlashError::Preflight {
                pass: FlashPass::Initial,
                source,
            })
        })?;
        // Re-bind after the startup transaction, before entering the loader.
        check_receiver(
            io.reads,
            installed,
            &self.control,
            if updating {
                ExecutionMode::Recovery
            } else {
                ExecutionMode::Flash
            },
            FlashPass::Initial,
        )?;
        let mut storage = [Segment::PLACEHOLDER; 3];
        let transfer = plan(
            Some(self.kernel_transfer()),
            self.normal_transfer(),
            self.initial_receive.expect("checked receive layout"),
            &mut storage,
        )?;
        drive::execute_plan_with_entry(
            io.writes,
            runtime,
            &self.control,
            transfer,
            UpdateOptions {
                class: class(self.initial_class)?,
                recover: updating,
            },
            updating,
        )
        .map_err(|source| {
            ExecutionError::Flash(FlashError::Update {
                pass: FlashPass::Initial,
                source,
            })
        })?;
        execution::verify(io.reads, self.first_kernel_image(), FlashPass::Initial)
            .map_err(ExecutionError::Flash)?;
        let mut observed = target_identity(io.reads, self.target.normal(), FlashPass::Initial)?;
        let mut normal_verified = normal_readback(
            io.reads,
            &self.target.normal().image,
            self.normal_region,
            FlashPass::Initial,
            runtime,
        )?;
        let mut completed_passes = 1;
        if let Some(kernel) = self.restoration_kernel_transfer() {
            let pass = FlashPass::Restoration;
            runtime
                .check_pass(pass)
                .map_err(|source| ExecutionError::Flash(FlashError::Preflight { pass, source }))?;
            let control = self
                .restoration_receiver()
                .expect("prepared restoration")
                .control();
            check_receiver(
                io.reads,
                self.target.kernel(),
                &control,
                ExecutionMode::Flash,
                pass,
            )?;
            let mut storage = [Segment::PLACEHOLDER; 3];
            let transfer = plan(
                Some(kernel),
                self.normal_transfer(),
                transport::detect(self.first_kernel_image()),
                &mut storage,
            )?;
            drive::execute_plan(
                io.writes,
                runtime,
                &control,
                transfer,
                UpdateOptions {
                    class: class(self.target_class)?,
                    recover: false,
                },
            )
            .map_err(|source| ExecutionError::Flash(FlashError::Update { pass, source }))?;
            execution::verify(io.reads, self.final_kernel_image(), pass)
                .map_err(ExecutionError::Flash)?;
            observed = target_identity(io.reads, self.target.normal(), pass)?;
            normal_verified = normal_readback(
                io.reads,
                &self.target.normal().image,
                self.normal_region,
                pass,
                runtime,
            )?;
            completed_passes += 1;
        }
        Ok(FlashOutcome {
            kernel_verified: true,
            normal_verified,
            completed_passes,
            identity: observed,
        })
    }
}
impl PreparedNormal {
    /// Flash Normal through the complete receiver-owned procedure.
    pub fn flash<R, W, H>(
        &self,
        io: FlashTransport<'_, R, W>,
        runtime: &mut H,
    ) -> Result<FlashOutcome, ExecutionError<W::Error>>
    where
        W: Transport,
        R: Transport<Error = W::Error>,
        H: ExecutionRuntime<W::Error>,
    {
        self.execute(io, runtime)
    }

    /// Execute Normal-only with required startup migration and exact target
    /// startup confirmation. Unavailable readback is retained in the outcome.
    pub fn execute<R, W, H>(
        &self,
        io: FlashTransport<'_, R, W>,
        runtime: &mut H,
    ) -> Result<FlashOutcome, ExecutionError<W::Error>>
    where
        W: Transport,
        R: Transport<Error = W::Error>,
        H: ExecutionRuntime<W::Error>,
    {
        let installed = self.installed_kernel.as_ref().ok_or(ExecutionError::Plan(
            "installed Kernel evidence unavailable",
        ))?;
        class::<W::Error>(self.initial_class)?;
        let mut storage = [Segment::PLACEHOLDER; 3];
        plan::<W::Error>(
            None,
            self.normal_transfer(),
            transport::detect(&installed.image),
            &mut storage,
        )?;
        runtime.check_pass(FlashPass::Initial).map_err(|source| {
            ExecutionError::Flash(FlashError::Preflight {
                pass: FlashPass::Initial,
                source,
            })
        })?;
        check_receiver(
            io.reads,
            installed,
            &self.control,
            ExecutionMode::Flash,
            FlashPass::Initial,
        )?;
        if let Some(setting) = self.startup_setting {
            return crate::startup::migration::execute(
                io.writes,
                setting.parameter,
                setting.value,
                |writes| {
                    self.execute_normal(
                        FlashTransport {
                            reads: io.reads,
                            writes,
                        },
                        runtime,
                    )
                },
            )
            .map_err(|source| ExecutionError::Startup(Box::new(source)));
        }
        self.execute_normal(io, runtime)
    }
    fn execute_normal<R, W, H>(
        &self,
        io: FlashTransport<'_, R, W>,
        runtime: &mut H,
    ) -> Result<FlashOutcome, ExecutionError<W::Error>>
    where
        W: Transport,
        R: Transport<Error = W::Error>,
        H: ExecutionRuntime<W::Error>,
    {
        let pass = FlashPass::Initial;
        runtime
            .check_pass(pass)
            .map_err(|source| ExecutionError::Flash(FlashError::Preflight { pass, source }))?;
        let installed = self
            .installed_kernel
            .as_ref()
            .expect("checked installed Kernel");
        check_receiver(
            io.reads,
            installed,
            &self.control,
            ExecutionMode::Flash,
            pass,
        )?;
        drive::execute_update(
            io.writes,
            runtime,
            &self.control,
            drive::UpdateTransfer {
                kernel: None,
                normal: self.normal_transfer(),
            },
            UpdateOptions {
                class: class(self.initial_class)?,
                recover: false,
            },
        )
        .map_err(|source| ExecutionError::Flash(FlashError::Update { pass, source }))?;
        let identity = target_identity(io.reads, &self.normal, pass)?;
        let normal_verified = normal_readback(
            io.reads,
            &self.normal.image,
            self.normal_region,
            pass,
            runtime,
        )?;
        Ok(FlashOutcome {
            kernel_verified: false,
            normal_verified,
            completed_passes: 1,
            identity,
        })
    }
}

#[cfg(test)]
#[path = "execution_safe_tests.rs"]
mod tests;
