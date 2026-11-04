//! Complete receiver-owned execution. Host callbacks enforce host policy only.
use super::{
    execution, transport, FlashError, FlashStage, FlashTransport, PreparedNormal, PreparedStage,
    PreparedUpdate,
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
    /// Persist the complete source-bank backup atomically, sync its file and
    /// directory, then return a receipt from byte-exact persisted readback.
    /// The default supplies no receipt and cannot authorize bank mutation.
    /// This callback has no effect until an explicit bank transition invokes it.
    fn persist_bank_backup(
        &mut self,
        _backup: &crate::startup::bank::backup::BankBackup,
    ) -> Result<Option<crate::startup::bank::backup::BackupReceipt>, E> {
        Ok(None)
    }
    /// Persist the exact temporary Normal artifact before installing it. The
    /// default refuses operations which could leave temporary firmware behind.
    fn persist_bank_bridge(&mut self, _pair: &crate::envelope::Update) -> Result<bool, E> {
        Ok(false)
    }
    /// Check host conditions (for example, an empty tray) before each stage.
    fn check_stage(&mut self, stage: FlashStage) -> Result<(), E>;
    /// A component comparison completed; emitted before any later failure.
    fn verified(&mut self, _pass: FlashStage, _role: crate::Role, _matched: bool) {}
    /// The device responded after transfer. This alone does not prove startup.
    fn observed_identity(&mut self, _pass: FlashStage, _identity: &Identity) {}
    /// Normal runtime and receiver continuity were confirmed.
    fn startup_confirmed(&mut self, _pass: FlashStage) {}
    /// A component could not be fully read back. This is evidence for a
    /// qualified outcome, never permission to ignore a readable mismatch.
    fn verification_unavailable(
        &mut self,
        _pass: FlashStage,
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
    /// Number of successfully completed stages.
    pub completed_stages: usize,
    /// Observed identity after runtime/receiver confirmation; branding is informational.
    pub identity: Identity,
}

impl FlashOutcome {
    fn require_complete<E>(self) -> Result<Self, ExecutionError<E>> {
        if self.normal_verified {
            Ok(self)
        } else {
            Err(ExecutionError::VerificationIncomplete(self))
        }
    }
}

/// Failure of a complete operation. A readable mismatch is never downgraded to
/// limited verification. No failing write is retried.
#[derive(Debug)]
#[non_exhaustive]
pub enum ExecutionError<E> {
    /// A read-only preflight failed before this operation attempted any mutation.
    BeforeWrite(Box<ExecutionError<E>>),
    /// A deferred bank transition failed; retain its backup and temporary image.
    BankTransition {
        /// Exact temporary Normal may already be installed.
        temporary_firmware: bool,
        /// The armed FF command may have attempted persistent-bank mutation.
        bank_write_started: bool,
        /// Bank-transition boundary which failed.
        phase: &'static str,
        /// Original failure, including transport diagnostics.
        source: Box<ExecutionError<E>>,
    },
    /// A later transition failed after earlier stages already changed firmware.
    AfterStage {
        /// Number of stages verified before this failure.
        completed: usize,
        /// The failing stage's original error and diagnostics.
        source: Box<ExecutionError<E>>,
    },
    /// The target started, but Normal readback was unavailable. Retains the
    /// completed operation's evidence; a readable mismatch is a different error.
    VerificationIncomplete(FlashOutcome),
    /// Firmware did not establish an unambiguous executable plan.
    Plan(&'static str),
    /// Identity could not be obtained at a required boundary.
    IdentityRead {
        /// Stage whose boundary could not be checked.
        stage: FlashStage,
        /// Whether this was post-transfer target confirmation.
        target: bool,
        /// Command failure.
        source: drive::Error<E>,
    },
    /// Identity did not match the firmware expected at this boundary.
    IdentityMismatch {
        /// Stage whose boundary did not match.
        stage: FlashStage,
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
        /// Stage being verified.
        stage: FlashStage,
        /// First differing drive address.
        address: u32,
    },
}
impl<E: core::fmt::Debug> core::fmt::Display for ExecutionError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BeforeWrite(source) => write!(f, "before update writes: {source}"),
            Self::BankTransition { phase, temporary_firmware, source, .. } => write!(f, "bank transition {phase} (temporary firmware installed: {temporary_firmware}): {source}"),
            Self::AfterStage { completed, source } => {
                write!(f, "after {completed} completed update stages: {source}")
            }
            Self::VerificationIncomplete(_) => {
                f.write_str("target firmware started, but complete Normal readback is unavailable")
            }
            Self::Plan(reason) => {
                write!(f, "update plan refused before firmware transfer: {reason}")
            }
            Self::IdentityRead { stage, source, .. } => {
                write!(f, "{stage:?} required identity read: {source}")
            }
            Self::IdentityMismatch {
                stage,
                observed,
                target,
            } => write!(
                f,
                "{stage:?} {} identity mismatch: {} revision {}, platform {}, Kernel {}, Normal {}",
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
            Self::NormalMismatch { stage, address } => {
                write!(
                    f,
                    "{stage:?} target Normal readback differs at {address:#x}"
                )
            }
        }
    }
}
impl<E: core::fmt::Debug + 'static> std::error::Error for ExecutionError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::BeforeWrite(source)
            | Self::BankTransition { source, .. }
            | Self::AfterStage { source, .. } => Some(source),
            Self::IdentityRead { source, .. } => Some(source),
            Self::Flash(source) => Some(source),
            Self::Startup(source) => Some(source),
            _ => None,
        }
    }
}

impl<E> ExecutionError<E> {
    /// Whether a temporary bank bridge may remain installed after this failure.
    pub fn temporary_bank_bridge(&self) -> bool {
        match self {
            Self::BankTransition {
                temporary_firmware,
                source,
                ..
            } => *temporary_firmware || source.temporary_bank_bridge(),
            Self::BeforeWrite(source) | Self::AfterStage { source, .. } => {
                source.temporary_bank_bridge()
            }
            Self::Startup(error) => match error.as_ref() {
                crate::startup::migration::Error::Preflight(source)
                | crate::startup::migration::Error::Flash { source, .. } => {
                    source.temporary_bank_bridge()
                }
                _ => false,
            },
            _ => false,
        }
    }
    /// Completed transitions retained by the executor, even when the next
    /// stage fails before its first command or host progress callback.
    pub fn completed_stages(&self) -> usize {
        match self {
            Self::BankTransition { source, .. } => source.completed_stages(),
            Self::AfterStage { completed, .. } => *completed,
            Self::VerificationIncomplete(outcome) => outcome.completed_stages,
            Self::Startup(error) => match error.as_ref() {
                crate::startup::migration::Error::Preflight(source)
                | crate::startup::migration::Error::Flash { source, .. } => {
                    source.completed_stages()
                }
                _ => 0,
            },
            _ => 0,
        }
    }
    /// Firmware transfer may have been attempted; conservative for uncertain entry failures.
    pub fn firmware_write_started(&self) -> bool {
        match self {
            Self::BeforeWrite(_) => false,
            Self::BankTransition { source, .. } => source.firmware_write_started(),
            Self::AfterStage { .. } => true,
            Self::VerificationIncomplete(_) => true,
            Self::Plan(_) => false,
            Self::IdentityRead { stage, target, .. }
            | Self::IdentityMismatch { stage, target, .. } => {
                *target || stage.completed_stages() > 0
            }
            Self::NormalMismatch { .. } => true,
            Self::Flash(error) => match error {
                FlashError::Preflight { stage, .. }
                | FlashError::DescriptorRead { stage, .. }
                | FlashError::DescriptorChanged { stage }
                | FlashError::DescriptorMismatch { stage }
                | FlashError::UnsupportedTransport { stage } => stage.completed_stages() > 0,
                FlashError::Update {
                    source: drive::UpdateError::InvalidSpan { .. },
                    stage,
                } => stage.completed_stages() > 0,
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
        if matches!(self, Self::BeforeWrite(_)) {
            return false;
        }
        if let Self::BankTransition {
            bank_write_started,
            source,
            ..
        } = self
        {
            return *bank_write_started || source.write_started();
        }
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
            Self::BeforeWrite(_) => "preflight",
            Self::BankTransition { phase, .. } => phase,
            Self::AfterStage { source, .. } => source.phase(),
            Self::VerificationIncomplete(_) => "Normal readback",
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
    /// Follows the typed cause, but never reports a pre-write category once
    /// firmware may have been written.
    fn kind(&self) -> crate::operation::IssueKind {
        use crate::operation::IssueKind;
        use crate::startup::migration::{Error as Migration, Rollback};
        let mut written = self.firmware_write_started();
        let kind = match self {
            Self::AfterStage { source, .. } => source.kind(),
            Self::IdentityRead { target: true, .. }
            | Self::IdentityMismatch { target: true, .. } => IssueKind::Verification,
            Self::Flash(error) => error.kind(),
            Self::Startup(error) => match error.as_ref() {
                Migration::Preflight(source) => source.kind(),
                Migration::Flash { rollback, .. } if rollback.failed() => IssueKind::Update,
                Migration::Flash {
                    source, rollback, ..
                } => {
                    written |= matches!(rollback, Rollback::UnsafeAfterFirmwareWrite);
                    source.kind()
                }
                other => other.kind(),
            },
            _ => crate::error_codes::kind_for_code(self.code()),
        };
        if written && !matches!(kind, IssueKind::Update | IssueKind::Verification) {
            IssueKind::Update
        } else {
            kind
        }
    }
    fn code(&self) -> &'static str {
        match self {
            Self::BeforeWrite(source)
            | Self::BankTransition { source, .. }
            | Self::AfterStage { source, .. } => source.code(),
            Self::VerificationIncomplete(_) => "pioneer.execute.verification_incomplete",
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
    stage: FlashStage,
    target: bool,
) -> Result<Identity, ExecutionError<T::Error>> {
    drive::identify(t).map_err(|source| ExecutionError::IdentityRead {
        stage,
        source,
        target,
    })
}
fn optical(id: &Identity, firmware: &Envelope) -> bool {
    // OEM-branded drives run this protocol too. Bind the observed vendor to
    // the supplied firmware; the decoded Kernel establishes the dialect.
    id.device_type() == 5
        && !firmware.info().vendor.is_empty()
        && firmware.info().vendor == id.vendor()
}
fn loader(id: &Identity, firmware: &Envelope) -> bool {
    optical(id, firmware)
        && id.revision() == "0000"
        && id.normal_tag().is_empty()
        && !id.kernel_tag().is_empty()
}
fn receiver_matches(id: &Identity, kernel: &Envelope) -> bool {
    let info = kernel.info();
    optical(id, kernel)
        && id.platform() == info.hardware_version
        && id.kernel_tag() == info.kernel_version
}
fn check_receiver<T: Transport>(
    t: &mut T,
    kernel: &Envelope,
    control: &super::Control,
    mode: ExecutionMode,
    stage: FlashStage,
) -> Result<(bool, Identity), ExecutionError<T::Error>> {
    let id = identity(t, stage, false)?;
    // Loader mode may expose a partially installed Kernel identity. Recovery
    // uses explicit Current firmware evidence for that loader's protocol.
    if mode == ExecutionMode::Recovery && loader(&id, kernel) {
        return Ok((true, id));
    }
    if !receiver_matches(&id, kernel)
        || id.revision().starts_with("000")
        || id.normal_tag().is_empty()
    {
        return Err(ExecutionError::IdentityMismatch {
            stage,
            observed: id,
            target: false,
        });
    }
    execution::bind(t, control, stage).map_err(ExecutionError::Flash)?;
    Ok((false, id))
}
// Enclosures and envelope headers may rename identical firmware. Binding uses
// physical continuity and receiver fields; exact component readback proves the
// requested firmware. Never use vendor/model/revision equality as that proof.
fn target_identity<T: Transport, H: ExecutionRuntime<T::Error>>(
    t: &mut T,
    target: &Envelope,
    stage: FlashStage,
    serial: &str,
    runtime: &mut H,
) -> Result<Identity, ExecutionError<T::Error>> {
    let id = identity(t, stage, true)?;
    runtime.observed_identity(stage, &id);
    let info = target.info();
    if id.device_type() != 5
        || (!serial.is_empty() && id.serial() != serial)
        || id.platform() != info.hardware_version
        || id.kernel_tag() != info.kernel_version
        || id.normal_tag() != info.kernel_version
        || id.normal_tag().is_empty()
        || id.revision().is_empty()
        || id.revision().starts_with("000")
    {
        return Err(ExecutionError::IdentityMismatch {
            stage,
            observed: id,
            target: true,
        });
    }
    runtime.startup_confirmed(stage);
    Ok(id)
}
fn verify_kernel<T: Transport, H: ExecutionRuntime<T::Error>>(
    t: &mut T,
    expected: &[u8],
    stage: FlashStage,
    runtime: &mut H,
) -> Result<(), ExecutionError<T::Error>> {
    runtime.operation_progress(crate::operation::Progress::bytes(
        crate::operation::Phase::Verifying,
        crate::operation::Component::Kernel,
        0,
        expected.len(),
    ));
    match execution::verify(t, expected, stage) {
        Ok(()) => {
            runtime.operation_progress(crate::operation::Progress::bytes(
                crate::operation::Phase::Verifying,
                crate::operation::Component::Kernel,
                expected.len(),
                expected.len(),
            ));
            runtime.verified(stage, crate::Role::Kernel, true);
            Ok(())
        }
        Err(error) => {
            match &error {
                FlashError::ReadbackMismatch { .. } => {
                    runtime.verified(stage, crate::Role::Kernel, false)
                }
                _ => runtime.verification_unavailable(
                    stage,
                    crate::Role::Kernel,
                    None,
                    &"Kernel readback unavailable",
                ),
            }
            Err(ExecutionError::Flash(error))
        }
    }
}
fn normal_readback<T: Transport, H: ExecutionRuntime<T::Error>>(
    t: &mut T,
    expected: &[u8],
    region: Option<crate::envelope::NormalRegion>,
    stage: FlashStage,
    runtime: &mut H,
) -> Result<bool, ExecutionError<T::Error>> {
    let Some(region) = region else {
        runtime.verification_unavailable(
            stage,
            crate::Role::Normal,
            None,
            &"Kernel does not establish a supported Normal readback region",
        );
        return Ok(false);
    };
    let result = verify_normal_at(t, expected, region.address(), stage, runtime);
    match &result {
        Ok(true) => runtime.verified(stage, crate::Role::Normal, true),
        Err(ExecutionError::NormalMismatch { .. }) => {
            runtime.verified(stage, crate::Role::Normal, false)
        }
        _ => {}
    }
    result
}
fn verify_normal_at<T: Transport, H: ExecutionRuntime<T::Error>>(
    t: &mut T,
    expected: &[u8],
    base: u32,
    stage: FlashStage,
    runtime: &mut H,
) -> Result<bool, ExecutionError<T::Error>> {
    let mut buffer = [0; 0x8000];
    let mut complete = true;
    for (index, chunk) in expected.chunks(buffer.len()).enumerate() {
        runtime.operation_progress(crate::operation::Progress::bytes(
            crate::operation::Phase::Verifying,
            crate::operation::Component::Normal,
            index * buffer.len(),
            expected.len(),
        ));
        let address = base + (index * buffer.len()) as u32;
        let actual = &mut buffer[..chunk.len()];
        match drive::read_memory(t, address, actual) {
            Ok(n) => {
                // Even a short read must not hide a readable mismatch. Continue
                // later spans after inaccessible spans so all readable bytes count.
                let n = n.min(actual.len());
                if let crate::envelope::ByteComparison::Different { offset, .. } =
                    crate::envelope::compare_bytes(&chunk[..n], &actual[..n])
                {
                    return Err(ExecutionError::NormalMismatch {
                        stage,
                        address: address + offset as u32,
                    });
                }
                if n != chunk.len() {
                    runtime.verification_unavailable(
                        stage,
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
                runtime.verification_unavailable(stage, crate::Role::Normal, Some(address), &error);
                complete = false;
            }
        }
    }
    runtime.operation_progress(crate::operation::Progress::bytes(
        crate::operation::Phase::Verifying,
        crate::operation::Component::Normal,
        expected.len(),
        expected.len(),
    ));
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
    /// Execute and require complete Normal readback as well as startup.
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
        self.flash_completed(io, runtime)?.require_complete()
    }
    /// Execute while retaining unavailable Normal readback as limited evidence.
    pub fn flash_completed<R, W, H>(
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
    /// Execute the complete prepared sequence with per-stage settings and checks.
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
        if self.bank_transition.is_some() {
            bank_execution::execute(self, io, runtime, mode)
        } else {
            execute_stages(self.stages(), io, runtime, mode)
        }
    }
}
impl PreparedNormal {
    /// Execute and require complete Normal readback as well as startup.
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
        self.flash_completed(io, runtime)?.require_complete()
    }
    /// Execute while retaining unavailable Normal readback as limited evidence.
    pub fn flash_completed<R, W, H>(
        &self,
        io: FlashTransport<'_, R, W>,
        runtime: &mut H,
    ) -> Result<FlashOutcome, ExecutionError<W::Error>>
    where
        W: Transport,
        R: Transport<Error = W::Error>,
        H: ExecutionRuntime<W::Error>,
    {
        execute_stages(
            std::slice::from_ref(self.stage()),
            io,
            runtime,
            ExecutionMode::Flash,
        )
    }
    /// Execute the complete prepared sequence with per-stage settings and checks.
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
        execute_stages(
            std::slice::from_ref(self.stage()),
            io,
            runtime,
            ExecutionMode::Flash,
        )
    }
}
fn preflight_stages<E>(stages: &[PreparedStage]) -> Result<(), ExecutionError<E>> {
    // Validate the whole sequence before the first settings or firmware write.
    for stage in stages {
        let installed = stage
            .receiver
            .installed_kernel()
            .ok_or(ExecutionError::Plan(
                "installed Kernel evidence unavailable",
            ))?;
        class::<E>(installed.update_dialect())?;
        let mut storage = [Segment::PLACEHOLDER; 3];
        plan::<E>(
            stage.kernel_transfer(),
            stage.normal_transfer(),
            transport::detect(&installed.image),
            &mut storage,
        )?;
    }
    Ok(())
}

fn existing_bridge_error<E>(source: ExecutionError<E>) -> ExecutionError<E> {
    ExecutionError::BankTransition {
        temporary_firmware: true,
        bank_write_started: false,
        phase: "existing temporary Normal",
        source: Box::new(source),
    }
}
fn execute_stages<R, W, H>(
    stages: &[PreparedStage],
    io: FlashTransport<'_, R, W>,
    runtime: &mut H,
    mode: ExecutionMode,
) -> Result<FlashOutcome, ExecutionError<W::Error>>
where
    W: Transport,
    R: Transport<Error = W::Error>,
    H: ExecutionRuntime<W::Error>,
{
    let existing = stages
        .first()
        .is_some_and(|s| s.receiver.bank_bridge.is_some());
    execute_stages_inner(stages, io, runtime, mode).map_err(|e| {
        if existing {
            existing_bridge_error(e)
        } else {
            e
        }
    })
}
fn execute_stages_inner<R, W, H>(
    stages: &[PreparedStage],
    io: FlashTransport<'_, R, W>,
    runtime: &mut H,
    mode: ExecutionMode,
) -> Result<FlashOutcome, ExecutionError<W::Error>>
where
    W: Transport,
    R: Transport<Error = W::Error>,
    H: ExecutionRuntime<W::Error>,
{
    if stages.is_empty() {
        return Err(ExecutionError::Plan("empty update sequence"));
    }
    preflight_stages(stages)?;
    let mut result: Option<FlashOutcome> = None;
    for (index, stage) in stages.iter().enumerate() {
        // A marker-only intermediate already applied the same Normal's settings.
        // A source bridge has a different Normal and must apply the next plan.
        let settings = index == 0 || stages[index - 1].normal_image() != stage.normal_image();
        let next = stage.execute_stage(
            FlashTransport {
                reads: io.reads,
                writes: io.writes,
            },
            runtime,
            StageContext {
                mode: if index == 0 {
                    mode
                } else {
                    ExecutionMode::Flash
                },
                recovery: mode == ExecutionMode::Recovery,
                stage: FlashStage::at(index),
                apply_settings: settings,
                previous: index.checked_sub(1).map(|i| {
                    (
                        &stages[i].normal,
                        &result.as_ref().expect("completed stage").identity,
                    )
                }),
            },
        );
        match next {
            Ok(mut outcome) => {
                outcome.completed_stages = index + 1;
                result = Some(outcome);
            }
            Err(source) if index > 0 => {
                return Err(ExecutionError::AfterStage {
                    completed: index,
                    source: Box::new(source),
                })
            }
            Err(source) => return Err(source),
        }
    }
    Ok(result.expect("nonempty prepared sequence"))
}
struct StageContext<'a> {
    mode: ExecutionMode,
    recovery: bool,
    stage: FlashStage,
    apply_settings: bool,
    previous: Option<(&'a Envelope, &'a Identity)>,
}
impl PreparedStage {
    fn execute_stage<R, W, H>(
        &self,
        io: FlashTransport<'_, R, W>,
        runtime: &mut H,
        context: StageContext<'_>,
    ) -> Result<FlashOutcome, ExecutionError<W::Error>>
    where
        W: Transport,
        R: Transport<Error = W::Error>,
        H: ExecutionRuntime<W::Error>,
    {
        let StageContext {
            mode,
            recovery,
            stage,
            apply_settings,
            previous,
        } = context;
        // An unchanged Normal already completed its settings transaction. Keep
        // the established single continuation binding before its next transfer.
        if previous.is_some() && !apply_settings {
            return self.transfer_stage(io, runtime, false, recovery, stage, previous);
        }
        let (updating, _) = self.bind_stage(io.reads, runtime, mode, stage, previous)?;
        if !updating && apply_settings && !self.settings.entries().is_empty() {
            return self
                .settings
                .execute(io.writes, |writes| {
                    self.transfer_stage(
                        FlashTransport {
                            reads: io.reads,
                            writes,
                        },
                        runtime,
                        false,
                        recovery,
                        stage,
                        previous,
                    )
                })
                .map_err(|source| ExecutionError::Startup(Box::new(source)));
        }
        self.transfer_stage(io, runtime, updating, recovery, stage, previous)
    }
    fn bind_stage<T: Transport, H: ExecutionRuntime<T::Error>>(
        &self,
        reads: &mut T,
        runtime: &mut H,
        mode: ExecutionMode,
        stage: FlashStage,
        previous: Option<(&Envelope, &Identity)>,
    ) -> Result<(bool, Identity), ExecutionError<T::Error>> {
        runtime
            .check_stage(stage)
            .map_err(|source| ExecutionError::Flash(FlashError::Preflight { stage, source }))?;
        let control = self.receiver.control();
        if let Some((normal, identity)) = previous {
            let observed = target_identity(reads, normal, stage, identity.serial(), runtime)?;
            execution::bind(reads, &control, stage).map_err(ExecutionError::Flash)?;
            Ok((false, observed))
        } else {
            check_receiver(
                reads,
                self.receiver
                    .installed_kernel()
                    .expect("validated installed Kernel"),
                &control,
                mode,
                stage,
            )
        }
    }
    fn transfer_stage<R, W, H>(
        &self,
        io: FlashTransport<'_, R, W>,
        runtime: &mut H,
        updating: bool,
        recovery: bool,
        stage: FlashStage,
        previous: Option<(&Envelope, &Identity)>,
    ) -> Result<FlashOutcome, ExecutionError<W::Error>>
    where
        W: Transport,
        R: Transport<Error = W::Error>,
        H: ExecutionRuntime<W::Error>,
    {
        let installed = self
            .receiver
            .installed_kernel()
            .expect("validated installed Kernel");
        let control = self
            .entry_control
            .unwrap_or_else(|| self.receiver.control());
        let (_, before) = self.bind_stage(
            io.reads,
            runtime,
            if updating {
                ExecutionMode::Recovery
            } else {
                ExecutionMode::Flash
            },
            stage,
            previous,
        )?;
        let mut storage = [Segment::PLACEHOLDER; 3];
        let transfer = plan(
            self.kernel_transfer(),
            self.normal_transfer(),
            transport::detect(&installed.image),
            &mut storage,
        )?;
        let options = UpdateOptions {
            class: class(installed.update_dialect())?,
            recover: updating,
        };
        let written = if recovery {
            drive::execute_plan_with_entry_for_recovery(
                io.writes, runtime, &control, transfer, options, updating,
            )
        } else {
            drive::execute_plan_with_entry(
                io.writes, runtime, &control, transfer, options, updating,
            )
        };
        written.map_err(|source| ExecutionError::Flash(FlashError::Update { stage, source }))?;
        if let Some(kernel) = self.kernel_image() {
            verify_kernel(io.reads, kernel, stage, runtime)?;
        }
        let observed = target_identity(io.reads, &self.normal, stage, before.serial(), runtime)?;
        let normal_verified = normal_readback(
            io.reads,
            self.normal_image(),
            self.normal_region,
            stage,
            runtime,
        )?;
        Ok(FlashOutcome {
            kernel_verified: self.kernel.is_some(),
            normal_verified,
            completed_stages: 1,
            identity: observed,
        })
    }
}

#[cfg(test)]
#[path = "execution_safe_tests.rs"]
mod tests;

#[path = "bank_execution.rs"]
mod bank_execution;
