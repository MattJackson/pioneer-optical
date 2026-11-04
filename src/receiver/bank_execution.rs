//! Materialize a receipt-bound transition only from live storage, never a host
//! supplied control buffer. Source schema and installed bridge remain distinct.
use super::*;
use crate::startup::bank::{
    backup::{BackupReceipt, BankBackup},
    bridge, programmer,
};
use std::cell::Cell;

struct Capture {
    banks: [Vec<u8>; 2],
    base: u32,
    active: u32,
    receipt: BackupReceipt,
}
fn failure<E>(
    phase: &'static str,
    temporary: bool,
    bank_write: bool,
    source: ExecutionError<E>,
) -> ExecutionError<E> {
    ExecutionError::BankTransition {
        temporary_firmware: temporary,
        bank_write_started: bank_write,
        phase,
        source: Box::new(source),
    }
}
fn read_exact<T: Transport>(
    reads: &mut T,
    address: u32,
    bytes: &mut [u8],
) -> Result<(), ExecutionError<T::Error>> {
    let n = drive::read_memory(reads, address, bytes).map_err(|e| {
        ExecutionError::Startup(Box::new(crate::startup::migration::Error::Read(e)))
    })?;
    if n != bytes.len() {
        return Err(ExecutionError::Startup(Box::new(
            crate::startup::migration::Error::Read(drive::Error::Short {
                expected: bytes.len(),
                actual: n,
            }),
        )));
    }
    Ok(())
}
fn capture<T: Transport, H: ExecutionRuntime<T::Error>>(
    reads: &mut T,
    runtime: &mut H,
    source: &[u8],
    current: &[u8],
    target: &[u8],
    stage: FlashStage,
) -> Result<Capture, ExecutionError<T::Error>> {
    let mut pointers = [0; 8];
    read_exact(reads, 0x33e0, &mut pointers)?;
    let base = u32::from_be_bytes(pointers[..4].try_into().unwrap());
    let active = u32::from_be_bytes(pointers[4..].try_into().unwrap());
    if !matches!(base, 0x5e0000 | 0x7d0000) || ![base, base + 0x10000].contains(&active) {
        return Err(ExecutionError::Plan(
            "live source bank geometry is not audited",
        ));
    }
    let mut banks = [vec![0; 0x10000], vec![0; 0x10000]];
    for (bank, bytes) in banks.iter_mut().enumerate() {
        for (part, chunk) in bytes.chunks_mut(0x8000).enumerate() {
            read_exact(reads, base + (bank * 0x10000 + part * 0x8000) as u32, chunk)?;
        }
    }
    let mut after = [0; 8];
    read_exact(reads, 0x33e0, &mut after)?;
    if pointers != after {
        return Err(ExecutionError::Plan(
            "source bank selection changed during capture",
        ));
    }
    let backup = BankBackup::capture(source, target, [&banks[0], &banks[1]], base, active)
        .map_err(|_| {
            ExecutionError::Plan("source bank capture failed audited conversion binding")
        })?;
    let backup = backup.bind_current_image(current).map_err(|_| {
        ExecutionError::Plan("current Normal does not match source schema or canonical bridge")
    })?;
    let receipt = runtime
        .persist_bank_backup(&backup)
        .map_err(|source| ExecutionError::Flash(FlashError::Preflight { stage, source }))?
        .filter(|receipt| backup.accepts(receipt))
        .ok_or(ExecutionError::Plan(
            "a matching durable full-bank backup receipt is required",
        ))?;
    Ok(Capture {
        banks,
        base,
        active,
        receipt,
    })
}
fn build<E>(
    source: &[u8],
    target: &[u8],
    capture: &Capture,
) -> Result<bridge::Bridge, ExecutionError<E>> {
    bridge::build(
        source,
        target,
        [&capture.banks[0], &capture.banks[1]],
        capture.base,
        capture.active,
        &capture.receipt,
    )
    .map_err(|_| {
        ExecutionError::Plan("bank bridge could not bind captured storage and durable receipt")
    })
}
struct ArmedWrites<'a, T> {
    transport: &'a mut T,
    attempted: &'a Cell<bool>,
}
impl<T: Transport> Transport for ArmedWrites<'_, T> {
    type Error = T::Error;
    fn exec(&mut self, command: &[u8], data: drive::Data<'_>) -> Result<usize, Self::Error> {
        if command == crate::cdb::enter_update() {
            self.attempted.set(true);
        }
        self.transport.exec(command, data)
    }
    fn sense(&self) -> Option<(u8, u8, u8)> {
        self.transport.sense()
    }
}

pub(super) fn execute<R, W, H>(
    update: &PreparedUpdate,
    io: FlashTransport<'_, R, W>,
    runtime: &mut H,
    mode: ExecutionMode,
) -> Result<FlashOutcome, ExecutionError<W::Error>>
where
    W: Transport,
    R: Transport<Error = W::Error>,
    H: ExecutionRuntime<W::Error>,
{
    let existing = update
        .bank_transition
        .as_ref()
        .is_some_and(|s| s.bank_bridge.is_some());
    execute_inner(update, io, runtime, mode).map_err(|e| {
        if existing {
            existing_bridge_error(e)
        } else {
            e
        }
    })
}
fn completed_bridge<E>(source: ExecutionError<E>) -> ExecutionError<E> {
    ExecutionError::AfterStage {
        completed: 1,
        source: Box::new(source),
    }
}
fn execute_inner<R, W, H>(
    update: &PreparedUpdate,
    io: FlashTransport<'_, R, W>,
    runtime: &mut H,
    _mode: ExecutionMode,
) -> Result<FlashOutcome, ExecutionError<W::Error>>
where
    W: Transport,
    R: Transport<Error = W::Error>,
    H: ExecutionRuntime<W::Error>,
{
    let source = update
        .bank_transition
        .as_ref()
        .expect("deferred bank transition");
    let original = source
        .installed_normal
        .as_ref()
        .ok_or(ExecutionError::Plan("source Normal schema unavailable"))?;
    let kernel = source
        .installed_kernel
        .as_ref()
        .ok_or(ExecutionError::Plan("source Kernel unavailable"))?;
    let schema = source
        .source_schema()
        .ok_or(ExecutionError::Plan("original source schema unavailable"))?;
    let target = &update.target.normal().image;
    preflight_stages(update.stages(), io.reads)?;
    // A native bank writer requires running Normal even when the outer request
    // was called recovery; a loader cannot waive this live binding.
    update.stages[0].bind_stage(
        io.reads,
        runtime,
        ExecutionMode::Flash,
        FlashStage::Initial,
        None,
    )?;
    let region = super::super::preparation::normal_region(kernel, &original.image);
    if !normal_readback(
        io.reads,
        &original.image,
        region,
        FlashStage::Initial,
        runtime,
    )
    .map_err(|e| ExecutionError::BeforeWrite(Box::new(e)))?
    {
        return Err(ExecutionError::Plan(
            "exact source Normal readback required for bank transition",
        ));
    }
    let native = programmer::discover(schema).ok_or(ExecutionError::Plan(
        "source native programmer is not audited",
    ))?;
    let (ram, length) = native.runtime_interval();
    let mut code = vec![0; length];
    read_exact(io.reads, ram, &mut code)?;
    if !native.matches_runtime(&code) {
        return Err(ExecutionError::Plan(
            "live Normal programmer differs from audited vectors",
        ));
    }
    let before = capture(
        io.reads,
        runtime,
        schema,
        &original.image,
        target,
        FlashStage::Initial,
    )
    .map_err(|e| failure("pre-settings backup", false, false, e))?;
    let initial = build(schema, target, &before)?;
    let bridge_stage = source
        .prepare_persistent_bridge(initial.image(), update.stages[0].settings.clone())
        .map_err(|_| {
            ExecutionError::Plan("temporary Normal could not authenticate for the source Kernel")
        })?;
    let kernel_wire = kernel
        .repack(&kernel.image)
        .ok_or(ExecutionError::Plan("source Kernel artifact unavailable"))?;
    let normal_wire = bridge_stage
        .normal
        .repack(&bridge_stage.normal.image)
        .ok_or(ExecutionError::Plan("bridge Normal artifact unavailable"))?;
    let artifact = crate::envelope::Update::load(&kernel_wire, &normal_wire)
        .map_err(|_| ExecutionError::Plan("temporary firmware artifact failed pair validation"))?;
    if !runtime.persist_bank_bridge(&artifact).map_err(|source| {
        ExecutionError::Flash(FlashError::Preflight {
            stage: FlashStage::Initial,
            source,
        })
    })? {
        return Err(ExecutionError::Plan(
            "durable temporary firmware artifact is required",
        ));
    }
    let installed = bridge_stage
        .execute_stage(
            FlashTransport {
                reads: io.reads,
                writes: io.writes,
            },
            runtime,
            StageContext {
                mode: ExecutionMode::Flash,
                recovery: false,
                stage: FlashStage::Initial,
                apply_settings: true,
                previous: None,
            },
        )
        .and_then(FlashOutcome::require_complete)
        .map_err(|e| {
            failure(
                "temporary Normal installation",
                e.firmware_write_started(),
                false,
                e,
            )
        })?;
    verify_kernel(io.reads, &kernel.image, FlashStage::Initial, runtime).map_err(|e| {
        failure(
            "temporary Kernel continuity",
            true,
            false,
            completed_bridge(e),
        )
    })?;
    read_exact(io.reads, ram, &mut code).map_err(|e| {
        failure(
            "temporary programmer binding",
            true,
            false,
            completed_bridge(e),
        )
    })?;
    if !native.matches_runtime(&code) {
        return Err(failure(
            "temporary programmer binding",
            true,
            false,
            completed_bridge(ExecutionError::Plan(
                "live temporary Normal programmer differs from audited vectors",
            )),
        ));
    }
    // Bank mutation never runs inside the A0 transaction above. Once this
    // temporary firmware is installed, later failures retain it and the backup.
    let after = capture(
        io.reads,
        runtime,
        schema,
        bridge_stage.normal_image(),
        target,
        FlashStage::Continuation(1),
    )
    .map_err(|e| failure("post-settings backup", true, false, completed_bridge(e)))?;
    let armed = build(schema, target, &after)
        .map_err(|e| failure("fresh bridge binding", true, false, completed_bridge(e)))?;
    if armed.image() != bridge_stage.normal_image() {
        return Err(failure(
            "fresh bridge binding",
            true,
            false,
            completed_bridge(ExecutionError::Plan(
                "fresh bank capture changed the installed bridge image",
            )),
        ));
    }
    let mut final_stages = update.stages.clone();
    // Rebind only after exact bridge readback. Its changed FF handler is not
    // permission to substitute the target image for the original source schema.
    final_stages[0].receiver.installed_normal = Some(bridge_stage.normal.clone());
    final_stages[0].entry_control = Some(*armed.control());
    for stage in &mut final_stages {
        stage.settings = crate::settings::update::Plan::default();
    }
    let attempted = Cell::new(false);
    let mut writes = ArmedWrites {
        transport: io.writes,
        attempted: &attempted,
    };
    let mut previous = installed;
    for (index, stage) in final_stages.iter().enumerate() {
        let previous_normal = if index == 0 {
            &bridge_stage.normal
        } else {
            &final_stages[index - 1].normal
        };
        match stage.execute_stage(
            FlashTransport {
                reads: io.reads,
                writes: &mut writes,
            },
            runtime,
            StageContext {
                mode: ExecutionMode::Flash,
                recovery: false,
                stage: FlashStage::at(index + 1),
                apply_settings: false,
                previous: Some((previous_normal, &previous.identity)),
            },
        ) {
            Ok(mut outcome) => {
                outcome.completed_stages = index + 2;
                previous = outcome;
            }
            Err(e) => {
                return Err(failure(
                    "target handoff",
                    true,
                    attempted.get(),
                    ExecutionError::AfterStage {
                        completed: index + 1,
                        source: Box::new(e),
                    },
                ))
            }
        }
    }
    Ok(previous)
}
