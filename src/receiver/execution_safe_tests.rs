use super::*;
use crate::{cdb, drive::Data, envelope::Update, receiver::Receiver};
use std::{cell::RefCell, rc::Rc, time::Duration};

fn checksum(bytes: &mut [u8]) {
    let end = bytes.len() - 4;
    bytes[end..].fill(0);
    let sum = bytes.chunks_exact(4).fold(0u32, |s, w| {
        s.wrapping_add(u32::from_be_bytes(w.try_into().unwrap()))
    });
    bytes[end..].copy_from_slice(&sum.wrapping_neg().to_be_bytes());
}
fn fixture(gated: bool, marker: u8) -> Update {
    let original = super::super::preparation::tests::update(gated, marker, 0x12, true);
    let mut kernel = original.kernel().image.clone();
    let mut normal = original.normal().image.clone();
    normal[..16].copy_from_slice(b"PIONEER BD-RW   ");
    checksum(&mut normal);
    let mut normal_wire = original.normal().repack(&normal).unwrap();
    let mut key = [0; 20];
    key[19] = 5;
    crate::envelope::signature::SigningKey::from_bytes(key)
        .unwrap()
        .sign_normal(&mut normal_wire)
        .unwrap();
    // Independent H8 descriptor/extent instructions. They establish readback
    // geometry rather than making the mock's fixed memory map the authority.
    let descriptor = "18 bb 1a 91 0c b9 78 10 6a 2a 00 41 00 00 78 10 6a 28 00 40 62 00 1c 8a 47 04 5e 40 10 20 0a 0b ab 10 45 de";
    let extent = "1a a2 7a 01 00 40 00 00 01 00 6b 23 00 41 00 14 7a 13 00 41 00 00 40 06 01 00 6d 10 0a 82 1f b1 46 f6";
    for (at, hex) in [(0x6000, descriptor), (0x6100, extent)] {
        let bytes: Vec<u8> = hex
            .split_whitespace()
            .map(|b| u8::from_str_radix(b, 16).unwrap())
            .collect();
        kernel[at..at + bytes.len()].copy_from_slice(&bytes);
    }
    kernel[0x6200..0x6210].copy_from_slice(&normal[..16]);
    checksum(&mut kernel);
    Update::load(&original.kernel().repack(&kernel).unwrap(), &normal_wire).unwrap()
}
#[derive(Default, Clone)]
struct State {
    installed_id: Option<Identity>,
    target_id: Option<Identity>,
    descriptor: Vec<u8>,
    normal: Vec<u8>,
    stage_normals: Vec<Vec<u8>>,
    kernels: Vec<Vec<u8>>,
    parameter: u16,
    parameter_writes: Vec<u16>,
    mechanism_parameter: u16,
    mechanism_parameter_reads: usize,
    entries: usize,
    finishes: usize,
    writes: usize,
    fail_write: Option<usize>,
    loader: bool,
    stay_loader: bool,
    descriptor_reads: usize,
    change_descriptor_at: Option<usize>,
    wrong_target: Option<usize>,
    unreadable_normal: bool,
    corrupt_normal: bool,
    unsupported_medium: Option<(u8, u8, u8)>,
    last_sense: Option<(u8, u8, u8)>,
    readback_reads: usize,
}
fn id(envelope: &Envelope) -> Identity {
    let info = envelope.info();
    let mut inquiry = [b' '; crate::INQUIRY_LEN];
    inquiry[0] = 5;
    inquiry[8..16].copy_from_slice(format!("{:<8}", info.vendor).as_bytes());
    let product = format!("BD-RW   {}", info.model);
    inquiry[16..32].copy_from_slice(format!("{product:<16}").as_bytes());
    inquiry[32..36].copy_from_slice(&format!("{:<4}", info.revision).as_bytes()[..4]);
    let mut vendor = [b' '; crate::IDENTITY_LEN];
    vendor[16..24].copy_from_slice(format!("{:<8}", info.hardware_version).as_bytes());
    vendor[24..32].copy_from_slice(format!("{:<8}", info.kernel_version).as_bytes());
    vendor[32..40].copy_from_slice(format!("{:<8}", info.kernel_version).as_bytes());
    Identity::parse(&inquiry, &vendor).unwrap()
}
fn setup(restore: bool) -> (PreparedUpdate, Rc<RefCell<State>>) {
    setup_updates(fixture(restore, 1), fixture(false, 0xff))
}
fn setup_updates(installed: Update, target: Update) -> (PreparedUpdate, Rc<RefCell<State>>) {
    setup_updates_policy(installed, target, false)
}
fn setup_updates_policy(
    installed: Update,
    target: Update,
    bypass: bool,
) -> (PreparedUpdate, Rc<RefCell<State>>) {
    let receiver = Receiver::from_installed(&installed).unwrap();
    let plan = if bypass {
        receiver.prepare_without_family_check(target.clone())
    } else {
        receiver.prepare(target.clone())
    }
    .unwrap();
    let layout = target
        .kernel()
        .normal_layout()
        .expect("fixture Normal layout");
    layout
        .validate(&target.normal().image)
        .expect("fixture Normal body");
    let kernels = plan
        .stages()
        .iter()
        .map(|stage| stage.kernel_image().unwrap().to_vec())
        .collect();
    let state = Rc::new(RefCell::new(State {
        installed_id: Some(id(installed.normal())),
        target_id: Some(id(target.normal())),
        descriptor: installed.normal().image[..16].to_vec(),
        normal: target.normal().image.clone(),
        kernels,
        parameter: 0xfe24,
        ..State::default()
    }));
    (plan, state)
}
struct Port(Rc<RefCell<State>>);
impl Transport for Port {
    type Error = &'static str;
    fn exec(&mut self, command: &[u8], data: Data<'_>) -> Result<usize, Self::Error> {
        let mut s = self.0.borrow_mut();
        if command == cdb::knock() {
            return Ok(0);
        }
        match data {
            Data::Out(bytes) => {
                if command == cdb::write_parameter_word(0x28f).unwrap() {
                    return Err("a read-only mechanism prerequisite was written");
                }
                s.writes += 1;
                if s.fail_write == Some(s.writes) {
                    return Err("write failed");
                }
                if command == cdb::write_parameter_word(0x9f).unwrap() {
                    s.parameter = u16::from_be_bytes(bytes.try_into().unwrap());
                    let value = s.parameter;
                    s.parameter_writes.push(value);
                } else if command == cdb::enter_update() {
                    s.entries += 1;
                    s.loader = true;
                } else if command == cdb::finish() {
                    s.finishes += 1;
                    if let Some(normal) = s.stage_normals.get(s.finishes - 1).cloned() {
                        s.descriptor = normal[..16].to_vec();
                        s.normal = normal;
                    }
                    s.loader = s.stay_loader;
                }
                Ok(bytes.len())
            }
            Data::In(bytes) => {
                if command == cdb::test_unit_ready()
                    && s.unsupported_medium.is_some()
                    && s.finishes > 0
                {
                    s.last_sense = s.unsupported_medium;
                    return Err("unsupported medium");
                }
                if command[0] == 0x3c && s.finishes > 0 {
                    s.readback_reads += 1;
                }
                if command == cdb::read_parameter_word(0x9f).unwrap() {
                    bytes.copy_from_slice(&s.parameter.to_be_bytes());
                } else if command == cdb::read_parameter_word(0x28f).unwrap() {
                    s.mechanism_parameter_reads += 1;
                    bytes.copy_from_slice(&s.mechanism_parameter.to_be_bytes());
                } else if command[0] == 0x12 || command == cdb::vendor_identity() {
                    let identity = if s.finishes == 0 {
                        s.installed_id.as_ref().unwrap()
                    } else {
                        s.target_id.as_ref().unwrap()
                    };
                    let mut inquiry = *identity.inquiry_bytes();
                    let mut vendor = *identity.vendor_bytes();
                    if s.loader {
                        inquiry[32..36].copy_from_slice(b"0000");
                        vendor[32..40].fill(b' ');
                    }
                    if s.finishes > 0 {
                        match s.wrong_target {
                            Some(0) => inquiry[31] = b'X',
                            Some(1) => inquiry[35] = b'9',
                            Some(2) => vendor[32] = b'X',
                            Some(3) => vendor[16] = b'X',
                            Some(4) => inquiry[8..16].copy_from_slice(b"Slimtype"),
                            Some(5) => vendor[0] = b'X',
                            _ => {}
                        }
                    }
                    if command[0] == 0x12 {
                        let len = bytes.len().min(inquiry.len());
                        bytes[..len].copy_from_slice(&inquiry[..len]);
                    } else {
                        bytes.copy_from_slice(&vendor[..bytes.len()]);
                    }
                } else if command[0] == 0x3c {
                    let address = u32::from_be_bytes([0, command[3], command[4], command[5]]);
                    if address == 0x410000 && bytes.len() == 16 {
                        s.descriptor_reads += 1;
                        bytes.copy_from_slice(&s.descriptor);
                        if s.change_descriptor_at == Some(s.descriptor_reads) {
                            bytes[0] ^= 1;
                        }
                    } else if address < 0x410000 {
                        let offset = (address - crate::image::KERNEL_BASE) as usize;
                        let kernel = &s.kernels[s.finishes - 1];
                        bytes.copy_from_slice(&kernel[offset..offset + bytes.len()]);
                    } else {
                        if s.unreadable_normal {
                            return Err("protected read unavailable");
                        }
                        let offset = (address - 0x410000) as usize;
                        bytes.copy_from_slice(&s.normal[offset..offset + bytes.len()]);
                        if s.corrupt_normal {
                            bytes[100] ^= 1;
                        }
                    }
                } else {
                    assert!(
                        command == cdb::test_unit_ready()
                            || command == cdb::get_event_status()
                            || command == cdb::request_sense(18)
                    );
                }
                Ok(bytes.len())
            }
            Data::None => panic!("unexpected command"),
        }
    }
    fn sense(&self) -> Option<(u8, u8, u8)> {
        self.0.borrow().last_sense
    }
}
#[derive(Default)]
struct Clock {
    elapsed: Duration,
    deny: Option<FlashStage>,
    checks: usize,
    deny_check: Option<usize>,
    operation_progress: Vec<crate::operation::Progress>,
}
impl UpdateRuntime for Clock {
    fn operation_progress(&mut self, progress: crate::operation::Progress) {
        self.operation_progress.push(progress);
    }
    fn elapsed(&self) -> Duration {
        self.elapsed
    }
    fn sleep(&mut self, d: Duration) {
        self.elapsed += d;
    }
}
impl ExecutionRuntime<&'static str> for Clock {
    fn check_stage(&mut self, stage: FlashStage) -> Result<(), &'static str> {
        self.checks += 1;
        if self.deny == Some(stage) || self.deny_check == Some(self.checks) {
            Err("tray policy refused")
        } else {
            Ok(())
        }
    }
}
fn run(
    plan: &PreparedUpdate,
    state: &Rc<RefCell<State>>,
    mode: ExecutionMode,
) -> Result<FlashOutcome, ExecutionError<&'static str>> {
    plan.execute(
        FlashTransport {
            reads: &mut Port(state.clone()),
            writes: &mut Port(state.clone()),
        },
        &mut Clock::default(),
        mode,
    )
}

#[test]
fn final_stage_original_hardware_refusal_precedes_all_bridge_and_settings_writes() {
    struct UnavailableFactory;
    impl Transport for UnavailableFactory {
        type Error = &'static str;
        fn exec(&mut self, command: &[u8], _data: Data<'_>) -> Result<usize, Self::Error> {
            assert_eq!(command, crate::production::parameters());
            Err("factory record unavailable")
        }
        fn sense(&self) -> Option<(u8, u8, u8)> {
            None
        }
    }
    for restore in [false, true] {
        for mode in [ExecutionMode::Flash, ExecutionMode::Recovery] {
            let (mut plan, state) = setup(restore);
            let last = plan.stages.last_mut().unwrap();
            last.settings = last
                .settings
                .clone()
                .with_hardware_guard(&last.normal, true, None);
            let error = plan
                .execute(
                    FlashTransport {
                        reads: &mut UnavailableFactory,
                        writes: &mut Port(state.clone()),
                    },
                    &mut Clock::default(),
                    mode,
                )
                .unwrap_err();
            assert!(matches!(error, ExecutionError::Startup(ref source)
                if matches!(source.as_ref(), crate::startup::migration::Error::Read(_))));
            let state = state.borrow();
            assert_eq!(state.writes, 0);
            assert_eq!(state.entries, 0);
            assert_eq!(state.finishes, 0);
            assert!(state.parameter_writes.is_empty());
        }
    }
}

#[test]
fn final_stage_mechanism_prerequisite_is_checked_before_the_first_bridge_write() {
    struct WrongMechanism;
    impl Transport for WrongMechanism {
        type Error = &'static str;
        fn exec(&mut self, command: &[u8], data: Data<'_>) -> Result<usize, Self::Error> {
            assert_eq!(command, cdb::read_parameter_word(0x28f).unwrap());
            match data {
                Data::In(bytes) => {
                    bytes.copy_from_slice(&0u16.to_be_bytes());
                    Ok(2)
                }
                _ => panic!("only a prerequisite read is permitted"),
            }
        }
        fn sense(&self) -> Option<(u8, u8, u8)> {
            None
        }
    }
    for restore in [false, true] {
        for mode in [ExecutionMode::Flash, ExecutionMode::Recovery] {
            let (mut plan, state) = setup(restore);
            let last = plan.stages.last_mut().unwrap();
            let mut correction = crate::compatibility::PreparedCorrection::native(Vec::new(), &[]);
            correction.requirements = vec![crate::compatibility::ParameterPrerequisite {
                parameter: 0x28f,
                value: 1,
            }];
            last.settings = last.settings.clone().with_correction(Some(correction));
            let error = plan
                .execute(
                    FlashTransport {
                        reads: &mut WrongMechanism,
                        writes: &mut Port(state.clone()),
                    },
                    &mut Clock::default(),
                    mode,
                )
                .unwrap_err();
            assert!(matches!(error, ExecutionError::Startup(ref source)
                if matches!(source.as_ref(), crate::startup::migration::Error::Prerequisite {
                    parameter: 0x28f, expected: 1, actual: 0 })));
            let state = state.borrow();
            assert_eq!((state.writes, state.entries, state.finishes), (0, 0, 0));
            assert!(state.parameter_writes.is_empty());
        }
    }
}
#[test]
fn complete_flash_owns_migration_both_passes_and_exact_component_verification() {
    for restore in [false, true] {
        let (plan, state) = setup(restore);
        let mut clock = Clock::default();
        let result = plan
            .flash(
                FlashTransport {
                    reads: &mut Port(state.clone()),
                    writes: &mut Port(state.clone()),
                },
                &mut clock,
            )
            .unwrap();
        assert!(result.kernel_verified && result.normal_verified);
        use crate::operation::{Component, Phase};
        for phase in [Phase::Writing, Phase::Restarting, Phase::Verifying] {
            assert!(clock.operation_progress.iter().any(|p| p.phase == phase));
        }
        for component in [Component::Kernel, Component::Normal] {
            assert!(clock
                .operation_progress
                .iter()
                .any(|p| p.phase == Phase::Verifying
                    && p.component == component
                    && p.done == p.total
                    && p.total.is_some()));
        }
        let waiting = clock
            .operation_progress
            .iter()
            .find(|p| p.phase == Phase::Restarting)
            .unwrap();
        assert_eq!((waiting.done, waiting.total), (None, None));
        assert_eq!(result.completed_stages, if restore { 2 } else { 1 });
        assert_eq!(state.borrow().parameter_writes, [0xffff]);
        assert_eq!(state.borrow().finishes, result.completed_stages);
    }
}
#[test]
fn recovery_resumes_loader_and_still_verifies_both_components() {
    let (plan, state) = setup(true);
    state.borrow_mut().loader = true;
    let result = run(&plan, &state, ExecutionMode::Recovery).unwrap();
    assert_eq!(state.borrow().entries, 1); // restoration enters normally
    assert!(state.borrow().parameter_writes.is_empty());
    assert!(result.normal_verified && result.kernel_verified);
    assert_eq!(result.completed_stages, 2);
}

#[test]
fn recovery_unsupported_medium_advances_to_existing_exact_readbacks() {
    let (plan, state) = setup(true);
    state.borrow_mut().unsupported_medium = Some((2, 0x30, 0));
    let result = run(&plan, &state, ExecutionMode::Recovery).unwrap();
    assert!(result.kernel_verified && result.normal_verified);
    assert_eq!(result.completed_stages, 2);
    assert!(state.borrow().readback_reads > 0);
}

#[test]
fn unsupported_medium_does_not_hide_recovery_mismatches() {
    let (plan, state) = setup(false);
    {
        let mut state = state.borrow_mut();
        state.unsupported_medium = Some((2, 0x30, 0));
        state.corrupt_normal = true;
    }
    let error = run(&plan, &state, ExecutionMode::Recovery).unwrap_err();
    assert!(
        matches!(
            &error,
            ExecutionError::Startup(source)
                if matches!(source.as_ref(), crate::startup::migration::Error::Flash {
                    source: ExecutionError::NormalMismatch { .. }, ..
                })
        ),
        "got {error:?}"
    );

    let (plan, state) = setup(false);
    {
        let mut state = state.borrow_mut();
        state.unsupported_medium = Some((2, 0x30, 0));
        state.wrong_target = Some(2);
    }
    let error = run(&plan, &state, ExecutionMode::Recovery).unwrap_err();
    assert!(
        matches!(
            &error,
            ExecutionError::Startup(source)
                if matches!(source.as_ref(), crate::startup::migration::Error::Flash {
                    source: ExecutionError::IdentityMismatch { target: true, .. }, ..
                })
        ),
        "got {error:?}"
    );
}

#[test]
fn flash_still_times_out_on_unsupported_medium_before_readback() {
    let (plan, state) = setup(false);
    state.borrow_mut().unsupported_medium = Some((2, 0x30, 0));
    let error = run(&plan, &state, ExecutionMode::Flash).unwrap_err();
    assert!(
        matches!(
            &error,
            ExecutionError::Startup(source)
                if matches!(source.as_ref(), crate::startup::migration::Error::Flash {
                    source: ExecutionError::Flash(FlashError::Update { .. }), ..
                })
        ),
        "got {error:?}"
    );
    assert_eq!(state.borrow().readback_reads, 0);
}

#[test]
fn recovery_does_not_advance_on_other_medium_sense_codes() {
    let (plan, state) = setup(false);
    state.borrow_mut().unsupported_medium = Some((2, 0x30, 1));
    let error = run(&plan, &state, ExecutionMode::Recovery).unwrap_err();
    assert!(
        matches!(
            &error,
            ExecutionError::Startup(source)
                if matches!(source.as_ref(), crate::startup::migration::Error::Flash {
                    source: ExecutionError::Flash(FlashError::Update { .. }), ..
                })
        ),
        "got {error:?}"
    );
    assert_eq!(state.borrow().readback_reads, 0);
}

#[test]
fn ordinary_flash_cannot_use_the_recovery_loader_waiver() {
    let (plan, state) = setup(false);
    state.borrow_mut().loader = true;
    let error = run(&plan, &state, ExecutionMode::Flash).unwrap_err();
    assert!(!error.write_started());
    assert_eq!(state.borrow().writes, 0);
}
#[test]
fn wrong_target_identity_is_fatal_even_when_readback_unavailable() {
    for wrong in 2..4 {
        let (plan, state) = setup(false);
        state.borrow_mut().wrong_target = Some(wrong);
        state.borrow_mut().unreadable_normal = true;
        let error = run(&plan, &state, ExecutionMode::Flash).unwrap_err();
        assert_eq!(error.phase(), "target startup");
        assert!(error.write_started());
    }
}
#[test]
fn readiness_does_not_prove_normal_started() {
    let (plan, state) = setup(false);
    state.borrow_mut().stay_loader = true;
    assert_eq!(
        run(&plan, &state, ExecutionMode::Flash)
            .unwrap_err()
            .phase(),
        "target startup"
    );
}
#[test]
fn target_identity_with_unreadable_normal_is_qualified_not_fully_verified() {
    let (plan, state) = setup(false);
    state.borrow_mut().unreadable_normal = true;
    let result = run(&plan, &state, ExecutionMode::Flash).unwrap();
    assert!(result.kernel_verified);
    assert!(!result.normal_verified);
}

#[test]
fn recovery_unsupported_medium_without_normal_readback_is_not_fully_verified() {
    let (plan, state) = setup(false);
    {
        let mut state = state.borrow_mut();
        state.unsupported_medium = Some((2, 0x30, 0));
        state.unreadable_normal = true;
    }
    let outcome = run(&plan, &state, ExecutionMode::Recovery).unwrap();
    assert!(outcome.kernel_verified);
    assert!(!outcome.normal_verified);
    assert_eq!(outcome.completed_stages, 1);
}

#[test]
fn flash_requires_complete_readback_and_completed_preserves_qualified_evidence() {
    use crate::CodedError;
    let (plan, state) = setup(false);
    state.borrow_mut().unreadable_normal = true;
    let error = plan
        .flash(
            FlashTransport {
                reads: &mut Port(state.clone()),
                writes: &mut Port(state.clone()),
            },
            &mut Clock::default(),
        )
        .unwrap_err();
    assert_eq!(error.code(), "pioneer.execute.verification_incomplete");
    assert!(error.write_started() && error.firmware_write_started());
    let ExecutionError::VerificationIncomplete(outcome) = error else {
        panic!("completed evidence was lost");
    };
    assert!(outcome.kernel_verified && !outcome.normal_verified);
    assert_eq!(outcome.completed_stages, 1);

    let (plan, state) = setup(false);
    state.borrow_mut().unreadable_normal = true;
    let outcome = plan
        .flash_completed(
            FlashTransport {
                reads: &mut Port(state.clone()),
                writes: &mut Port(state.clone()),
            },
            &mut Clock::default(),
        )
        .unwrap();
    assert!(outcome.kernel_verified && !outcome.normal_verified);
    assert_eq!(outcome.completed_stages, 1);
}
#[test]
fn normal_mismatch_is_fatal_and_stops_restoration() {
    let (plan, state) = setup(true);
    state.borrow_mut().corrupt_normal = true;
    let error = run(&plan, &state, ExecutionMode::Flash).unwrap_err();
    assert_eq!(error.phase(), "Normal readback");
    assert_eq!(state.borrow().finishes, 1);
}
#[test]
fn descriptor_change_after_parameter_change_stops_before_entry_and_restores_parameter() {
    let (plan, state) = setup(false);
    state.borrow_mut().change_descriptor_at = Some(3);
    let error = run(&plan, &state, ExecutionMode::Flash).unwrap_err();
    assert!(error.write_started());
    assert!(!error.firmware_write_started());
    assert_eq!(state.borrow().entries, 0);
    assert_eq!(state.borrow().parameter_writes, [0xffff, 0xfe24]);
}
#[test]
fn every_complete_operation_write_failure_is_terminal_without_retry() {
    let (plan, state) = setup(true);
    run(&plan, &state, ExecutionMode::Flash).unwrap();
    let count = state.borrow().writes;
    for fail in 2..=count {
        // parameter rollback itself is independently covered
        let (plan, state) = setup(true);
        state.borrow_mut().fail_write = Some(fail);
        assert!(
            run(&plan, &state, ExecutionMode::Flash).is_err(),
            "write {fail}"
        );
        assert_eq!(state.borrow().writes, fail, "no firmware retry at {fail}");
    }
}
#[test]
fn normal_only_also_migrates_and_verifies_exact_target() {
    let installed = fixture(false, 1);
    let plan = Receiver::from_installed(&installed)
        .unwrap()
        .prepare_normal(installed.normal_transfer())
        .unwrap();
    let (_, state) = setup(false);
    let result = plan
        .flash(
            FlashTransport {
                reads: &mut Port(state.clone()),
                writes: &mut Port(state.clone()),
            },
            &mut Clock::default(),
        )
        .unwrap();
    assert!(!result.kernel_verified);
    assert!(result.normal_verified);
    assert_eq!(state.borrow().parameter_writes, [0xffff]);
    let (_, state) = setup(false);
    state.borrow_mut().wrong_target = Some(2);
    assert_eq!(
        plan.execute(
            FlashTransport {
                reads: &mut Port(state.clone()),
                writes: &mut Port(state.clone())
            },
            &mut Clock::default()
        )
        .unwrap_err()
        .phase(),
        "target startup"
    );
}
#[test]
fn unreadable_early_span_cannot_hide_a_readable_later_mismatch() {
    struct Reads {
        calls: usize,
    }
    impl Transport for Reads {
        type Error = &'static str;
        fn exec(&mut self, c: &[u8], data: Data<'_>) -> Result<usize, Self::Error> {
            if c == cdb::knock() {
                return Ok(0);
            }
            self.calls += 1;
            if self.calls == 1 {
                return Err("first span unreadable");
            }
            let Data::In(bytes) = data else { panic!() };
            bytes.fill(0);
            bytes[7] = 1;
            Ok(bytes.len())
        }
        fn sense(&self) -> Option<(u8, u8, u8)> {
            None
        }
    }
    let mut reads = Reads { calls: 0 };
    assert!(matches!(
        verify_normal_at(
            &mut reads,
            &vec![0; 0x10000],
            0x410000,
            FlashStage::Initial,
            &mut Clock::default()
        ),
        Err(ExecutionError::NormalMismatch {
            address: 0x418007,
            ..
        })
    ));
    assert_eq!(reads.calls, 2);
}

#[test]
fn changed_host_policy_after_parameter_migration_refuses_transfer_and_restores_setting() {
    let (plan, state) = setup(false);
    let mut clock = Clock {
        deny_check: Some(2),
        ..Clock::default()
    };
    let error = plan
        .flash(
            FlashTransport {
                reads: &mut Port(state.clone()),
                writes: &mut Port(state.clone()),
            },
            &mut clock,
        )
        .unwrap_err();
    assert!(!error.firmware_write_started());
    assert_eq!(state.borrow().entries, 0);
    assert_eq!(state.borrow().parameter_writes, [0xffff, 0xfe24]);
}

// Change only envelope identity fields; the independent instruction/body
// fixtures and transfer verification remain the same.
fn branded_fixture(vendor: &str, revision: &str) -> Update {
    let source = fixture(false, 0xff);
    let edit = |bytes: &[u8]| {
        let mut bytes = bytes.to_vec();
        for (key, value) in [
            ("ID : ", format!("{vendor} BDR-TEST")),
            ("Revision Level : ", revision.to_owned()),
        ] {
            let start = bytes
                .windows(key.len())
                .position(|w| w == key.as_bytes())
                .unwrap()
                + key.len();
            let end = start + bytes[start..].iter().position(|&b| b == b'\r').unwrap();
            assert!(value.len() < end - start);
            bytes[start..end].fill(b' ');
            bytes[start..start + value.len()].copy_from_slice(value.as_bytes());
            bytes[start + value.len()] = 0;
        }
        bytes
    };
    Update::load(
        &edit(source.kernel_transfer()),
        &edit(source.normal_transfer()),
    )
    .unwrap()
}

#[test]
fn oem_vendor_is_bound_to_firmware_instead_of_a_pioneer_brand_literal() {
    for vendor in ["PLEXTOR", "TEAC", "ASUS", "SONY"] {
        let firmware = branded_fixture(vendor, "1.00");
        let (plan, state) = setup_updates(firmware.clone(), firmware);
        let result = run(&plan, &state, ExecutionMode::Flash).unwrap();
        assert_eq!(result.identity.vendor(), vendor);
        assert!(result.kernel_verified && result.normal_verified);

        let firmware = branded_fixture(vendor, "1.00");
        let (plan, state) = setup_updates(firmware.clone(), firmware);
        let observed = state.borrow().installed_id.clone().unwrap();
        let mut inquiry = *observed.inquiry_bytes();
        inquiry[8..16].copy_from_slice(b"WRONG   ");
        state.borrow_mut().installed_id =
            Some(Identity::parse(&inquiry, observed.vendor_bytes()).unwrap());
        let error = run(&plan, &state, ExecutionMode::Flash).unwrap_err();
        assert_eq!(error.phase(), "receiver binding");
        assert_eq!(state.borrow().writes, 0);
    }
}

#[test]
fn envelope_revision_is_not_a_runtime_identity_requirement() {
    let firmware = branded_fixture("PIONEER", "0.05e");
    let (plan, state) = setup_updates(firmware.clone(), firmware.clone());
    let result = run(&plan, &state, ExecutionMode::Flash).unwrap();
    assert_eq!(result.identity.revision(), "0.05");
    assert!(result.kernel_verified && result.normal_verified);

    let (plan, state) = setup_updates(firmware.clone(), firmware);
    let observed = state.borrow().target_id.clone().unwrap();
    let mut inquiry = *observed.inquiry_bytes();
    inquiry[32..36].copy_from_slice(b"0.06");
    state.borrow_mut().target_id =
        Some(Identity::parse(&inquiry, observed.vendor_bytes()).unwrap());
    assert!(
        run(&plan, &state, ExecutionMode::Flash)
            .unwrap()
            .normal_verified
    );
}

#[test]
fn envelope_non_ascii_suffix_does_not_override_exact_readback() {
    let firmware = branded_fixture("PIONEER", "0.05é");
    let (plan, state) = setup_updates(firmware.clone(), firmware);
    assert!(
        run(&plan, &state, ExecutionMode::Flash)
            .unwrap()
            .normal_verified
    );
}

#[test]
fn branding_differences_are_success_when_bytes_match_including_restoration() {
    for restore in [false, true] {
        for wrong in [0, 1, 4] {
            let (plan, state) = setup(restore);
            state.borrow_mut().wrong_target = Some(wrong);
            let outcome = run(&plan, &state, ExecutionMode::Flash).unwrap();
            assert!(outcome.kernel_verified && outcome.normal_verified);
            assert_eq!(outcome.completed_stages, if restore { 2 } else { 1 });
        }
    }
}
#[test]
fn branding_difference_cannot_hide_wrong_or_unreadable_normal() {
    let (plan, state) = setup(false);
    state.borrow_mut().wrong_target = Some(1);
    state.borrow_mut().corrupt_normal = true;
    assert_eq!(
        run(&plan, &state, ExecutionMode::Flash)
            .unwrap_err()
            .phase(),
        "Normal readback"
    );
    let (plan, state) = setup(false);
    state.borrow_mut().wrong_target = Some(1);
    state.borrow_mut().unreadable_normal = true;
    let outcome = run(&plan, &state, ExecutionMode::Flash).unwrap();
    assert!(!outcome.normal_verified);
}
#[test]
fn serial_change_after_transfer_is_terminal() {
    let (plan, state) = setup(false);
    let mut borrowed = state.borrow_mut();
    let State {
        installed_id,
        target_id,
        ..
    } = &mut *borrowed;
    for identity in [installed_id, target_id] {
        let old = identity.as_ref().unwrap();
        let mut vendor = *old.vendor_bytes();
        vendor[..8].copy_from_slice(b"ORIGINAL");
        *identity = Some(Identity::parse(old.inquiry_bytes(), &vendor).unwrap());
    }
    drop(borrowed);
    state.borrow_mut().wrong_target = Some(5);
    assert_eq!(
        run(&plan, &state, ExecutionMode::Flash)
            .unwrap_err()
            .phase(),
        "target startup"
    );
}

#[test]
fn envelope_comparison_separates_naming_from_exact_contents() {
    let a = branded_fixture("PIONEER", "1.00");
    let b = branded_fixture("ASUS", "HLE2");
    let result = a.normal().compare(b.normal());
    assert_eq!(result.bytes, crate::envelope::ByteComparison::Equal);
    assert!(result.name_changed && result.revision_changed);
    assert!(!result.component_changed && !result.hardware_changed && !result.destination_changed);
}

#[test]
fn recovery_loader_may_reveal_its_serial_only_after_normal_starts() {
    let (plan, state) = setup(false);
    state.borrow_mut().loader = true;
    let observed = state.borrow().target_id.clone().unwrap();
    let mut vendor = *observed.vendor_bytes();
    vendor[..8].copy_from_slice(b"ORIGINAL");
    state.borrow_mut().target_id =
        Some(Identity::parse(observed.inquiry_bytes(), &vendor).unwrap());
    let result = run(&plan, &state, ExecutionMode::Recovery).unwrap();
    assert!(result.kernel_verified && result.normal_verified);
    assert_eq!(result.identity.serial(), "ORIGINAL");
}

fn setup_handoff_bridge(marker: bool) -> (PreparedUpdate, Rc<RefCell<State>>) {
    let source = fixture(marker, 1);
    let original = fixture(false, if marker { 0 } else { 1 });
    let mut kernel = original.kernel().image.clone();
    kernel.copy_within(0x20..0x30, 0x2a);
    kernel[0x20..0x2a].fill(0);
    kernel[0x2107] = 0x2a;
    checksum(&mut kernel);
    let mut normal = original.normal().image.clone();
    normal[0x620] ^= 1; // Distinguish readback without damaging native filters.
    checksum(&mut normal);
    let mut normal_wire = original.normal().repack(&normal).unwrap();
    let mut key = [0; 20];
    key[19] = 5;
    crate::envelope::signature::SigningKey::from_bytes(key)
        .unwrap()
        .sign_normal(&mut normal_wire)
        .unwrap();
    let target = Update::load(&original.kernel().repack(&kernel).unwrap(), &normal_wire).unwrap();
    let (plan, state) = setup_updates(source, target);
    state.borrow_mut().stage_normals = plan
        .stages()
        .iter()
        .map(|stage| stage.normal_image().to_vec())
        .collect();
    (plan, state)
}

#[test]
fn handoff_and_marker_bridges_execute_with_each_stages_own_normal() {
    for marker in [false, true] {
        let (plan, state) = setup_handoff_bridge(marker);
        assert_eq!(plan.stages().len(), if marker { 3 } else { 2 });
        assert_ne!(
            plan.stages()[0].normal_image(),
            plan.stages()[1].normal_image()
        );
        let result = run(&plan, &state, ExecutionMode::Flash).unwrap();
        assert_eq!(result.completed_stages, plan.stages().len());
        assert!(result.kernel_verified && result.normal_verified);
        assert_eq!(state.borrow().finishes, plan.stages().len());
    }
}

#[test]
fn handoff_bridge_failure_stops_and_retains_completed_stages() {
    let (plan, state) = setup_handoff_bridge(true);
    let initial = state.borrow().clone();
    run(&plan, &state, ExecutionMode::Flash).unwrap();
    let writes = state.borrow().writes;
    for fail in 1..=writes {
        let mut next = initial.clone();
        next.fail_write = Some(fail);
        let state = Rc::new(RefCell::new(next));
        let error = run(&plan, &state, ExecutionMode::Flash).unwrap_err();
        if fail == 1 {
            // Before entering UPDATE, the settings transaction may restore its
            // original word. This is the established safe rollback boundary.
            assert_eq!(state.borrow().entries, 0);
            assert_eq!(state.borrow().parameter, initial.parameter);
        } else {
            assert_eq!(
                state.borrow().writes,
                fail,
                "a failing firmware write must not retry or advance"
            );
        }
        assert_eq!(error.completed_stages(), state.borrow().finishes);
        if state.borrow().finishes > 0 {
            assert!(error.write_started() && error.firmware_write_started());
        }
    }
    let state = Rc::new(RefCell::new(initial));
    let error = plan
        .execute(
            FlashTransport {
                reads: &mut Port(state.clone()),
                writes: &mut Port(state.clone()),
            },
            &mut Clock {
                deny: Some(FlashStage::Continuation(1)),
                ..Clock::default()
            },
            ExecutionMode::Flash,
        )
        .unwrap_err();
    assert_eq!(error.completed_stages(), 1);
    assert!(error.firmware_write_started());
    assert_eq!(state.borrow().finishes, 1);
    assert_eq!(state.borrow().entries, 1);
}

#[test]
fn later_stage_settings_roll_back_locally_without_erasing_earlier_completion() {
    let (mut plan, state) = setup_handoff_bridge(false);
    plan.stages[1].settings = crate::settings::update::Plan::target(
        Some(crate::startup::Setting {
            parameter: 0x9f,
            value: 0xfe34,
            explicit: true,
        }),
        false,
    );
    let initial = state.borrow().clone();
    let result = run(&plan, &state, ExecutionMode::Flash).unwrap();
    assert_eq!(result.completed_stages, 2);
    assert_eq!(state.borrow().parameter_writes, [0xffff, 0xfe34]);

    let state = Rc::new(RefCell::new(initial));
    let error = plan
        .execute(
            FlashTransport {
                reads: &mut Port(state.clone()),
                writes: &mut Port(state.clone()),
            },
            &mut Clock {
                deny_check: Some(4),
                ..Clock::default()
            },
            ExecutionMode::Flash,
        )
        .unwrap_err();
    assert_eq!(error.completed_stages(), 1);
    assert!(error.firmware_write_started());
    assert_eq!(state.borrow().entries, 1);
    assert_eq!(state.borrow().finishes, 1);
    assert_eq!(state.borrow().parameter_writes, [0xffff, 0xfe34, 0xffff]);
    let ExecutionError::AfterStage { source, .. } = error else {
        panic!("lost completed bridge")
    };
    let ExecutionError::Startup(source) = *source else {
        panic!("lost stage settings failure")
    };
    assert!(matches!(
        *source,
        crate::startup::migration::Error::Flash {
            rollback: crate::startup::migration::Rollback::Restored,
            ..
        }
    ));
}

fn workflow_repack(pair: &Update, mut kernel: Vec<u8>, mut normal: Vec<u8>) -> Update {
    checksum(&mut kernel);
    checksum(&mut normal);
    let mut bytes = pair.normal().repack(&normal).unwrap();
    let mut key = [0; 20];
    key[19] = 5;
    crate::envelope::signature::SigningKey::from_bytes(key)
        .unwrap()
        .sign_normal(&mut bytes)
        .unwrap();
    Update::load(&pair.kernel().repack(&kernel).unwrap(), &bytes).unwrap()
}

fn workflow_startup_gate(normal: &mut [u8], value: u16) {
    normal[0x740..0x754].copy_from_slice(&[
        0x79,
        0,
        0,
        0x9f,
        0x5e,
        0x41,
        0x10,
        0,
        0x79,
        0x20,
        (value >> 8) as u8,
        value as u8,
        0x47,
        6,
        0xf8,
        1,
        0x5e,
        0x41,
        7,
        0x80,
    ]);
    normal[0x780..0x786].copy_from_slice(&[0x5e, 0x40, 0x0a, 0x1a, 0x54, 0x70]);
}

fn workflow_mechanism_bridge() -> (PreparedUpdate, Rc<RefCell<State>>) {
    let base = fixture(false, 1);
    let mut source_normal = base.normal().image.clone();
    workflow_startup_gate(&mut source_normal, 0xfe24);
    let source = workflow_repack(&base, base.kernel().image.clone(), source_normal);

    let mut target_kernel = base.kernel().image.clone();
    target_kernel.copy_within(0x20..0x30, 0x2a);
    target_kernel[0x20..0x2a].fill(0);
    target_kernel[0x2107] = 0x2a;
    let mut target_normal = base.normal().image.clone();
    workflow_startup_gate(&mut target_normal, 0xfe34);
    target_normal[0x620] ^= 1;
    let target = workflow_repack(&base, target_kernel, target_normal);
    let mut expected = target.normal().image.clone();
    expected[0x624] ^= 1;
    checksum(&mut expected);
    let document = serde_json::json!({
        "schema_version": 1,
        "id": "test.workflow-mechanism",
        "hardware_scheme": crate::image::FAMILY_SCHEME,
        "hardware_family": crate::image::legacy_family(&source.normal().image).unwrap().to_string(),
        "source_normal_sha256": [crate::filters::phase::mechanism::digest(&source.normal().image)],
        "mode": "adapt",
        "resolves_issue": "ud02-mechanism-convention",
        "target_normal_sha256": crate::filters::phase::mechanism::digest(&target.normal().image),
        "target_model": target.normal().info().model,
        "input_length": target.normal().image.len(),
        "required_parameters": [{"parameter": 0x28f, "value": 1}],
        "replacements": [{
            "offset": 0x624,
            "expected_hex": format!("{:02x}", target.normal().image[0x624]),
            "replacement_hex": format!("{:02x}", expected[0x624]),
        }],
        "checksum_offset": expected.len() - 4,
        "output_sha256": crate::filters::phase::mechanism::digest(&expected),
    })
    .to_string();
    let mut receiver = Receiver::from_installed(&source).unwrap();
    receiver.correction_contracts = Some(vec![document]);
    let plan = receiver.prepare(target.clone()).unwrap();
    assert_eq!(plan.stages().len(), 2);
    assert_eq!(plan.target.normal().image, expected);
    let state = Rc::new(RefCell::new(State {
        installed_id: Some(id(source.normal())),
        target_id: Some(id(target.normal())),
        descriptor: source.normal().image[..16].to_vec(),
        normal: expected,
        stage_normals: plan
            .stages()
            .iter()
            .map(|s| s.normal_image().to_vec())
            .collect(),
        kernels: plan
            .stages()
            .iter()
            .map(|s| s.kernel_image().unwrap().to_vec())
            .collect(),
        parameter: 0xfe20,
        ..State::default()
    }));
    (plan, state)
}

#[test]
fn final_mechanism_prerequisite_is_checked_before_source_bridge_mutation() {
    let (plan, state) = workflow_mechanism_bridge();
    let first = &plan.stages()[0];
    assert_eq!(
        first.bridge(),
        Some(crate::receiver::BridgeKind::KernelHandoff)
    );
    assert!(first.settings().requires_normal_runtime());
    assert_eq!(
        first.settings().requirements(),
        plan.settings().requirements()
    );
    assert!(first.settings().firmware_corrections().is_empty());
    assert_eq!(first.settings().startup_setting().unwrap().value, 0xfe24);
    assert_eq!(plan.settings().startup_setting().unwrap().value, 0xfe34);
    let error = run(&plan, &state, ExecutionMode::Flash).unwrap_err();
    assert!(
        matches!(error,
            ExecutionError::Startup(ref source)
            if matches!(source.as_ref(), crate::startup::migration::Error::Prerequisite {
                parameter: 0x28f, expected: 1, actual: 0,
            })
        ),
        "unexpected failure: {error:?}"
    );
    let state = state.borrow();
    assert_eq!(state.mechanism_parameter_reads, 1);
    assert_eq!(state.parameter, 0xfe20);
    assert!(state.parameter_writes.is_empty());
    assert_eq!((state.entries, state.finishes, state.writes), (0, 0, 0));
    assert!(!error.write_started());
}

#[test]
fn mechanism_bridge_keeps_distinct_source_and_target_settings_in_execution_order() {
    let (plan, state) = workflow_mechanism_bridge();
    state.borrow_mut().mechanism_parameter = 1;
    let outcome = run(&plan, &state, ExecutionMode::Flash).unwrap();
    assert_eq!(outcome.completed_stages, 2);
    assert!(outcome.kernel_verified && outcome.normal_verified);
    let state = state.borrow();
    assert_eq!(state.mechanism_parameter_reads, 3);
    assert_eq!(state.mechanism_parameter, 1);
    assert_eq!(state.parameter_writes, [0xfe24, 0xfe34]);
    assert_eq!(state.finishes, 2);
}

#[test]
fn inherited_mechanism_runtime_requirement_blocks_recovery_before_bridge_write() {
    let (plan, state) = workflow_mechanism_bridge();
    state.borrow_mut().loader = true;
    state.borrow_mut().mechanism_parameter = 1;
    let error = run(&plan, &state, ExecutionMode::Recovery).unwrap_err();
    assert!(
        matches!(error, ExecutionError::Plan(_)),
        "unexpected failure: {error:?}"
    );
    let state = state.borrow();
    assert_eq!(state.writes, 0);
    assert_eq!(state.entries, 0);
    assert_eq!(state.mechanism_parameter_reads, 1);
}

#[test]
fn native_phase_correction_can_recover_without_mechanism_runtime_checks() {
    use crate::compatibility::Correction;
    use crate::image::phase::{correct_normal, Assignment};
    let source = fixture(false, 1);
    let swapped = correct_normal(&source.normal().image, Assignment::Swapped).unwrap();
    let target = workflow_repack(&source, source.kernel().image.clone(), swapped);
    let (plan, state) = setup_updates(source.clone(), target);
    assert!(!plan.settings().requires_normal_runtime());
    assert!(plan.settings().requirements().is_empty());
    assert_eq!(
        plan.settings().firmware_corrections(),
        &[Correction::Phase {
            from: Assignment::Swapped,
            to: Assignment::Direct,
        }]
    );
    assert_eq!(plan.target.normal().image, source.normal().image);
    {
        let mut state = state.borrow_mut();
        state.loader = true;
        state.normal = plan.target.normal().image.clone();
    }
    let result = run(&plan, &state, ExecutionMode::Recovery).unwrap();
    assert_eq!(result.completed_stages, 1);
    assert!(result.normal_verified && result.kernel_verified);
    let state = state.borrow();
    assert!(state.parameter_writes.is_empty());
    assert_eq!(state.mechanism_parameter_reads, 0);
}

fn assert_category_follows_write_boundary(error: &ExecutionError<&'static str>) {
    use crate::{operation::IssueKind, CodedError};
    let kind = error.kind();
    let written = matches!(kind, IssueKind::Update | IssueKind::Verification);
    if error.firmware_write_started() {
        assert!(written, "{kind:?} for possibly-written {error:?}");
    }
    if !error.write_started() {
        assert!(!written, "{kind:?} for unwritten {error:?}");
    }
}
fn constructed_errors(identity: &Identity) -> Vec<ExecutionError<&'static str>> {
    use crate::startup::migration::{Error as Migration, Rollback};
    let flash = |stage: FlashStage| -> Vec<FlashError<&'static str>> {
        vec![
            FlashError::Preflight {
                stage,
                source: "host",
            },
            FlashError::DescriptorRead {
                stage,
                source: drive::Error::Transport("read"),
            },
            FlashError::DescriptorChanged { stage },
            FlashError::DescriptorMismatch { stage },
            FlashError::UnsupportedTransport { stage },
            FlashError::Update {
                stage,
                source: drive::UpdateError::InvalidSpan {
                    role: crate::Role::Normal,
                    length: 0,
                },
            },
            FlashError::Update {
                stage,
                source: drive::UpdateError::Entry(drive::Error::Transport("entry")),
            },
            FlashError::Readback {
                stage,
                source: drive::Error::Transport("read"),
            },
            FlashError::ReadbackMismatch { stage, address: 0 },
        ]
    };
    let mut base = vec![
        ExecutionError::Plan("x"),
        ExecutionError::VerificationIncomplete(FlashOutcome {
            kernel_verified: true,
            normal_verified: false,
            completed_stages: 1,
            identity: identity.clone(),
        }),
    ];
    for stage in [FlashStage::Initial, FlashStage::Continuation(1)] {
        for target in [false, true] {
            base.push(ExecutionError::IdentityRead {
                stage,
                target,
                source: drive::Error::Transport("identify"),
            });
            base.push(ExecutionError::IdentityMismatch {
                stage,
                observed: identity.clone(),
                target,
            });
        }
        base.push(ExecutionError::NormalMismatch { stage, address: 0 });
        base.extend(flash(stage).into_iter().map(ExecutionError::Flash));
    }
    let mut all = Vec::new();
    for source in base {
        // Rebuild each source per wrapper; errors are not Clone.
        let again = |e: &ExecutionError<&'static str>| rebuild(e, identity);
        let flash = |original, rollback| Migration::Flash {
            original,
            target: 2,
            source: again(&source),
            rollback,
        };
        let failed = || Rollback::Failed(drive::Error::Transport("restore"));
        for wrapped in [
            Migration::Preflight(again(&source)),
            flash(1, Rollback::Restored),
            flash(2, Rollback::Unchanged),
            flash(1, failed()),
            flash(
                1,
                Rollback::Settings(vec![(1, Rollback::Restored), (2, failed())]),
            ),
            flash(1, Rollback::UnsafeAfterFirmwareWrite),
        ] {
            all.push(ExecutionError::Startup(Box::new(wrapped)));
        }
        all.push(ExecutionError::AfterStage {
            completed: 1,
            source: Box::new(again(&source)),
        });
        all.push(source);
    }
    all.push(ExecutionError::Startup(Box::new(Migration::Change {
        original: 1,
        source: drive::Error::Transport("write"),
        rollback: Rollback::Restored,
    })));
    all.push(ExecutionError::Startup(Box::new(Migration::Read(
        drive::Error::Transport("read"),
    ))));
    all.push(ExecutionError::Startup(Box::new(Migration::Prerequisite {
        parameter: 1,
        expected: 2,
        actual: 3,
    })));
    all.push(ExecutionError::Startup(Box::new(
        Migration::OriginalHardware,
    )));
    all
}
fn rebuild(
    error: &ExecutionError<&'static str>,
    identity: &Identity,
) -> ExecutionError<&'static str> {
    // Only the shapes produced by `constructed_errors` need rebuilding.
    let flash = |e: &FlashError<&'static str>| match e {
        FlashError::Preflight { stage, source } => FlashError::Preflight {
            stage: *stage,
            source: *source,
        },
        FlashError::DescriptorRead { stage, .. } => FlashError::DescriptorRead {
            stage: *stage,
            source: drive::Error::Transport("read"),
        },
        FlashError::DescriptorChanged { stage } => FlashError::DescriptorChanged { stage: *stage },
        FlashError::DescriptorMismatch { stage } => {
            FlashError::DescriptorMismatch { stage: *stage }
        }
        FlashError::UnsupportedTransport { stage } => {
            FlashError::UnsupportedTransport { stage: *stage }
        }
        FlashError::Update {
            stage,
            source: drive::UpdateError::InvalidSpan { role, length },
        } => FlashError::Update {
            stage: *stage,
            source: drive::UpdateError::InvalidSpan {
                role: *role,
                length: *length,
            },
        },
        FlashError::Update { stage, .. } => FlashError::Update {
            stage: *stage,
            source: drive::UpdateError::Entry(drive::Error::Transport("entry")),
        },
        FlashError::Readback { stage, .. } => FlashError::Readback {
            stage: *stage,
            source: drive::Error::Transport("read"),
        },
        FlashError::ReadbackMismatch { stage, address } => FlashError::ReadbackMismatch {
            stage: *stage,
            address: *address,
        },
    };
    match error {
        ExecutionError::Plan(reason) => ExecutionError::Plan(reason),
        ExecutionError::VerificationIncomplete(outcome) => {
            ExecutionError::VerificationIncomplete(FlashOutcome {
                kernel_verified: outcome.kernel_verified,
                normal_verified: outcome.normal_verified,
                completed_stages: outcome.completed_stages,
                identity: identity.clone(),
            })
        }
        ExecutionError::IdentityRead { stage, target, .. } => ExecutionError::IdentityRead {
            stage: *stage,
            target: *target,
            source: drive::Error::Transport("identify"),
        },
        ExecutionError::IdentityMismatch { stage, target, .. } => {
            ExecutionError::IdentityMismatch {
                stage: *stage,
                observed: identity.clone(),
                target: *target,
            }
        }
        ExecutionError::NormalMismatch { stage, address } => ExecutionError::NormalMismatch {
            stage: *stage,
            address: *address,
        },
        ExecutionError::Flash(e) => ExecutionError::Flash(flash(e)),
        other => panic!("not rebuilt: {other:?}"),
    }
}

#[test]
fn host_category_follows_the_firmware_write_boundary_for_every_variant() {
    let identity = id(fixture(false, 1).normal());
    let errors = constructed_errors(&identity);
    assert!(errors.iter().any(|e| e.firmware_write_started()));
    assert!(errors.iter().any(|e| !e.write_started()));
    for error in &errors {
        assert_category_follows_write_boundary(error);
    }
}

type Scenario = Box<dyn Fn(&mut State, &mut Clock)>;
#[test]
fn host_category_follows_the_firmware_write_boundary_in_live_failures() {
    let mut errors = Vec::new();
    for restore in [false, true] {
        let (plan, state) = setup(restore);
        let template = state.borrow().clone();
        run(&plan, &state, ExecutionMode::Flash).unwrap();
        let writes = state.borrow().writes;
        let mut scenarios: Vec<Scenario> = Vec::new();
        // Settings writes, both stage entries and the last transfer writes.
        let mut fails: Vec<usize> = (1..=4).collect();
        fails.extend([writes / 2, writes / 2 + 1, writes - 1, writes]);
        for fail in fails {
            scenarios.push(Box::new(move |s, _| s.fail_write = Some(fail)));
        }
        for at in 1..5 {
            scenarios.push(Box::new(move |s, _| s.wrong_target = Some(at)));
            scenarios.push(Box::new(move |s, _| s.change_descriptor_at = Some(at)));
            scenarios.push(Box::new(move |_, c| c.deny_check = Some(at)));
        }
        for stage in 0..2 {
            scenarios.push(Box::new(move |_, c| c.deny = Some(FlashStage::at(stage))));
        }
        scenarios.push(Box::new(|s, _| s.corrupt_normal = true));
        scenarios.push(Box::new(|s, _| s.unreadable_normal = true));
        scenarios.push(Box::new(|s, _| s.loader = true));
        scenarios.push(Box::new(|s, _| s.unsupported_medium = Some((2, 0x30, 0))));
        for scenario in &scenarios {
            for mode in [ExecutionMode::Flash, ExecutionMode::Recovery] {
                let state = Rc::new(RefCell::new(template.clone()));
                let mut clock = Clock::default();
                scenario(&mut state.borrow_mut(), &mut clock);
                let result = plan.execute(
                    FlashTransport {
                        reads: &mut Port(state.clone()),
                        writes: &mut Port(state.clone()),
                    },
                    &mut clock,
                    mode,
                );
                if let Err(error) = result {
                    errors.push(error);
                }
            }
        }
    }
    assert!(errors.iter().any(|e| e.firmware_write_started()));
    assert!(errors.iter().any(|e| !e.write_started()));
    assert!(errors
        .iter()
        .any(|e| matches!(e, ExecutionError::AfterStage { .. })));
    for error in &errors {
        assert_category_follows_write_boundary(error);
    }
}

#[test]
fn typed_host_categories_keep_codes_and_follow_their_cause() {
    use crate::operation::IssueKind::*;
    use crate::startup::migration::{Error as Migration, Rollback};
    use crate::CodedError;
    let identity = id(fixture(false, 1).normal());
    let at0 = FlashStage::Initial;
    let at1 = FlashStage::Continuation(1);
    let span = |stage| {
        ExecutionError::<&'static str>::Flash(FlashError::Update {
            stage,
            source: drive::UpdateError::InvalidSpan {
                role: crate::Role::Normal,
                length: 0,
            },
        })
    };
    let mismatch = |target| ExecutionError::<&'static str>::IdentityMismatch {
        stage: at0,
        observed: identity.clone(),
        target,
    };
    let cases: Vec<(ExecutionError<&'static str>, _, &str)> = vec![
        (
            ExecutionError::Plan("x"),
            UnsupportedFirmware,
            "pioneer.execute.plan",
        ),
        (
            mismatch(true),
            Verification,
            "pioneer.execute.identity_mismatch",
        ),
        (
            mismatch(false),
            ReceiverMismatch,
            "pioneer.execute.identity_mismatch",
        ),
        (
            ExecutionError::IdentityRead {
                stage: at0,
                target: true,
                source: drive::Error::Transport("x"),
            },
            Verification,
            "pioneer.execute.identity_read",
        ),
        (
            ExecutionError::Flash(FlashError::Preflight {
                stage: at0,
                source: "tray",
            }),
            Unexpected,
            "pioneer.flash.preflight",
        ),
        (
            ExecutionError::Flash(FlashError::Preflight {
                stage: at1,
                source: "tray",
            }),
            Update,
            "pioneer.flash.preflight",
        ),
        (
            ExecutionError::Flash(FlashError::DescriptorMismatch { stage: at1 }),
            Update,
            "pioneer.flash.descriptor_mismatch",
        ),
        (span(at0), InvalidFirmware, "pioneer.flash.update"),
        (span(at1), Update, "pioneer.flash.update"),
        (
            ExecutionError::Flash(FlashError::Readback {
                stage: at0,
                source: drive::Error::Transport("x"),
            }),
            Verification,
            "pioneer.flash.readback",
        ),
        (
            ExecutionError::AfterStage {
                completed: 1,
                source: Box::new(ExecutionError::Plan("x")),
            },
            Update,
            "pioneer.execute.plan",
        ),
        (
            ExecutionError::AfterStage {
                completed: 1,
                source: Box::new(ExecutionError::NormalMismatch {
                    stage: at1,
                    address: 0,
                }),
            },
            Verification,
            "pioneer.execute.normal_mismatch",
        ),
        (
            ExecutionError::Startup(Box::new(Migration::Preflight(ExecutionError::Flash(
                FlashError::DescriptorMismatch { stage: at0 },
            )))),
            ReceiverMismatch,
            "pioneer.startup.preflight_refused",
        ),
        (
            ExecutionError::Startup(Box::new(Migration::Flash {
                original: 1,
                target: 2,
                source: ExecutionError::Plan("x"),
                rollback: Rollback::Restored,
            })),
            UnsupportedFirmware,
            "pioneer.startup.flash_failed_before_transfer",
        ),
        (
            ExecutionError::Startup(Box::new(Migration::Flash {
                original: 1,
                target: 2,
                source: mismatch(true),
                rollback: Rollback::UnsafeAfterFirmwareWrite,
            })),
            Verification,
            "pioneer.startup.flash_state_uncertain",
        ),
        (
            ExecutionError::Startup(Box::new(Migration::Flash {
                original: 1,
                target: 2,
                source: ExecutionError::Plan("x"),
                rollback: Rollback::Failed(drive::Error::Transport("x")),
            })),
            Update,
            "pioneer.startup.flash_failed_before_transfer",
        ),
    ];
    for (error, kind, code) in cases {
        assert_eq!(error.code(), code, "{error:?}");
        assert_eq!(error.kind(), kind, "{error:?}");
    }

    // A live certified-route target mismatch is a verification failure.
    let (plan, state) = setup(false);
    state.borrow_mut().wrong_target = Some(2);
    let error = run(&plan, &state, ExecutionMode::Flash).unwrap_err();
    assert!(error.firmware_write_started());
    assert_eq!(error.kind(), Verification, "{error:?}");
    // A host refusal before the first stage never reports an update failure.
    let (plan, state) = setup(false);
    let error = plan
        .execute(
            FlashTransport {
                reads: &mut Port(state.clone()),
                writes: &mut Port(state.clone()),
            },
            &mut Clock {
                deny: Some(FlashStage::Initial),
                ..Clock::default()
            },
            ExecutionMode::Flash,
        )
        .unwrap_err();
    assert!(!error.write_started());
    assert_ne!(error.kind(), Update, "{error:?}");
}

#[test]
fn generic_settings_flash_failures_keep_rollback_outcome_categories() {
    use crate::operation::IssueKind::*;
    use crate::startup::migration::{Error as Migration, Rollback};
    use crate::CodedError;
    let flash = |rollback| Migration::<&'static str, FlashError<&'static str>>::Flash {
        original: 1,
        target: 2,
        source: FlashError::DescriptorMismatch {
            stage: FlashStage::Initial,
        },
        rollback,
    };
    assert_eq!(
        Migration::<&'static str, FlashError<&'static str>>::Preflight(
            FlashError::DescriptorMismatch {
                stage: FlashStage::Initial
            }
        )
        .kind(),
        Unexpected
    );
    assert_eq!(flash(Rollback::Restored).kind(), Unexpected);
    assert_eq!(flash(Rollback::Unchanged).kind(), Unexpected);
    assert_eq!(flash(Rollback::UnsafeAfterFirmwareWrite).kind(), Update);
    assert_eq!(
        flash(Rollback::Failed(drive::Error::Transport("x"))).kind(),
        Update
    );
    assert_eq!(
        flash(Rollback::Settings(vec![(
            1,
            Rollback::Failed(drive::Error::Transport("x"))
        )]))
        .kind(),
        Update
    );
}

// Explicit family overrides retain the ordinary transaction only when bank
// contracts are compatible. Actual conversion uses a separate deferred plan.
fn setup_explicit_crossflash(restore: bool) -> (PreparedUpdate, Rc<RefCell<State>>) {
    setup_updates_policy(fixture(restore, 1), fixture(false, 0xff), true)
}

#[test]
fn explicit_crossflash_preserves_settings_transaction_and_bridge_policy() {
    for restore in [false, true] {
        for mode in [ExecutionMode::Flash, ExecutionMode::Recovery] {
            let (plan, state) = setup_explicit_crossflash(restore);
            for stage in plan.stages() {
                let startup = stage.settings.startup_plan().unwrap();
                assert_eq!(
                    startup.policy(),
                    crate::startup::checks::Policy::ExplicitCrossflash
                );
                assert_eq!(startup.word_setting().parameter, 0x9f);
                assert_eq!(startup.word_setting().value, 0xffff);
            }
            let result = run(&plan, &state, mode).unwrap();
            assert!(result.kernel_verified && result.normal_verified);
            assert_eq!(result.completed_stages, if restore { 2 } else { 1 });
            assert_eq!(state.borrow().parameter_writes, [0xffff]);
        }
    }
}

#[test]
fn explicit_crossflash_rolls_back_word_before_firmware_entry_on_descriptor_change() {
    for restore in [false, true] {
        let (plan, state) = setup_explicit_crossflash(restore);
        state.borrow_mut().change_descriptor_at = Some(3);
        let error = run(&plan, &state, ExecutionMode::Flash).unwrap_err();
        assert!(!error.firmware_write_started());
        assert_eq!(state.borrow().entries, 0);
        assert_eq!(state.borrow().parameter_writes, [0xffff, 0xfe24]);
    }
}

#[test]
fn explicit_crossflash_all_firmware_write_failures_stop_without_retry() {
    let (plan, state) = setup_explicit_crossflash(true);
    run(&plan, &state, ExecutionMode::Flash).unwrap();
    let count = state.borrow().writes;
    for fail in 2..=count {
        let (plan, state) = setup_explicit_crossflash(true);
        state.borrow_mut().fail_write = Some(fail);
        assert!(
            run(&plan, &state, ExecutionMode::Flash).is_err(),
            "write {fail}"
        );
        assert_eq!(state.borrow().writes, fail, "unexpected retry at {fail}");
        assert_eq!(state.borrow().parameter_writes, [0xffff]);
    }
}
