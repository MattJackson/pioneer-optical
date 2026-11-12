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
    prerequisite_reads: usize,
    fail_prerequisite_read: bool,
    parameter_writes: Vec<u16>,
    entries: usize,
    finishes: usize,
    writes: usize,
    fail_write: Option<usize>,
    loader: bool,
    stay_loader: bool,
    loader_after_identities: Option<usize>,
    identities: usize,
    parameter_write_entries: Vec<usize>,
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
                s.writes += 1;
                if s.fail_write == Some(s.writes) {
                    return Err("write failed");
                }
                if command == cdb::write_parameter_word(0x9f).unwrap() {
                    s.parameter = u16::from_be_bytes(bytes.try_into().unwrap());
                    let value = s.parameter;
                    s.parameter_writes.push(value);
                    let entries = s.entries;
                    s.parameter_write_entries.push(entries);
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
                if command == cdb::read_parameter_word(0x28f).unwrap() {
                    s.prerequisite_reads += 1;
                    if s.fail_prerequisite_read {
                        return Err("prerequisite read failed");
                    }
                    bytes.copy_from_slice(&s.parameter.to_be_bytes());
                } else if command == cdb::read_parameter_word(0x9f).unwrap() {
                    bytes.copy_from_slice(&s.parameter.to_be_bytes());
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
                        s.identities += 1;
                        if s.loader_after_identities == Some(s.identities) {
                            s.loader = true;
                        }
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
        assert!(state.borrow().parameter_writes.is_empty());
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
        matches!(&error, ExecutionError::NormalMismatch { .. }),
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
            ExecutionError::IdentityMismatch { target: true, .. }
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
        matches!(&error, ExecutionError::Flash(FlashError::Update { .. })),
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
        matches!(&error, ExecutionError::Flash(FlashError::Update { .. })),
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
fn descriptor_change_stops_before_entry_without_parameter_writes() {
    let (plan, state) = setup(false);
    state.borrow_mut().change_descriptor_at = Some(2);
    let error = run(&plan, &state, ExecutionMode::Flash).unwrap_err();
    assert!(!error.write_started());
    assert!(!error.firmware_write_started());
    assert_eq!(state.borrow().entries, 0);
    assert!(state.borrow().parameter_writes.is_empty());
}
#[test]
fn every_complete_operation_write_failure_is_terminal_without_retry() {
    let (plan, state) = setup(true);
    run(&plan, &state, ExecutionMode::Flash).unwrap();
    let count = state.borrow().writes;
    for fail in 1..=count {
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
fn normal_only_preserves_parameters_and_verifies_exact_target() {
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
    assert!(state.borrow().parameter_writes.is_empty());
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
fn changed_host_policy_refuses_transfer_without_parameter_writes() {
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
    assert!(state.borrow().parameter_writes.is_empty());
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

fn startup_fixture(gated: bool, marker: u8) -> Update {
    let original = fixture(gated, marker);
    let mut normal = original.normal().image.clone();
    normal[0x680..0x694].copy_from_slice(&[
        0x79, 0, 0, 0x9f, 0x5e, 0x41, 0x10, 0, 0x79, 0x20, 0xfe, 0x24, 0x47, 6, 0xf8, 1, 0x5e,
        0x41, 0x06, 0xa0,
    ]);
    normal[0x6a0..0x6a6].copy_from_slice(&[0x5e, 0x40, 0x0a, 0x1a, 0x54, 0x70]);
    workflow_repack(&original, original.kernel().image.clone(), normal)
}

fn setup_handoff_bridge(marker: bool) -> (PreparedUpdate, Rc<RefCell<State>>) {
    let source = startup_fixture(marker, 1);
    let original = startup_fixture(false, if marker { 0 } else { 1 });
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
    assert_eq!(state.borrow().parameter_writes, [0xfe34]);

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
    assert_eq!(state.borrow().parameter_writes, [0xfe34, 0xfe24]);
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

#[test]
fn native_phase_correction_executes_without_parameter_writes() {
    use crate::compatibility::Correction;
    use crate::image::phase::{correct_normal, Assignment};
    let source = startup_fixture(false, 1);
    let swapped = correct_normal(&source.normal().image, Assignment::Swapped).unwrap();
    let target = workflow_repack(&source, source.kernel().image.clone(), swapped);
    let (plan, state) = setup_updates(source.clone(), target);
    assert!(plan
        .settings()
        .firmware_corrections()
        .contains(&Correction::Phase {
            from: Assignment::Swapped,
            to: Assignment::Direct,
        }));
    assert_eq!(plan.target.normal().image, source.normal().image);
    {
        let mut state = state.borrow_mut();
        state.normal = plan.target.normal().image.clone();
    }
    let result = run(&plan, &state, ExecutionMode::Recovery).unwrap();
    assert_eq!(result.completed_stages, 1);
    assert!(result.normal_verified && result.kernel_verified);
    let state = state.borrow();
    assert!(state.parameter_writes.is_empty());
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
// contracts are identical; differing contracts refuse at preparation.
fn setup_explicit_crossflash(restore: bool) -> (PreparedUpdate, Rc<RefCell<State>>) {
    setup_updates_policy(fixture(restore, 1), fixture(false, 0xff), true)
}

#[test]
fn explicit_crossflash_preserves_parameters_and_bridge_policy() {
    for restore in [false, true] {
        for mode in [ExecutionMode::Flash, ExecutionMode::Recovery] {
            let (plan, state) = setup_explicit_crossflash(restore);
            for stage in plan.stages() {
                let startup = stage.settings.startup_plan().unwrap();
                assert_eq!(
                    startup.policy(),
                    crate::startup::checks::Policy::ExplicitCrossflash
                );
                assert!(stage.settings.startup_setting().is_none());
                assert!(stage.settings.startup_selection().is_none());
            }
            let result = run(&plan, &state, mode).unwrap();
            assert!(result.kernel_verified && result.normal_verified);
            assert_eq!(result.completed_stages, if restore { 2 } else { 1 });
            assert!(state.borrow().parameter_writes.is_empty());
        }
    }
}

#[test]
fn explicit_crossflash_descriptor_change_refuses_without_parameter_writes() {
    for restore in [false, true] {
        let (plan, state) = setup_explicit_crossflash(restore);
        state.borrow_mut().change_descriptor_at = Some(2);
        let error = run(&plan, &state, ExecutionMode::Flash).unwrap_err();
        assert!(!error.firmware_write_started());
        assert_eq!(state.borrow().entries, 0);
        assert!(state.borrow().parameter_writes.is_empty());
    }
}

#[test]
fn explicit_crossflash_all_firmware_write_failures_stop_without_retry() {
    let (plan, state) = setup_explicit_crossflash(true);
    run(&plan, &state, ExecutionMode::Flash).unwrap();
    let count = state.borrow().writes;
    for fail in 1..=count {
        let (plan, state) = setup_explicit_crossflash(true);
        state.borrow_mut().fail_write = Some(fail);
        assert!(
            run(&plan, &state, ExecutionMode::Flash).is_err(),
            "write {fail}"
        );
        assert_eq!(state.borrow().writes, fail, "unexpected retry at {fail}");
        assert!(state.borrow().parameter_writes.is_empty());
    }
}

#[test]
fn final_filter_requirement_is_checked_before_any_bridge_write() {
    use crate::filters::prerequisites::{OwnedWord, Word};
    for (actual, read_failure) in [(0, false), (1, true), (1, false)] {
        let (plan, state) = setup(true);
        let mut stages = plan.stages().to_vec();
        assert!(stages.len() > 1);
        let last = stages.last_mut().unwrap();
        last.settings = last.settings.clone().with_correction(Some(
            crate::compatibility::PreparedCorrection::native(
                last.normal.image.clone(),
                &[],
                vec![OwnedWord {
                    filter: "phase",
                    word: Word {
                        parameter: 0x28f,
                        value: 1,
                    },
                }],
                Vec::new(),
            ),
        ));
        state.borrow_mut().parameter = actual;
        state.borrow_mut().fail_prerequisite_read = read_failure;
        let result = execute_stages(
            &stages,
            FlashTransport {
                reads: &mut Port(state.clone()),
                writes: &mut Port(state.clone()),
            },
            &mut Clock::default(),
            ExecutionMode::Flash,
        );
        let s = state.borrow();
        assert_eq!(s.prerequisite_reads, 1);
        if actual != 1 || read_failure {
            let error = result.unwrap_err();
            assert!(matches!(error, ExecutionError::BeforeWrite(_)));
            assert!(!error.write_started());
            assert_eq!(s.writes, 0);
            assert_eq!(s.entries, 0);
            assert!(s.parameter_writes.is_empty());
        } else {
            assert!(result.is_ok(), "{result:?}");
        }
    }
}

#[test]
fn read_only_requirement_cannot_be_overwritten_by_settings() {
    use crate::filters::prerequisites::{OwnedWord, Word};
    let (plan, state) = setup(true);
    let mut stages = plan.stages().to_vec();
    let last = stages.last_mut().unwrap();
    last.settings = crate::settings::update::Plan::target(
        Some(crate::startup::Setting {
            parameter: 0x9f,
            value: 1,
            explicit: true,
        }),
        false,
    );
    last.settings = last.settings.clone().with_correction(Some(
        crate::compatibility::PreparedCorrection::native(
            last.normal.image.clone(),
            &[],
            vec![OwnedWord {
                filter: "startup",
                word: Word {
                    parameter: 0x9f,
                    value: 1,
                },
            }],
            Vec::new(),
        ),
    ));
    let error = execute_stages(
        &stages,
        FlashTransport {
            reads: &mut Port(state.clone()),
            writes: &mut Port(state.clone()),
        },
        &mut Clock::default(),
        ExecutionMode::Flash,
    )
    .unwrap_err();
    assert!(!error.write_started());
    assert_eq!(state.borrow().writes, 0);
    assert_eq!(state.borrow().descriptor_reads, 0);
}

#[test]
fn conflicting_stage_requirements_refuse_before_device_io() {
    use crate::filters::prerequisites::{OwnedWord, Word};
    let (plan, state) = setup(true);
    let mut stages = plan.stages().to_vec();
    for (index, stage) in stages.iter_mut().enumerate() {
        stage.settings = stage.settings.clone().with_correction(Some(
            crate::compatibility::PreparedCorrection::native(
                stage.normal.image.clone(),
                &[],
                vec![OwnedWord {
                    filter: "phase",
                    word: Word {
                        parameter: 0x28f,
                        value: index as u16,
                    },
                }],
                Vec::new(),
            ),
        ));
    }
    let error = execute_stages(
        &stages,
        FlashTransport {
            reads: &mut Port(state.clone()),
            writes: &mut Port(state.clone()),
        },
        &mut Clock::default(),
        ExecutionMode::Flash,
    )
    .unwrap_err();
    assert!(!error.write_started());
    assert_eq!(state.borrow().writes, 0);
    assert_eq!(state.borrow().prerequisite_reads, 0);
    assert_eq!(state.borrow().descriptor_reads, 0);
}

#[test]
fn recovery_loader_does_not_bypass_read_only_filter_requirements() {
    use crate::filters::prerequisites::{OwnedWord, Word};
    let (plan, state) = setup(true);
    let mut stages = plan.stages().to_vec();
    let last = stages.last_mut().unwrap();
    last.settings = last.settings.clone().with_correction(Some(
        crate::compatibility::PreparedCorrection::native(
            last.normal.image.clone(),
            &[],
            vec![OwnedWord {
                filter: "phase",
                word: Word {
                    parameter: 0x28f,
                    value: 1,
                },
            }],
            Vec::new(),
        ),
    ));
    state.borrow_mut().loader = true;
    let error = execute_stages(
        &stages,
        FlashTransport {
            reads: &mut Port(state.clone()),
            writes: &mut Port(state.clone()),
        },
        &mut Clock::default(),
        ExecutionMode::Recovery,
    )
    .unwrap_err();
    assert!(!error.write_started());
    assert_eq!(state.borrow().writes, 0);
    assert_eq!(state.borrow().prerequisite_reads, 0);
}

fn with_word_write(stage: &mut PreparedStage, value: u16) {
    use crate::filters::prerequisites::{OwnedWord, Word};
    stage.settings = stage.settings.clone().with_correction(Some(
        crate::compatibility::PreparedCorrection::native(
            stage.normal.image.clone(),
            &[],
            Vec::new(),
            vec![OwnedWord {
                filter: "startup-prerequisite",
                word: Word {
                    parameter: 0x9f,
                    value,
                },
            }],
        ),
    ));
}

fn execute_with(
    stages: &[PreparedStage],
    state: &Rc<RefCell<State>>,
    mode: ExecutionMode,
) -> Result<FlashOutcome, ExecutionError<&'static str>> {
    execute_stages(
        stages,
        FlashTransport {
            reads: &mut Port(state.clone()),
            writes: &mut Port(state.clone()),
        },
        &mut Clock::default(),
        mode,
    )
}

#[test]
fn a_correction_word_write_runs_in_the_first_stage_settings_transaction() {
    let (plan, state) = setup(false);
    let mut stages = plan.stages().to_vec();
    assert_eq!(stages.len(), 1);
    with_word_write(&mut stages[0], 0xfe34);
    execute_with(&stages, &state, ExecutionMode::Flash).unwrap();
    assert_eq!(state.borrow().parameter_writes, [0xfe34]);
    assert_eq!(state.borrow().parameter, 0xfe34);
}

#[test]
fn a_correction_word_write_refuses_in_the_loader_before_any_write() {
    let (plan, state) = setup(false);
    let mut stages = plan.stages().to_vec();
    with_word_write(&mut stages[0], 0xfe34);
    state.borrow_mut().loader = true;
    let error = execute_with(&stages, &state, ExecutionMode::Recovery).unwrap_err();
    assert!(!error.write_started());
    assert_eq!(state.borrow().writes, 0);
    assert!(state.borrow().parameter_writes.is_empty());
}

#[test]
fn a_correction_word_write_after_the_first_stage_refuses_before_any_write() {
    let (plan, state) = setup_handoff_bridge(false);
    let mut stages = plan.stages().to_vec();
    assert!(stages.len() > 1);
    with_word_write(stages.last_mut().unwrap(), 0xfe34);
    let error = execute_with(&stages, &state, ExecutionMode::Flash).unwrap_err();
    assert!(!error.write_started());
    assert_eq!(state.borrow().writes, 0);
    assert!(state.borrow().parameter_writes.is_empty());
}

#[test]
fn a_marker_route_writes_the_shared_correction_word_once_before_the_first_transfer() {
    // prepare_inner gives the marker intermediate and the target the same
    // corrected settings; only the first applies them.
    let (plan, state) = setup(true);
    let mut stages = plan.stages().to_vec();
    assert_eq!(stages.len(), 2);
    assert_eq!(stages[0].normal_image(), stages[1].normal_image());
    for stage in &mut stages {
        with_word_write(stage, 0xfe34);
    }
    let outcome = execute_with(&stages, &state, ExecutionMode::Flash).unwrap();
    assert_eq!(outcome.completed_stages, 2);
    assert_eq!(state.borrow().parameter_writes, [0xfe34]);
    assert_eq!(state.borrow().parameter_write_entries, [0]);
    assert_eq!(state.borrow().parameter, 0xfe34);
}

#[test]
fn a_correction_word_write_refuses_when_the_receiver_turns_out_to_be_a_loader() {
    // Even if preflight would observe the running receiver and the stage's
    // own identity read then reports the loader, the corrected firmware is
    // never transferred without its word: Recovery refuses the write.
    let (plan, state) = setup(false);
    let mut stages = plan.stages().to_vec();
    assert_eq!(stages.len(), 1);
    with_word_write(&mut stages[0], 0xfe34);
    state.borrow_mut().loader_after_identities = Some(1);
    let error = execute_with(&stages, &state, ExecutionMode::Recovery).unwrap_err();
    assert!(!error.write_started(), "{error}");
    assert_eq!(state.borrow().writes, 0);
    assert_eq!(state.borrow().entries, 0);
    assert!(state.borrow().parameter_writes.is_empty());
}

#[test]
fn a_flash_word_write_refuses_when_the_stage_bind_finds_a_loader() {
    // Preflight binds the running receiver; the drive then reports the
    // loader at the stage's own bind. Flash never accepts a loader there, so
    // the corrected firmware is never transferred without its word.
    let (plan, state) = setup(false);
    let mut stages = plan.stages().to_vec();
    assert_eq!(stages.len(), 1);
    with_word_write(&mut stages[0], 0xfe34);
    state.borrow_mut().loader_after_identities = Some(1);
    let error = execute_with(&stages, &state, ExecutionMode::Flash).unwrap_err();
    assert!(
        matches!(
            error,
            ExecutionError::IdentityMismatch { target: false, .. }
        ),
        "{error}"
    );
    assert!(!error.write_started(), "{error}");
    assert_eq!(state.borrow().identities, 2);
    assert_eq!(state.borrow().writes, 0);
    assert_eq!(state.borrow().entries, 0);
    assert!(state.borrow().parameter_writes.is_empty());
}

#[test]
fn check_plan_refuses_marker_route_word_writes_that_differ_from_stage_zero() {
    // A marker intermediate reuses stage 0's settings transaction, so its
    // later stage may only repeat stage 0's exact writes.
    for (first, second) in [(None, Some(0xfe34)), (Some(0xfe34), Some(0xfe35))] {
        let (mut plan, state) = setup(true);
        assert_eq!(plan.stages().len(), 2);
        if let Some(value) = first {
            with_word_write(&mut plan.stages[0], value);
        }
        if let Some(value) = second {
            with_word_write(&mut plan.stages[1], value);
        }
        let error = plan.check_plan(ExecutionMode::Flash).unwrap_err();
        assert_eq!(error.reason(), PlanReason::StartupWordPlacement);
        assert!(run(&plan, &state, ExecutionMode::Flash).is_err());
        assert_eq!(state.borrow().identities, 0);
        assert_eq!(state.borrow().writes, 0);
    }
}

#[test]
fn word_write_refusals_precede_the_live_requirement_reads() {
    use crate::filters::prerequisites::{OwnedWord, Word};
    // A Recovery word write and a misplaced handoff word write both refuse
    // before the read-only requirement preflight binds the receiver.
    for (handoff, mode) in [
        (false, ExecutionMode::Recovery),
        (true, ExecutionMode::Flash),
    ] {
        let (plan, state) = if handoff {
            setup_handoff_bridge(false)
        } else {
            setup(false)
        };
        let mut stages = plan.stages().to_vec();
        let last = stages.last_mut().unwrap();
        last.settings = last.settings.clone().with_correction(Some(
            crate::compatibility::PreparedCorrection::native(
                last.normal.image.clone(),
                &[],
                vec![OwnedWord {
                    filter: "phase",
                    word: Word {
                        parameter: 0x28f,
                        value: 1,
                    },
                }],
                vec![OwnedWord {
                    filter: "startup-prerequisite",
                    word: Word {
                        parameter: 0x9f,
                        value: 0xfe34,
                    },
                }],
            ),
        ));
        let error = execute_with(&stages, &state, mode).unwrap_err();
        assert!(
            matches!(&error, ExecutionError::BeforeWrite(source)
                if matches!(source.as_ref(), ExecutionError::Plan(_))),
            "{error}"
        );
        assert_eq!(state.borrow().identities, 0, "{error}");
        assert_eq!(state.borrow().prerequisite_reads, 0);
        assert_eq!(state.borrow().writes, 0);
    }
}

#[test]
fn a_failed_correction_word_write_rolls_back_before_any_firmware_write() {
    let (plan, state) = setup(false);
    let mut stages = plan.stages().to_vec();
    with_word_write(&mut stages[0], 0xfe34);
    state.borrow_mut().fail_write = Some(1);
    let error = execute_with(&stages, &state, ExecutionMode::Flash).unwrap_err();
    assert!(!error.firmware_write_started(), "{error}");
    assert_eq!(state.borrow().entries, 0);
    assert_eq!(state.borrow().finishes, 0);
    assert_eq!(state.borrow().parameter, 0xfe24);
    assert!(matches!(
        &error,
        ExecutionError::Startup(source)
            if matches!(source.as_ref(), crate::startup::migration::Error::Change { .. })
    ));
}

#[test]
fn a_correction_word_write_is_rolled_back_when_the_stage_stops_before_transfer() {
    let (plan, state) = setup(false);
    let mut stages = plan.stages().to_vec();
    with_word_write(&mut stages[0], 0xfe34);
    // Preflight, stage binding, then the transfer binding inside the
    // settings transaction: refuse the third host check.
    let mut clock = Clock {
        deny_check: Some(3),
        ..Clock::default()
    };
    let error = execute_stages(
        &stages,
        FlashTransport {
            reads: &mut Port(state.clone()),
            writes: &mut Port(state.clone()),
        },
        &mut clock,
        ExecutionMode::Flash,
    )
    .unwrap_err();
    assert!(!error.firmware_write_started(), "{error}");
    assert_eq!(state.borrow().entries, 0);
    assert_eq!(state.borrow().parameter_writes, [0xfe34, 0xfe24]);
    assert_eq!(state.borrow().parameter, 0xfe24);
}

#[test]
fn a_correction_word_write_refuses_in_recovery_even_on_a_running_receiver() {
    // Recovery plans from caller-supplied Current evidence; the word write is
    // normal-mode Flash only, so refuse before any I/O.
    let (plan, state) = setup(false);
    let mut stages = plan.stages().to_vec();
    with_word_write(&mut stages[0], 0xfe34);
    let error = execute_with(&stages, &state, ExecutionMode::Recovery).unwrap_err();
    assert!(!error.write_started(), "{error}");
    assert_eq!(state.borrow().writes, 0);
    assert_eq!(state.borrow().identities, 0);
    assert!(state.borrow().parameter_writes.is_empty());
}

#[test]
fn a_prerequisite_mismatch_names_the_word_in_hex() {
    use crate::filters::prerequisites::{CheckError, OwnedWord, Word};
    let error: ExecutionError<&'static str> = ExecutionError::Prerequisite(CheckError::Mismatch {
        required: OwnedWord {
            filter: "phase",
            word: Word {
                parameter: 0x28f,
                value: 1,
            },
        },
        actual: 0,
    });
    assert_eq!(
        error.to_string(),
        "read-only correction prerequisite: phase requires word 0x28f == 0x0001; the drive holds 0x0000"
    );
}

#[test]
fn check_plan_admits_a_marker_route_with_a_shared_stage_zero_word_write() {
    let (mut plan, _) = setup(true);
    assert_eq!(plan.stages().len(), 2);
    assert_eq!(
        plan.stages()[0].bridge(),
        Some(crate::receiver::BridgeKind::ReceiverMarker)
    );
    for stage in &mut plan.stages {
        with_word_write(stage, 0xfe34);
    }
    assert_eq!(plan.check_plan(ExecutionMode::Flash), Ok(()));
}

#[test]
fn check_plan_refuses_a_handoff_route_word_write_outside_stage_zero_in_every_mode() {
    let (mut plan, state) = setup_handoff_bridge(false);
    assert!(plan.stages().len() > 1);
    assert_eq!(
        plan.stages()[0].bridge(),
        Some(crate::receiver::BridgeKind::KernelHandoff)
    );
    with_word_write(&mut plan.stages[0], 0xfe34);
    with_word_write(plan.stages.last_mut().unwrap(), 0xfe35);
    for mode in [ExecutionMode::Flash, ExecutionMode::Recovery] {
        let error = plan.check_plan(mode).unwrap_err();
        assert_eq!(
            error.detail(),
            "a startup word write must precede the first transfer"
        );
        assert_eq!(crate::CodedError::code(&error), "pioneer.execute.plan");
        // The executor reports the same refusal before any device I/O.
        let executed = plan
            .execute(
                FlashTransport {
                    reads: &mut Port(state.clone()),
                    writes: &mut Port(state.clone()),
                },
                &mut Clock::default(),
                mode,
            )
            .unwrap_err();
        assert!(
            matches!(&executed, ExecutionError::BeforeWrite(source)
                if matches!(source.as_ref(), ExecutionError::Plan(reason) if *reason == error.detail())),
            "{executed}"
        );
        assert_eq!(state.borrow().identities, 0);
        assert_eq!(state.borrow().writes, 0);
    }
}

#[test]
fn check_plan_refuses_any_word_write_in_recovery() {
    let (mut plan, _) = setup(false);
    with_word_write(&mut plan.stages[0], 0xfe34);
    assert_eq!(plan.check_plan(ExecutionMode::Flash), Ok(()));
    assert_eq!(
        plan.check_plan(ExecutionMode::Recovery)
            .unwrap_err()
            .detail(),
        "a startup word write is not performed in Recovery mode"
    );
}

#[test]
fn check_plan_refuses_an_empty_plan() {
    let (mut plan, _) = setup(false);
    plan.stages.clear();
    for mode in [ExecutionMode::Flash, ExecutionMode::Recovery] {
        assert_eq!(
            plan.check_plan(mode).unwrap_err().detail(),
            "empty update sequence"
        );
    }
}

#[test]
fn check_plan_admits_a_plan_without_word_writes_in_recovery() {
    for restore in [false, true] {
        let (plan, _) = setup(restore);
        assert!(plan
            .stages()
            .iter()
            .all(|stage| stage.settings().word_writes().is_empty()));
        assert_eq!(plan.check_plan(ExecutionMode::Recovery), Ok(()));
        assert_eq!(plan.check_plan(ExecutionMode::Flash), Ok(()));
    }
}

#[test]
fn check_plan_refuses_conflicting_read_only_requirements() {
    use crate::filters::prerequisites::{OwnedWord, Word};
    let (mut plan, _) = setup(true);
    for (index, stage) in plan.stages.iter_mut().enumerate() {
        stage.settings = stage.settings.clone().with_correction(Some(
            crate::compatibility::PreparedCorrection::native(
                stage.normal.image.clone(),
                &[],
                vec![OwnedWord {
                    filter: "phase",
                    word: Word {
                        parameter: 0x28f,
                        value: index as u16,
                    },
                }],
                Vec::new(),
            ),
        ));
    }
    assert_eq!(
        plan.check_plan(ExecutionMode::Flash).unwrap_err().detail(),
        "invalid or conflicting read-only requirements"
    );
}

fn normal_only() -> PreparedNormal {
    let installed = fixture(false, 1);
    Receiver::from_installed(&installed)
        .unwrap()
        .prepare_normal(installed.normal_transfer())
        .unwrap()
}

fn with_requirements(stage: &mut PreparedStage, words: &[(u16, u16)]) {
    use crate::filters::prerequisites::{OwnedWord, Word};
    stage.settings = stage.settings.clone().with_correction(Some(
        crate::compatibility::PreparedCorrection::native(
            stage.normal.image.clone(),
            &[],
            words
                .iter()
                .map(|&(parameter, value)| OwnedWord {
                    filter: "phase",
                    word: Word { parameter, value },
                })
                .collect(),
            Vec::new(),
        ),
    ));
}

/// The Normal-only executor reports `error` before any device I/O.
fn assert_normal_only_refuses_before_io(plan: &PreparedNormal, error: PlanError) {
    let (_, state) = setup(false);
    let executed = plan
        .flash(
            FlashTransport {
                reads: &mut Port(state.clone()),
                writes: &mut Port(state.clone()),
            },
            &mut Clock::default(),
        )
        .unwrap_err();
    let reason = match &executed {
        ExecutionError::Plan(reason) => *reason,
        ExecutionError::BeforeWrite(source) => match source.as_ref() {
            ExecutionError::Plan(reason) => *reason,
            other => panic!("{other}"),
        },
        other => panic!("{other}"),
    };
    assert_eq!(reason, error.detail());
    assert_eq!(crate::CodedError::code(&executed), "pioneer.execute.plan");
    let s = state.borrow();
    assert_eq!(s.identities, 0);
    assert_eq!(s.writes, 0);
    assert_eq!(s.prerequisite_reads, 0);
    assert_eq!(s.descriptor_reads, 0);
}

#[test]
fn normal_only_check_plan_admits_a_plain_plan_in_every_mode() {
    let plan = normal_only();
    assert!(plan.settings().word_writes().is_empty());
    for mode in [ExecutionMode::Flash, ExecutionMode::Recovery] {
        assert_eq!(plan.check_plan(mode), Ok(()));
    }
    let (_, state) = setup(false);
    assert!(plan
        .flash(
            FlashTransport {
                reads: &mut Port(state.clone()),
                writes: &mut Port(state.clone()),
            },
            &mut Clock::default(),
        )
        .is_ok());
}

#[test]
fn normal_only_check_plan_refuses_a_word_write_only_in_recovery() {
    let mut plan = normal_only();
    with_word_write(&mut plan.stage, 0xfe34);
    assert_eq!(plan.check_plan(ExecutionMode::Flash), Ok(()));
    let error = plan.check_plan(ExecutionMode::Recovery).unwrap_err();
    assert_eq!(
        error.detail(),
        "a startup word write is not performed in Recovery mode"
    );
    assert_eq!(crate::CodedError::code(&error), "pioneer.execute.plan");
}

#[test]
fn normal_only_check_plan_refuses_missing_installed_kernel_evidence() {
    let mut plan = normal_only();
    plan.stage.receiver.installed_kernel = None;
    for mode in [ExecutionMode::Flash, ExecutionMode::Recovery] {
        let error = plan.check_plan(mode).unwrap_err();
        assert_eq!(error.detail(), "installed Kernel evidence unavailable");
        assert_eq!(crate::CodedError::code(&error), "pioneer.execute.plan");
    }
    assert_normal_only_refuses_before_io(&plan, plan.check_plan(ExecutionMode::Flash).unwrap_err());
}

#[test]
fn normal_only_check_plan_refuses_invalid_or_conflicting_read_only_requirements() {
    for words in [&[(0x28f, 0), (0x28f, 1)][..], &[(0x400, 0)][..]] {
        let mut plan = normal_only();
        with_requirements(&mut plan.stage, words);
        for mode in [ExecutionMode::Flash, ExecutionMode::Recovery] {
            assert_eq!(
                plan.check_plan(mode).unwrap_err().detail(),
                "invalid or conflicting read-only requirements",
                "{words:?}"
            );
        }
        assert_normal_only_refuses_before_io(
            &plan,
            plan.check_plan(ExecutionMode::Flash).unwrap_err(),
        );
    }
}

#[test]
fn normal_only_check_plan_refuses_a_settings_write_over_a_read_only_requirement() {
    let mut plan = normal_only();
    plan.stage.settings = crate::settings::update::Plan::target(
        Some(crate::startup::Setting {
            parameter: 0x9f,
            value: 1,
            explicit: true,
        }),
        false,
    );
    with_requirements(&mut plan.stage, &[(0x9f, 1)]);
    let error = plan.check_plan(ExecutionMode::Flash).unwrap_err();
    assert_eq!(
        error.detail(),
        "settings write overlaps a read-only requirement"
    );
    assert_normal_only_refuses_before_io(&plan, error);
}

#[test]
fn plan_error_reason_names_the_refusing_rule() {
    use crate::receiver::PlanReason;
    let (mut empty, _) = setup(false);
    empty.stages.clear();
    let (mut handoff, _) = setup_handoff_bridge(false);
    with_word_write(&mut handoff.stages[0], 0xfe34);
    with_word_write(handoff.stages.last_mut().unwrap(), 0xfe35);
    let (mut recovery, _) = setup(false);
    with_word_write(&mut recovery.stages[0], 0xfe34);
    let mut requirements = normal_only();
    with_requirements(&mut requirements.stage, &[(0x28f, 0), (0x28f, 1)]);
    // A transfer refusal is a transfer refusal whatever the settings carry.
    let mut transfer = normal_only();
    with_requirements(&mut transfer.stage, &[(0x28f, 1)]);
    transfer.stage.receiver.installed_kernel = None;
    for (error, kind) in [
        (empty.check_plan(ExecutionMode::Flash), PlanReason::Empty),
        (
            handoff.check_plan(ExecutionMode::Flash),
            PlanReason::StartupWordPlacement,
        ),
        (
            recovery.check_plan(ExecutionMode::Recovery),
            PlanReason::StartupWordInRecovery,
        ),
        (
            requirements.check_plan(ExecutionMode::Flash),
            PlanReason::Requirements,
        ),
        (
            transfer.check_plan(ExecutionMode::Flash),
            PlanReason::Transfer,
        ),
    ] {
        let error = error.unwrap_err();
        assert_eq!(error.reason(), kind, "{error}");
        assert_eq!(crate::CodedError::code(&error), "pioneer.execute.plan");
        // `kind()` is the host category, as on every other error.
        assert_eq!(
            crate::CodedError::kind(&error),
            crate::error_codes::kind_for_code("pioneer.execute.plan")
        );
    }
    assert_eq!(recovery.check_plan(ExecutionMode::Flash), Ok(()));
}
