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
#[derive(Default)]
struct State {
    installed_id: Option<Identity>,
    target_id: Option<Identity>,
    descriptor: Vec<u8>,
    normal: Vec<u8>,
    kernels: Vec<Vec<u8>>,
    parameter: u16,
    parameter_writes: Vec<u16>,
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
    let plan = Receiver::from_installed(&installed)
        .unwrap()
        .prepare(target.clone())
        .unwrap();
    let layout = target
        .kernel()
        .normal_layout()
        .expect("fixture Normal layout");
    layout
        .validate(&target.normal().image)
        .expect("fixture Normal body");
    let kernels = if plan.restoration_receiver().is_some() {
        vec![
            plan.first_kernel_image().to_vec(),
            plan.final_kernel_image().to_vec(),
        ]
    } else {
        vec![plan.final_kernel_image().to_vec()]
    };
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
                } else if command == cdb::enter_update() {
                    s.entries += 1;
                    s.loader = true;
                } else if command == cdb::finish() {
                    s.finishes += 1;
                    s.loader = s.stay_loader;
                }
                Ok(bytes.len())
            }
            Data::In(bytes) => {
                if command == cdb::read_parameter_word(0x9f).unwrap() {
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
        None
    }
}
#[derive(Default)]
struct Clock {
    elapsed: Duration,
    deny: Option<FlashPass>,
    checks: usize,
    deny_check: Option<usize>,
}
impl UpdateRuntime for Clock {
    fn elapsed(&self) -> Duration {
        self.elapsed
    }
    fn sleep(&mut self, d: Duration) {
        self.elapsed += d;
    }
}
impl ExecutionRuntime<&'static str> for Clock {
    fn check_pass(&mut self, pass: FlashPass) -> Result<(), &'static str> {
        self.checks += 1;
        if self.deny == Some(pass) || self.deny_check == Some(self.checks) {
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
        let result = plan
            .flash(
                FlashTransport {
                    reads: &mut Port(state.clone()),
                    writes: &mut Port(state.clone()),
                },
                &mut Clock::default(),
            )
            .unwrap();
        assert!(result.kernel_verified && result.normal_verified);
        assert_eq!(result.completed_passes, if restore { 2 } else { 1 });
        assert_eq!(state.borrow().parameter_writes, [0xffff]);
        assert_eq!(state.borrow().finishes, result.completed_passes);
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
    assert_eq!(result.completed_passes, 2);
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
    for wrong in 0..4 {
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
    state.borrow_mut().wrong_target = Some(1);
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
            FlashPass::Initial,
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
fn longer_oem_revision_compares_the_exact_four_byte_inquiry_projection() {
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
    assert_eq!(
        run(&plan, &state, ExecutionMode::Flash)
            .unwrap_err()
            .phase(),
        "target startup"
    );
}

#[test]
fn malformed_non_ascii_revision_never_matches_inquiry_projection() {
    let firmware = branded_fixture("PIONEER", "0.05é");
    let (plan, state) = setup_updates(firmware.clone(), firmware);
    assert_eq!(
        run(&plan, &state, ExecutionMode::Flash)
            .unwrap_err()
            .phase(),
        "target startup"
    );
}
