use super::*;
use crate::{cdb, drive::Data, envelope::Envelope, receiver::Receiver, DriveClass, Role};
use std::{cell::RefCell, rc::Rc, time::Duration};

#[derive(Default)]
struct State {
    descriptor: [u8; DESCRIPTOR_LEN],
    memory: Vec<u8>,
    kernels: Vec<Vec<u8>>,
    normals: Vec<Vec<u8>>,
    entries: usize,
    finishes: usize,
    descriptor_reads: usize,
    change_descriptor_at: Option<usize>,
    short_read: bool,
    short_after_finish: Option<usize>,
    corrupt_pass: Option<usize>,
    fail_write: Option<usize>,
    writes: usize,
}
struct Port {
    state: Rc<RefCell<State>>,
    reads: bool,
}
impl Transport for Port {
    type Error = &'static str;
    fn exec(&mut self, command: &[u8], data: Data<'_>) -> Result<usize, Self::Error> {
        let mut state = self.state.borrow_mut();
        if self.reads {
            if command == cdb::knock() {
                assert!(matches!(data, Data::None));
                return Ok(0);
            }
            let Data::In(bytes) = data else {
                panic!("write sent through read adapter")
            };
            let address = u32::from_be_bytes([0, command[3], command[4], command[5]]);
            assert_eq!(command, cdb::read_memory(address, bytes.len() as u32));
            if state.short_read || state.short_after_finish == Some(state.finishes) {
                return Ok(bytes.len() - 1);
            }
            if address == DESCRIPTOR_ADDRESS && bytes.len() == DESCRIPTOR_LEN {
                state.descriptor_reads += 1;
                if state.change_descriptor_at == Some(state.descriptor_reads) {
                    state.descriptor[0] ^= 1;
                }
                bytes.copy_from_slice(&state.descriptor);
            } else {
                let offset = (address - crate::image::KERNEL_BASE) as usize;
                bytes.copy_from_slice(&state.memory[offset..offset + bytes.len()]);
            }
            return Ok(bytes.len());
        }
        assert_ne!(
            command,
            cdb::knock(),
            "unlock sent through strict write adapter"
        );
        match data {
            Data::Out(bytes) => {
                state.writes += 1;
                if state.fail_write == Some(state.writes) {
                    return Err("injected write failure");
                }
                if command == cdb::enter_update() {
                    state.entries += 1;
                    state.kernels.push(Vec::new());
                    state.normals.push(Vec::new());
                } else if command == cdb::finish() {
                    state.finishes += 1;
                    let kernel = state.kernels.last().unwrap();
                    if !kernel.is_empty() {
                        state.memory = Envelope::load(kernel).unwrap().image;
                        if state.corrupt_pass == Some(state.finishes) {
                            state.memory[17] ^= 1;
                        }
                    }
                } else {
                    let role = if command[2] == cdb::transfer(Role::Kernel, 0, 0)[2] {
                        Role::Kernel
                    } else {
                        Role::Normal
                    };
                    let transfer = match role {
                        Role::Kernel => state.kernels.last_mut().unwrap(),
                        Role::Normal => state.normals.last_mut().unwrap(),
                    };
                    assert_eq!(
                        command,
                        cdb::transfer(role, transfer.len() as u32, bytes.len() as u32)
                    );
                    transfer.extend_from_slice(bytes);
                }
                Ok(bytes.len())
            }
            Data::In(bytes) => {
                if command == cdb::inquiry(0x60) {
                    bytes[32..36].copy_from_slice(b"000 ");
                } else {
                    assert!(
                        command == cdb::get_event_status() || command == cdb::test_unit_ready()
                    );
                }
                Ok(bytes.len())
            }
            Data::None => panic!("unexpected no-data update command"),
        }
    }
    fn sense(&self) -> Option<(u8, u8, u8)> {
        None
    }
}
#[derive(Default)]
struct Clock {
    now: Duration,
    starts: Vec<(usize, usize)>,
    deny: Option<FlashPass>,
}
impl UpdateRuntime for Clock {
    fn elapsed(&self) -> Duration {
        self.now
    }
    fn sleep(&mut self, duration: Duration) {
        self.now += duration;
    }
    fn starting(&mut self, kernel: usize, normal: usize) {
        self.starts.push((kernel, normal));
    }
}
impl FlashRuntime<&'static str> for Clock {
    fn prepare_pass(&mut self, pass: FlashPass) -> Result<UpdateOptions, &'static str> {
        if self.deny == Some(pass) {
            return Err("medium inserted");
        }
        Ok(UpdateOptions {
            class: DriveClass::Bd,
            recover: false,
        })
    }
}
fn plan(restore: bool) -> PreparedUpdate {
    let installed = super::super::preparation::tests::update(restore, 1, 0x12, true);
    Receiver::from_installed(&installed)
        .unwrap()
        .prepare(super::super::preparation::tests::update(
            false, 0, 0x12, true,
        ))
        .unwrap()
}
fn state(plan: &PreparedUpdate) -> Rc<RefCell<State>> {
    Rc::new(RefCell::new(State {
        descriptor: plan.control[..DESCRIPTOR_LEN].try_into().unwrap(),
        ..State::default()
    }))
}
fn run(
    plan: &PreparedUpdate,
    state: &Rc<RefCell<State>>,
) -> Result<Clock, FlashError<&'static str>> {
    let mut reads = Port {
        state: state.clone(),
        reads: true,
    };
    let mut writes = Port {
        state: state.clone(),
        reads: false,
    };
    let mut clock = Clock::default();
    plan.flash(
        FlashTransport {
            reads: &mut reads,
            writes: &mut writes,
        },
        &mut clock,
    )?;
    Ok(clock)
}

#[test]
fn executes_exact_prepared_passes_and_verifies_final_kernel() {
    for restore in [false, true] {
        let plan = plan(restore);
        let state = state(&plan);
        let clock = run(&plan, &state).unwrap();
        let state = state.borrow();
        let passes = if restore { 2 } else { 1 };
        assert_eq!(state.entries, passes);
        assert_eq!(state.finishes, passes);
        assert_eq!(state.descriptor_reads, 2 * passes);
        assert_eq!(clock.starts.len(), passes);
        assert_eq!(state.kernels[0], plan.kernel_transfer());
        if restore {
            assert_eq!(
                state.kernels[1],
                plan.restoration_kernel_transfer().unwrap()
            );
        }
        assert!(state
            .normals
            .iter()
            .all(|bytes| bytes == plan.normal_transfer()));
        assert_eq!(state.memory, plan.final_kernel_image());
    }
}

#[test]
fn descriptor_failures_prevent_entry_and_identify_the_pass() {
    let plan = plan(true);
    for read in 1..=4 {
        let state = state(&plan);
        state.borrow_mut().change_descriptor_at = Some(read);
        let error = run(&plan, &state).err().unwrap();
        let expected = if read <= 2 {
            FlashPass::Initial
        } else {
            FlashPass::Restoration
        };
        match error {
            FlashError::DescriptorMismatch { pass } if read % 2 == 1 => assert_eq!(pass, expected),
            FlashError::DescriptorChanged { pass } if read % 2 == 0 => assert_eq!(pass, expected),
            error => panic!("unexpected {error:?}"),
        }
        assert_eq!(state.borrow().entries, usize::from(read > 2));
    }
    let state = state(&plan);
    state.borrow_mut().short_read = true;
    assert!(matches!(
        run(&plan, &state),
        Err(FlashError::DescriptorRead {
            pass: FlashPass::Initial,
            source: drive::Error::Short { .. }
        })
    ));
    assert_eq!(state.borrow().entries, 0);
}

#[test]
fn readback_mismatch_stops_before_any_later_pass() {
    let plan = plan(true);
    for index in 1..=2 {
        let state = state(&plan);
        state.borrow_mut().corrupt_pass = Some(index);
        let error = run(&plan, &state).err().unwrap();
        assert!(
            matches!(error, FlashError::ReadbackMismatch { pass, address }
            if address == crate::image::KERNEL_BASE + 17 && pass ==
                if index == 1 { FlashPass::Initial } else { FlashPass::Restoration })
        );
        assert_eq!(state.borrow().entries, index);
    }
}

#[test]
fn every_write_failure_stops_without_retry_or_later_pass() {
    let plan = plan(true);
    let baseline = state(&plan);
    run(&plan, &baseline).unwrap();
    let total = baseline.borrow().writes;
    for index in 1..=total {
        let state = state(&plan);
        state.borrow_mut().fail_write = Some(index);
        assert!(matches!(run(&plan, &state), Err(FlashError::Update { .. })));
        assert_eq!(state.borrow().writes, index);
    }
}

#[test]
fn short_kernel_readback_stops_before_restoration() {
    let plan = plan(true);
    for index in 1..=2 {
        let state = state(&plan);
        state.borrow_mut().short_after_finish = Some(index);
        assert!(matches!(run(&plan, &state), Err(FlashError::Readback {
            pass, source: drive::Error::Short { .. }
        }) if pass == if index == 1 { FlashPass::Initial } else { FlashPass::Restoration }));
        assert_eq!(state.borrow().entries, index);
    }
}

#[test]
fn normal_only_binds_receiver_and_never_writes_or_reads_kernel() {
    let installed = super::super::preparation::tests::update(true, 1, 0x12, true);
    let receiver = Receiver::from_installed(&installed).unwrap();
    let plan = receiver
        .prepare_normal(installed.normal_transfer())
        .unwrap();
    let state = Rc::new(RefCell::new(State {
        descriptor: plan.control[..DESCRIPTOR_LEN].try_into().unwrap(),
        ..State::default()
    }));
    let mut reads = Port {
        state: state.clone(),
        reads: true,
    };
    let mut writes = Port {
        state: state.clone(),
        reads: false,
    };
    let mut clock = Clock::default();
    plan.flash(
        FlashTransport {
            reads: &mut reads,
            writes: &mut writes,
        },
        &mut clock,
    )
    .unwrap();
    let state = state.borrow();
    assert_eq!(state.entries, 1);
    assert_eq!(state.finishes, 1);
    assert_eq!(state.descriptor_reads, 2);
    assert_eq!(state.kernels, [Vec::<u8>::new()]);
    assert_eq!(state.normals, [plan.normal_transfer()]);
    assert!(state.memory.is_empty());
    assert_eq!(clock.starts, [(0, plan.normal_transfer().len())]);
}

#[test]
fn host_policy_can_refuse_either_pass_before_entry() {
    let plan = plan(true);
    for pass in [FlashPass::Initial, FlashPass::Restoration] {
        let state = state(&plan);
        let mut reads = Port {
            state: state.clone(),
            reads: true,
        };
        let mut writes = Port {
            state: state.clone(),
            reads: false,
        };
        let mut clock = Clock {
            deny: Some(pass),
            ..Clock::default()
        };
        let error = plan
            .flash(
                FlashTransport {
                    reads: &mut reads,
                    writes: &mut writes,
                },
                &mut clock,
            )
            .unwrap_err();
        assert!(
            matches!(error, FlashError::Preflight { pass: failed, source: "medium inserted" } if failed == pass)
        );
        let expected = usize::from(pass == FlashPass::Restoration);
        assert_eq!(state.borrow().entries, expected);
        assert_eq!(state.borrow().finishes, expected);
        assert_eq!(state.borrow().descriptor_reads, 2 * expected);
    }
}
