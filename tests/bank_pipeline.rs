//! Host pipeline KATs against exact OEM archives and a strict command mock.
//! Native bridge instructions are exercised independently by bank_bridge tests;
//! this mock verifies sequencing, live rebinding and failure/retention contracts.
#![cfg(all(feature = "envelope", feature = "drive"))]
use pioneer_optical as pioneer;
#[path = "support/bank_bridge_execution.rs"]
mod native_execution;
use pioneer_optical::{
    cdb,
    drive::{Data, Transport, UpdateRuntime},
    envelope::Update,
    receiver::{ExecutionMode, ExecutionRuntime, FlashStage, FlashTransport, Receiver},
    startup::bank::{
        backup::{BackupReceipt, BankBackup},
        bridge,
    },
};
use std::{cell::RefCell, rc::Rc, time::Duration};
fn pair(source: bool) -> Update {
    let root = std::path::PathBuf::from(
        std::env::var_os("PIONEER_BANK_HOARD").expect("PIONEER_BANK_HOARD required"),
    );
    let (path, k, n) = if source {
        ("packages/pioneer/8F01/ID83/1.01/276c667ac1383c3aac110cbb433bd8627e49d626ac7c2136b1fa9dd29ecd11a7.installer.tar","components/S8F01830.100.enc","components/S8F01831.101.enc")
    } else {
        ("packages/pioneer/9201/ID58/1.02/967c3e42c65ae54802d9b6e1480e3fdf5f70b5de0d875da65731ab8567065415.installer.tar","components/S9201580.101.enc","components/S9201581.102.enc")
    };
    let member = |name| {
        let out = std::process::Command::new("tar")
            .arg("-xOf")
            .arg(root.join(path))
            .arg(name)
            .output()
            .unwrap();
        assert!(out.status.success());
        out.stdout
    };
    Update::load(&member(k), &member(n)).unwrap()
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    FirstPointerRead,
    SecondPointerRead,
    PostReadError,
    Geometry,
    PointerDrift,
    BadCapture,
    ReadError,
    BackupError,
    ArtifactError,
    PostRuntime,
    PostKernel,
    SourceMismatch,
    Loader,
    ShortBank,
    RuntimeCode,
    Backup1,
    Artifact,
    BridgeReadback,
    Backup2,
    OldReceipt,
    StaleAfterReceipt,
    FinalEntry,
    FinalTransfer,
    FinalReadback,
}
struct State {
    source: Update,
    target: Update,
    current: Update,
    banks: [Vec<u8>; 2],
    base: u32,
    active: u32,
    parameter: u16,
    parameter_writes: Vec<u16>,
    entries: Vec<Vec<u8>>,
    finishes: usize,
    kernel_pending: Vec<u8>,
    normal_pending: Vec<u8>,
    loader: bool,
    backups: Vec<BankBackup>,
    receipts: Vec<BackupReceipt>,
    artifacts: Vec<Update>,
    native_execution: bool,
    bank_mutations: usize,
    bank_pointer_reads: usize,
    fault: Option<Fault>,
}
fn setup(source: &Update, target: &Update, fault: Option<Fault>, base: u32) -> Rc<RefCell<State>> {
    let mut banks = [vec![0x35; 0x10000], vec![0x69; 0x10000]];
    for (i, b) in banks.iter_mut().enumerate() {
        b[0xfff8..0xfffa].copy_from_slice(&0x8765u16.to_be_bytes());
        b[0xfffa..0xfffe].copy_from_slice(&0xfedc4321u32.to_be_bytes());
        b[0xfffe..].copy_from_slice(&(if i == 0 { 7u16 } else { 6 }).to_be_bytes());
    }
    if fault == Some(Fault::BadCapture) {
        banks[0][0xfff8..0xfffa].fill(0xff);
    }
    Rc::new(RefCell::new(State {
        source: source.clone(),
        target: target.clone(),
        current: source.clone(),
        banks,
        base,
        active: base,
        parameter: 0xfe24,
        parameter_writes: vec![],
        entries: vec![],
        finishes: 0,
        kernel_pending: vec![],
        normal_pending: vec![],
        loader: fault == Some(Fault::Loader),
        backups: vec![],
        receipts: vec![],
        artifacts: vec![],
        native_execution: false,
        bank_mutations: 0,
        bank_pointer_reads: 0,
        fault,
    }))
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
                if command == cdb::write_parameter_word(0x9f).unwrap() {
                    assert!(
                        s.entries.is_empty(),
                        "A0 must precede all bridge/armed entries"
                    );
                    s.parameter = u16::from_be_bytes(bytes.try_into().unwrap());
                    let value = s.parameter;
                    s.parameter_writes.push(value);
                    // A legitimate native append/compaction can change active bank.
                    s.banks[1] = s.banks[0].clone();
                    s.banks[1][0xfffe..].copy_from_slice(&8u16.to_be_bytes());
                    s.banks[1][0x9ac2..0x9ac4].copy_from_slice(&value.to_be_bytes());
                    s.active = s.base + 0x10000;
                } else if command == cdb::enter_update() {
                    s.entries.push(bytes.to_vec());
                    if s.entries.len() == 2 {
                        if s.fault == Some(Fault::FinalEntry) {
                            return Err("armed entry failed");
                        }
                        let live = BankBackup::capture(
                            &s.source.normal().image,
                            &s.target.normal().image,
                            [&s.banks[0], &s.banks[1]],
                            s.base,
                            s.active,
                        )
                        .unwrap();
                        let receipt = live.confirm_persisted(live.bytes()).unwrap();
                        let expected = bridge::build(
                            &s.source.normal().image,
                            &s.target.normal().image,
                            [&s.banks[0], &s.banks[1]],
                            s.base,
                            s.active,
                            &receipt,
                        )
                        .unwrap();
                        if bytes != expected.control() {
                            return Err("native entry hash refused stale capture");
                        }
                        if !s.parameter_writes.is_empty() {
                            assert_ne!(
                                s.receipts[0].backup_digest(),
                                s.receipts[1].backup_digest()
                            );
                        }
                        if s.native_execution {
                            let converted =
                                pioneer::startup::bank::conversion::LayoutPair::discover(
                                    &s.source.normal().image,
                                    &s.target.normal().image,
                                )
                                .unwrap()
                                .convert([&s.banks[0], &s.banks[1]])
                                .unwrap();
                            native_execution::execute_bridge(
                                &s.source.normal().image,
                                &expected,
                                &converted,
                                s.banks.clone(),
                                s.base,
                                ((s.active - s.base) / 0x10000) as usize,
                                None,
                                None,
                            );
                        }
                        s.bank_mutations += 1; // native payload semantics tested separately
                    }
                    s.loader = true;
                } else if command == cdb::finish() {
                    let kernel = if s.kernel_pending.is_empty() {
                        s.current
                            .kernel()
                            .repack(&s.current.kernel().image)
                            .unwrap()
                    } else {
                        std::mem::take(&mut s.kernel_pending)
                    };
                    let normal = std::mem::take(&mut s.normal_pending);
                    s.current = Update::load(&kernel, &normal)
                        .expect("actual transferred pair must authenticate and decode");
                    s.finishes += 1;
                    s.loader = false;
                } else if command[0] == cdb::WRITE_BUFFER && command[1] == cdb::TRANSFER_MODE {
                    if s.entries.len() == 2 && s.fault == Some(Fault::FinalTransfer) {
                        return Err("target transfer failed");
                    }
                    let offset =
                        u32::from_be_bytes([0, command[3], command[4], command[5]]) as usize;
                    let dest = if command[2] == cdb::KERNEL_ID {
                        &mut s.kernel_pending
                    } else {
                        assert_eq!(command[2], cdb::NORMAL_ID);
                        &mut s.normal_pending
                    };
                    if dest.len() < offset + bytes.len() {
                        dest.resize(offset + bytes.len(), 0);
                    }
                    dest[offset..offset + bytes.len()].copy_from_slice(bytes);
                } else {
                    panic!("unexpected write {command:x?}");
                }
                Ok(bytes.len())
            }
            Data::In(bytes) => {
                if command == cdb::read_parameter_word(0x9f).unwrap() {
                    bytes.copy_from_slice(&s.parameter.to_be_bytes());
                } else if command[0] == 0x12 {
                    let info = s.current.normal().info();
                    let mut b = [b' '; pioneer_optical::INQUIRY_LEN];
                    b[0] = 5;
                    b[8..16].copy_from_slice(format!("{:<8}", info.vendor).as_bytes());
                    b[16..32].copy_from_slice(
                        format!("{:<16}", format!("BD-RW   {}", info.model)).as_bytes(),
                    );
                    b[32..36].copy_from_slice(if s.loader {
                        b"0000"
                    } else {
                        &info.revision.as_bytes()[..4]
                    });
                    let n = bytes.len().min(b.len());
                    bytes[..n].copy_from_slice(&b[..n]);
                } else if command == cdb::vendor_identity() {
                    let info = s.current.normal().info();
                    let mut b = [b' '; pioneer_optical::IDENTITY_LEN];
                    b[16..24].copy_from_slice(format!("{:<8}", info.hardware_version).as_bytes());
                    b[24..32].copy_from_slice(format!("{:<8}", info.kernel_version).as_bytes());
                    if !s.loader {
                        b[32..40].copy_from_slice(format!("{:<8}", info.kernel_version).as_bytes());
                    }
                    bytes.copy_from_slice(&b[..bytes.len()]);
                } else if command[0] == cdb::READ_BUFFER && command[2] == cdb::MEMORY_ID {
                    let address = u32::from_be_bytes([0, command[3], command[4], command[5]]);
                    if address == 0x33e0 {
                        s.bank_pointer_reads += 1;
                        if (s.bank_pointer_reads == 1 && s.fault == Some(Fault::FirstPointerRead))
                            || (s.bank_pointer_reads == 2
                                && s.fault == Some(Fault::SecondPointerRead))
                        {
                            return Err("bank pointer read failed");
                        }
                        bytes[..4].copy_from_slice(&s.base.to_be_bytes());
                        bytes[4..].copy_from_slice(&s.active.to_be_bytes());
                        if s.fault == Some(Fault::Geometry) {
                            bytes[..4].fill(0);
                        }
                        if s.fault == Some(Fault::PointerDrift) && s.bank_pointer_reads == 2 {
                            bytes[4..].copy_from_slice(&(s.base + 0x10000).to_be_bytes());
                        }
                    } else if address == 0x4be {
                        bytes.copy_from_slice(
                            &s.source.normal().image[0x57e8fc - 0x410000..0x57eb88 - 0x410000],
                        );
                        if s.fault == Some(Fault::ReadError)
                            || (s.finishes == 1 && s.fault == Some(Fault::PostReadError))
                        {
                            return Err("read failed");
                        }
                        if s.fault == Some(Fault::RuntimeCode)
                            || (s.finishes == 1 && s.fault == Some(Fault::PostRuntime))
                        {
                            bytes[0] ^= 1;
                        }
                    } else if address >= s.base {
                        let off = (address - s.base) as usize;
                        let bank = off / 0x10000;
                        let off = off % 0x10000;
                        bytes.copy_from_slice(&s.banks[bank][off..off + bytes.len()]);
                        if s.fault == Some(Fault::ShortBank) {
                            return Ok(bytes.len() - 1);
                        }
                    } else if address < 0x410000 {
                        if s.finishes == 1 && s.fault == Some(Fault::PostKernel) {
                            return Err("post bridge kernel read failed");
                        }
                        let off = (address - 0x400000) as usize;
                        bytes.copy_from_slice(&s.current.kernel().image[off..off + bytes.len()]);
                    } else {
                        let off = (address - 0x410000) as usize;
                        bytes.copy_from_slice(&s.current.normal().image[off..off + bytes.len()]);
                        if bytes.len() > 16
                            && ((s.finishes == 0 && s.fault == Some(Fault::SourceMismatch))
                                || (s.finishes == 1 && s.fault == Some(Fault::BridgeReadback))
                                || (s.finishes >= 2 && s.fault == Some(Fault::FinalReadback)))
                        {
                            bytes[16] ^= 1;
                        }
                    }
                } else {
                    assert!(
                        command == cdb::test_unit_ready()
                            || command == cdb::get_event_status()
                            || command == cdb::request_sense(18),
                        "unexpected read {command:x?}"
                    );
                    bytes.fill(0);
                }
                Ok(bytes.len())
            }
            Data::None => panic!("unexpected no-data command"),
        }
    }
    fn sense(&self) -> Option<(u8, u8, u8)> {
        None
    }
}
struct Runtime {
    state: Rc<RefCell<State>>,
    elapsed: Duration,
}
impl UpdateRuntime for Runtime {
    fn elapsed(&self) -> Duration {
        self.elapsed
    }
    fn sleep(&mut self, d: Duration) {
        self.elapsed += d;
    }
}
impl ExecutionRuntime<&'static str> for Runtime {
    fn check_stage(&mut self, _: FlashStage) -> Result<(), &'static str> {
        Ok(())
    }
    fn persist_bank_backup(
        &mut self,
        backup: &BankBackup,
    ) -> Result<Option<BackupReceipt>, &'static str> {
        let mut s = self.state.borrow_mut();
        s.backups.push(backup.clone());
        let n = s.backups.len();
        if s.fault == Some(Fault::BackupError) {
            return Err("backup persistence failed");
        }
        if (n == 1 && s.fault == Some(Fault::Backup1))
            || (n == 2 && s.fault == Some(Fault::Backup2))
        {
            return Ok(None);
        }
        if n == 2 && s.fault == Some(Fault::OldReceipt) {
            return Ok(Some(s.receipts[0].clone()));
        }
        let receipt = backup.confirm_persisted(backup.bytes()).unwrap();
        s.receipts.push(receipt.clone());
        if n == 2 && s.fault == Some(Fault::StaleAfterReceipt) {
            s.banks[1][0x9000] ^= 1;
        }
        Ok(Some(receipt))
    }
    fn persist_bank_bridge(&mut self, pair: &Update) -> Result<bool, &'static str> {
        let mut s = self.state.borrow_mut();
        s.artifacts.push(pair.clone());
        if s.fault == Some(Fault::ArtifactError) {
            return Err("artifact persistence failed");
        }
        Ok(s.fault != Some(Fault::Artifact))
    }
}
fn run(
    plan: &pioneer_optical::receiver::PreparedUpdate,
    state: &Rc<RefCell<State>>,
) -> Result<
    pioneer_optical::receiver::FlashOutcome,
    pioneer_optical::receiver::ExecutionError<&'static str>,
> {
    plan.execute(
        FlashTransport {
            reads: &mut Port(state.clone()),
            writes: &mut Port(state.clone()),
        },
        &mut Runtime {
            state: state.clone(),
            elapsed: Duration::ZERO,
        },
        ExecutionMode::Recovery,
    )
}
#[test]
#[ignore = "requires PIONEER_BANK_HOARD exact OEM archives; mandatory bank-pipeline signoff"]
fn exact_bank_pipeline_uses_fresh_capture_after_a0_and_verifies_each_image() {
    let source = pair(true);
    let target = pair(false);
    let plan = Receiver::from_installed(&source)
        .unwrap()
        .prepare_without_family_check(target.clone())
        .unwrap();
    assert_eq!(
        plan.pending_bridge(),
        Some(pioneer_optical::receiver::BridgeKind::PersistentBanks)
    );
    assert_eq!(plan.stages()[0].normal_image(), target.normal().image);
    for base in [0x5e0000, 0x7d0000] {
        let state = setup(&source, &target, None, base);
        let result = run(&plan, &state).unwrap();
        let s = state.borrow();
        assert!(result.kernel_verified && result.normal_verified);
        assert_eq!(result.completed_stages, plan.stages().len() + 1);
        assert_eq!(s.parameter_writes, [0xffff]);
        assert_eq!(s.backups.len(), 2);
        assert_eq!(s.artifacts.len(), 1);
        assert_eq!(s.bank_mutations, 1);
        assert_eq!(s.entries[1][240..244], *b"BNK1");
        assert_eq!(s.artifacts[0].kernel().image, source.kernel().image);
        assert!(bridge::recognize(&s.artifacts[0].normal().image).is_some());
    }
}
#[test]
#[ignore = "requires PIONEER_BANK_HOARD exact OEM archives; mandatory bank-pipeline signoff"]
fn exact_bank_pipeline_faults_never_retry_or_roll_back_a0_after_armed_entry() {
    let source = pair(true);
    let target = pair(false);
    let plan = Receiver::from_installed(&source)
        .unwrap()
        .prepare_without_family_check(target.clone())
        .unwrap();
    for fault in [
        Fault::Loader,
        Fault::ShortBank,
        Fault::RuntimeCode,
        Fault::Backup1,
        Fault::Artifact,
        Fault::BridgeReadback,
        Fault::Backup2,
        Fault::OldReceipt,
        Fault::StaleAfterReceipt,
        Fault::FinalEntry,
        Fault::FinalTransfer,
        Fault::FinalReadback,
    ] {
        let state = setup(&source, &target, Some(fault), 0x5e0000);
        let error = run(&plan, &state).expect_err("injected boundary must fail");
        let s = state.borrow();
        assert!(
            s.parameter_writes.len() <= 1,
            "A0 rollback/retry after {fault:?}"
        );
        if matches!(
            fault,
            Fault::Loader
                | Fault::ShortBank
                | Fault::RuntimeCode
                | Fault::Backup1
                | Fault::Artifact
        ) {
            assert!(s.entries.is_empty(), "{fault:?}");
            assert!(s.parameter_writes.is_empty());
            assert!(!error.temporary_bank_bridge());
        } else {
            assert!(error.temporary_bank_bridge(), "{fault:?}: {error:?}");
            assert_eq!(s.artifacts.len(), 1);
        }
        if fault == Fault::Loader {
            assert_eq!(s.bank_pointer_reads, 0);
        }
        if matches!(
            fault,
            Fault::BridgeReadback | Fault::Backup2 | Fault::OldReceipt
        ) {
            assert_eq!(s.entries.len(), 1);
            assert_eq!(s.bank_mutations, 0);
        }
        if matches!(
            fault,
            Fault::StaleAfterReceipt
                | Fault::FinalEntry
                | Fault::FinalTransfer
                | Fault::FinalReadback
        ) {
            assert_eq!(s.entries.len(), 2);
            assert_eq!(s.parameter_writes, [0xffff]);
        }
    }
}

#[test]
#[ignore = "requires PIONEER_BANK_HOARD exact OEM archives; mandatory bank-pipeline signoff"]
fn recognized_temporary_bridge_can_resume_conversion_or_restore_source_without_bank_writes() {
    let source = pair(true);
    let target = pair(false);
    let plan = Receiver::from_installed(&source)
        .unwrap()
        .prepare_without_family_check(target.clone())
        .unwrap();
    let state = setup(&source, &target, Some(Fault::Backup2), 0x5e0000);
    assert!(run(&plan, &state).unwrap_err().temporary_bank_bridge());
    let temporary = state.borrow().current.clone();
    let receiver = Receiver::from_installed(&temporary).unwrap();
    let reset = |fault| {
        let next = setup(&source, &target, fault, 0x5e0000);
        {
            let saved = state.borrow();
            let mut s = next.borrow_mut();
            s.current = temporary.clone();
            s.banks = saved.banks.clone();
            s.active = saved.active;
            s.parameter = 0xffff;
        }
        next
    };
    let resume = receiver
        .prepare_without_family_check(target.clone())
        .unwrap();
    assert!(resume.pending_bridge().is_some());
    let wrong_capacity = reset(None);
    {
        let mut s = wrong_capacity.borrow_mut();
        s.base = 0x7d0000;
        s.active = 0x7e0000;
    }
    let error = run(&resume, &wrong_capacity).unwrap_err();
    assert!(error.temporary_bank_bridge());
    assert!(!error.write_started());
    assert!(!error.firmware_write_started());
    assert!(wrong_capacity.borrow().entries.is_empty());
    let resumed = reset(None);
    let outcome = run(&resume, &resumed).unwrap();
    assert!(outcome.normal_verified);
    assert_eq!(&resumed.borrow().entries[0][240..244], b"BNK0");
    assert_eq!(&resumed.borrow().entries[1][240..244], b"BNK1");
    assert!(resumed.borrow().parameter_writes.is_empty());
    let restore = receiver
        .prepare_without_family_check(source.clone())
        .unwrap();
    assert!(restore.pending_bridge().is_none());
    let restored = reset(None);
    let outcome = run(&restore, &restored).unwrap();
    assert!(outcome.normal_verified);
    let s = restored.borrow();
    assert_eq!(&s.entries[0][240..244], b"BNK0");
    assert_eq!(s.bank_mutations, 0);
    assert_eq!(s.current.normal().image, source.normal().image);
}

#[test]
#[ignore = "requires PIONEER_BANK_HOARD exact OEM archives; mandatory bank-pipeline signoff"]
fn unchecked_api_and_default_host_callbacks_cannot_bypass_bank_receipts() {
    use pioneer_optical::receiver::{FlashError, FlashRuntime};
    struct RuntimeDefault;
    impl UpdateRuntime for RuntimeDefault {
        fn elapsed(&self) -> Duration {
            Duration::ZERO
        }
        fn sleep(&mut self, _: Duration) {}
    }
    impl ExecutionRuntime<&'static str> for RuntimeDefault {
        fn check_stage(&mut self, _: FlashStage) -> Result<(), &'static str> {
            Ok(())
        }
    }
    impl FlashRuntime<&'static str> for RuntimeDefault {
        fn prepare_stage(
            &mut self,
            _: FlashStage,
        ) -> Result<pioneer_optical::drive::UpdateOptions, &'static str> {
            panic!("deferred plan must refuse before host entry callback")
        }
    }
    let source = pair(true);
    let target = pair(false);
    let plan = Receiver::from_installed(&source)
        .unwrap()
        .prepare_without_family_check(target.clone())
        .unwrap();
    let state = setup(&source, &target, None, 0x5e0000);
    assert!(matches!(
        plan.transfer_unchecked(
            FlashTransport {
                reads: &mut Port(state.clone()),
                writes: &mut Port(state.clone())
            },
            &mut RuntimeDefault
        ),
        Err(FlashError::UnsupportedTransport { .. })
    ));
    assert!(plan
        .transfer_with_parameter_unchecked(
            FlashTransport {
                reads: &mut Port(state.clone()),
                writes: &mut Port(state.clone())
            },
            &mut RuntimeDefault,
            0x9f,
            0xffff
        )
        .is_err());
    let error = plan
        .execute(
            FlashTransport {
                reads: &mut Port(state.clone()),
                writes: &mut Port(state.clone()),
            },
            &mut RuntimeDefault,
            ExecutionMode::Flash,
        )
        .unwrap_err();
    assert_eq!(error.phase(), "pre-settings backup");
    assert!(!error.write_started());
    assert!(state.borrow().entries.is_empty());
    assert!(state.borrow().parameter_writes.is_empty());
}

#[test]
#[ignore = "requires PIONEER_BANK_HOARD exact OEM archives; mandatory bank-pipeline signoff"]
fn additional_live_capture_and_persistence_failures_are_bounded_before_arming() {
    let source = pair(true);
    let target = pair(false);
    let plan = Receiver::from_installed(&source)
        .unwrap()
        .prepare_without_family_check(target.clone())
        .unwrap();
    for fault in [
        Fault::Geometry,
        Fault::PointerDrift,
        Fault::BadCapture,
        Fault::ReadError,
        Fault::BackupError,
        Fault::ArtifactError,
        Fault::PostReadError,
        Fault::PostRuntime,
        Fault::PostKernel,
        Fault::SourceMismatch,
    ] {
        let state = setup(&source, &target, Some(fault), 0x5e0000);
        let error = run(&plan, &state).expect_err("injected failure must refuse");
        let s = state.borrow();
        assert_eq!(s.bank_mutations, 0, "{fault:?}");
        if matches!(
            fault,
            Fault::PostRuntime | Fault::PostKernel | Fault::PostReadError
        ) {
            assert!(error.temporary_bank_bridge(), "{fault:?}: {error}");
            assert_eq!(error.completed_stages(), 1, "{fault:?}: {error}");
            assert_eq!(s.entries.len(), 1);
            assert_eq!(s.parameter_writes, [0xffff]);
        } else {
            assert!(s.entries.is_empty(), "{fault:?}");
            assert!(s.parameter_writes.is_empty(), "{fault:?}");
            assert!(!error.write_started(), "{fault:?}: {error}");
            assert!(!error.firmware_write_started(), "{fault:?}: {error}");
        }
    }
}

#[test]
#[ignore = "requires PIONEER_BANK_HOARD exact OEM archives; mandatory native pipeline signoff"]
fn actual_prepared_update_executes_native_migration_and_target_guard() {
    let source = pair(true);
    let target = pair(false);
    let plan = Receiver::from_installed(&source)
        .unwrap()
        .prepare_without_family_check(target.clone())
        .unwrap();
    for base in [0x5e0000, 0x7d0000] {
        let state = setup(&source, &target, None, base);
        state.borrow_mut().native_execution = true;
        let outcome = run(&plan, &state).unwrap();
        assert!(outcome.kernel_verified && outcome.normal_verified);
        assert_eq!(state.borrow().bank_mutations, 1);
    }
}

#[test]
#[ignore = "requires PIONEER_BANK_HOARD exact OEM archives; mandatory bank-pipeline signoff"]
fn competing_target_header_refuses_before_settings_or_firmware_write() {
    let source = pair(true);
    let target = pair(false);
    let plan = Receiver::from_installed(&source)
        .unwrap()
        .prepare_without_family_check(target.clone())
        .unwrap();
    let state = setup(&source, &target, None, 0x7d0000);
    state.borrow_mut().banks[0][0x7ffa..0x7ffe].copy_from_slice(&0xfedc4322u32.to_be_bytes());
    let error = run(&plan, &state).unwrap_err();
    assert!(!error.write_started());
    assert!(state.borrow().entries.is_empty());
    assert!(state.borrow().parameter_writes.is_empty());
}

#[test]
#[ignore = "requires PIONEER_BANK_HOARD exact OEM archives; mandatory bank-pipeline signoff"]
fn either_capture_pointer_read_failure_prevents_all_mutations() {
    let source = pair(true);
    let target = pair(false);
    let plan = Receiver::from_installed(&source)
        .unwrap()
        .prepare_without_family_check(target.clone())
        .unwrap();
    for (fault, reads) in [(Fault::FirstPointerRead, 1), (Fault::SecondPointerRead, 2)] {
        let state = setup(&source, &target, Some(fault), 0x5e0000);
        let error = run(&plan, &state).unwrap_err();
        assert!(error.to_string().contains("bank pointer read failed"));
        assert!(!error.write_started());
        assert!(!error.firmware_write_started());
        assert!(!error.temporary_bank_bridge());
        assert_eq!(error.completed_stages(), 0);
        let s = state.borrow();
        assert_eq!(s.bank_pointer_reads, reads);
        assert!(s.entries.is_empty());
        assert!(s.parameter_writes.is_empty());
        assert!(s.backups.is_empty());
        assert_eq!(s.bank_mutations, 0);
    }
}
