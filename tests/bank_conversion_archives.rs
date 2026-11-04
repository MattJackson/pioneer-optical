//! Reproducible binding from the exact customer source/target OEM archives.
#![cfg(feature = "envelope")]
use pioneer_optical as pioneer;
use pioneer_optical::{
    envelope::Envelope,
    startup::bank::conversion::{Error, LayoutPair},
};
use sha2::{Digest, Sha256};
#[path = "support/bank_bridge_execution.rs"]
mod bank_bridge_execution;
fn member(root: &std::path::Path, archive: &str, member: &str, sha: &str) -> Vec<u8> {
    let out = std::process::Command::new("tar")
        .args(["-xOf"])
        .arg(root.join(archive))
        .arg(member)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(format!("{:x}", Sha256::digest(&out.stdout)), sha);
    out.stdout
}
#[test]
#[ignore = "requires PIONEER_BANK_HOARD and exact OEM installer archives"]
fn exact_archives_bind_only_kernel_corrected_normal_images() {
    let root = std::path::PathBuf::from(
        std::env::var_os("PIONEER_BANK_HOARD").expect("set PIONEER_BANK_HOARD"),
    );
    let sa="packages/pioneer/8F01/ID83/1.01/276c667ac1383c3aac110cbb433bd8627e49d626ac7c2136b1fa9dd29ecd11a7.installer.tar";
    let ta="packages/pioneer/9201/ID58/1.02/967c3e42c65ae54802d9b6e1480e3fdf5f70b5de0d875da65731ab8567065415.installer.tar";
    let sk = member(
        &root,
        sa,
        "components/S8F01830.100.enc",
        "227083a8141e6effe2810b124b0dae3cd5a4bd556a3b0a687ed96ab76f62d8a8",
    );
    let sn = member(
        &root,
        sa,
        "components/S8F01831.101.enc",
        "9201ee0287df6e6b2acbd26f79414c75d4ed08745a0f3c4bae0908880c86567a",
    );
    let tk = member(
        &root,
        ta,
        "components/S9201580.101.enc",
        "255a74dc458cdc026accdb738f5bd371e5cd7dbaeb6acac88dc6920f2e0d9d05",
    );
    let tn = member(
        &root,
        ta,
        "components/S9201581.102.enc",
        "c45156efa3e19f3092cdd57e68a6d4e71cb2d7fa54509cb56a0c470a8fe65fc4",
    );
    let s = Envelope::load_with_kernel(&sn, &Envelope::load(&sk).unwrap()).unwrap();
    let t = Envelope::load_with_kernel(&tn, &Envelope::load(&tk).unwrap()).unwrap();
    assert_eq!(s.receiver_xor_exceptions(), Some(&[0x16900, 0x77300][..]));
    assert_eq!(t.receiver_xor_exceptions(), Some(&[0x16900, 0x77300][..]));
    assert_eq!(
        format!("{:x}", Sha256::digest(&s.image)),
        "014868226d2b9ef07685fb612d0060e4aeee6552dc48aa53371bd2631462d09b"
    );
    assert_eq!(
        format!("{:x}", Sha256::digest(&t.image)),
        "4c57a8f1a43367489a24ed591ba3bcd0e87267a07b58d290a8f658d2cc200025"
    );
    assert_eq!(
        &t.image[0x5509e8 - 0x410000..0x550a7a - 0x410000],
        include_bytes!("fixtures/pioneer-213u-native-bank-guard.bin")
    );
    for (raw, paired) in [(&sn, &s), (&tn, &t)] {
        let standalone = Envelope::load(raw).unwrap();
        let differences: Vec<_> = standalone
            .image
            .iter()
            .zip(&paired.image)
            .enumerate()
            .filter_map(|(i, (a, b))| (a != b).then_some(i))
            .collect();
        assert_eq!(
            differences,
            [0x16900, 0x16901, 0x16902, 0x16903, 0x77300, 0x77301, 0x77302, 0x77303]
        );
    }
    for (start, end, fixture) in [
        (
            0x410000usize,
            0x410018,
            include_bytes!("fixtures/pioneer-212u-bridge-header.bin").as_slice(),
        ),
        (
            0x44ba96,
            0x44bada,
            include_bytes!("fixtures/pioneer-212u-bridge-ff-hooks.bin").as_slice(),
        ),
        (
            0x57e8fc,
            0x57eb88,
            include_bytes!("fixtures/pioneer-212u-bridge-flash-vectors.bin").as_slice(),
        ),
        (
            0x4b6418usize,
            0x4b7670,
            include_bytes!("fixtures/pioneer-212u-sha-code.bin").as_slice(),
        ),
        (
            0x59be6e,
            0x59bf6e,
            include_bytes!("fixtures/pioneer-212u-sha-constants.bin").as_slice(),
        ),
        (
            0x57ec28,
            0x57ec5a,
            include_bytes!("fixtures/pioneer-212u-sha-shl.bin").as_slice(),
        ),
        (
            0x57ecc8,
            0x57ecfa,
            include_bytes!("fixtures/pioneer-212u-sha-shr.bin").as_slice(),
        ),
    ] {
        assert_eq!(&s.image[start - 0x410000..end - 0x410000], fixture);
    }
    if std::env::var_os("PIONEER_EXECUTE_BANK_BRIDGE").is_some() {
        let scenario = std::env::var("PIONEER_EXECUTE_BANK_BRIDGE").unwrap();
        let base = if scenario.contains("extended") {
            0x7d0000
        } else {
            0x5e0000
        };
        let selected = usize::from(scenario.contains("_b"));
        let fault = if scenario.contains("footer_fault") {
            Some(770)
        } else if scenario.contains("stage_fault") {
            Some(1030)
        } else if scenario.contains("erase_fault") {
            Some(1)
        } else if scenario.contains("program_fault") {
            Some(2)
        } else {
            None
        };
        bank_bridge_execution::execute(&s.image, &t.image, base, selected, fault);
    }
    LayoutPair::discover(&s.image, &t.image).unwrap();
    assert_eq!(
        LayoutPair::discover(&Envelope::load(&sn).unwrap().image, &t.image).unwrap_err(),
        Error::UnknownFirmware
    );
    assert_eq!(
        LayoutPair::discover(&s.image, &Envelope::load(&tn).unwrap().image).unwrap_err(),
        Error::UnknownFirmware
    );
    let mut changed = t.image.clone();
    changed[0x16900] ^= 1;
    assert_eq!(
        LayoutPair::discover(&s.image, &changed).unwrap_err(),
        Error::UnknownFirmware
    );
    use pioneer_optical::startup::bank::backup::{BankBackup, Error as BackupError};
    let banks: Vec<Vec<u8>> = [7u16, 8]
        .into_iter()
        .map(|sequence| {
            let mut bytes: Vec<_> = (0..0x10000)
                .map(|i| ((i * 17 + i / 257) % 251) as u8)
                .collect();
            bytes[0xfff8..0xfffa].copy_from_slice(&0x8765u16.to_be_bytes());
            bytes[0xfffa..0xfffe].copy_from_slice(&0xfedc4321u32.to_be_bytes());
            bytes[0xfffe..].copy_from_slice(&sequence.to_be_bytes());
            bytes
        })
        .collect();
    assert_eq!(
        BankBackup::capture(&[], &t.image, [&banks[0], &banks[1]], 0x5e0000, 0x5f0000).unwrap_err(),
        BackupError::Conversion(Error::UnknownFirmware)
    );
    assert_eq!(
        BankBackup::capture(
            &s.image,
            &t.image,
            [&banks[0][..0xffff], &banks[1]],
            0x5e0000,
            0x5f0000
        )
        .unwrap_err(),
        BackupError::Conversion(Error::BankLength)
    );
    let mut unresolved = banks[1].clone();
    unresolved[0xfff8..0xfffa].fill(0xff);
    assert_eq!(
        BankBackup::capture(
            &s.image,
            &t.image,
            [&banks[0], &unresolved],
            0x5e0000,
            0x5f0000
        )
        .unwrap_err(),
        BackupError::Conversion(Error::MaintenanceState)
    );
    for base in [0x5e0000u32, 0x7d0000] {
        let backup = BankBackup::capture(
            &s.image,
            &t.image,
            [&banks[0], &banks[1]],
            base,
            base + 0x10000,
        )
        .unwrap();
        assert_eq!(
            &backup.bytes()[backup.bytes().len() - 0x20000..backup.bytes().len() - 0x10000],
            banks[0]
        );
        assert_eq!(&backup.bytes()[backup.bytes().len() - 0x10000..], banks[1]);
        let receipt = backup.confirm_persisted(backup.bytes()).unwrap();
        assert!(backup.accepts(&receipt));
        let bridge = pioneer::startup::bank::bridge::build(
            &s.image,
            &t.image,
            [&banks[0], &banks[1]],
            base,
            base + 0x10000,
            &receipt,
        )
        .unwrap();
        let bridge_backup = backup.clone().bind_current_image(bridge.image()).unwrap();
        assert_ne!(bridge_backup.digest(), backup.digest());
        assert!(!bridge_backup.accepts(&receipt));
        let bridge_receipt = bridge_backup
            .confirm_persisted(bridge_backup.bytes())
            .unwrap();
        let resumed = pioneer::startup::bank::bridge::build(
            &s.image,
            &t.image,
            [&banks[0], &banks[1]],
            base,
            base + 0x10000,
            &bridge_receipt,
        )
        .unwrap();
        assert_eq!(resumed.image(), bridge.image());
        assert_eq!(resumed.control(), bridge.control());
        let mut damaged = bridge.image().to_vec();
        damaged[0x3ba96] ^= 1;
        assert_eq!(
            backup.clone().bind_current_image(&damaged).unwrap_err(),
            BackupError::CurrentImage
        );
        let other_base = if base == 0x5e0000 { 0x7d0000 } else { 0x5e0000 };
        let other_backup = BankBackup::capture(
            &s.image,
            &t.image,
            [&banks[0], &banks[1]],
            other_base,
            other_base + 0x10000,
        )
        .unwrap();
        let other_receipt = other_backup
            .confirm_persisted(other_backup.bytes())
            .unwrap();
        let other_bridge = pioneer::startup::bank::bridge::build(
            &s.image,
            &t.image,
            [&banks[0], &banks[1]],
            other_base,
            other_base + 0x10000,
            &other_receipt,
        )
        .unwrap();
        assert_eq!(
            backup
                .clone()
                .bind_current_image(other_bridge.image())
                .unwrap_err(),
            BackupError::CurrentImage
        );
        assert!(!bridge.code().is_empty());
        assert_eq!(&bridge.control()[..16], &s.image[..16]);
        let installed = pioneer::startup::bank::bridge::recognize(bridge.image()).unwrap();
        assert_eq!(installed.source_image(), &s.image);
        assert_eq!(installed.base(), base);
        for at in [
            0x3ba96,
            0x3bac8,
            s.image.len() + 0x3e00,
            bridge.image().len() - 1,
        ] {
            let mut corrupted = bridge.image().to_vec();
            corrupted[at] ^= 1;
            assert!(pioneer::startup::bank::bridge::recognize(&corrupted).is_none());
        }

        assert_eq!(
            BankBackup::capture(&s.image, &t.image, [&banks[0], &banks[1]], base, base)
                .unwrap_err(),
            BackupError::ActiveBank
        );
        assert_eq!(
            BankBackup::capture(
                &s.image,
                &t.image,
                [&banks[0], &banks[1]],
                base + 1,
                base + 0x10000
            )
            .unwrap_err(),
            BackupError::Geometry
        );
    }
}
