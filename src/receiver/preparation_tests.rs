use super::*;
use crate::envelope::{
    builder::{encode_encrypted_pair, BuildInputs, KernelBuild, NormalSignature},
    signature::SigningKey,
    synthetic_roundtrip_tests::{front_kernel, normal_image},
    Envelope,
};

fn fix_sum(bytes: &mut [u8]) {
    let end = bytes.len() - 4;
    bytes[end..].fill(0);
    let sum = bytes.chunks_exact(4).fold(0u32, |sum, word| {
        sum.wrapping_add(u32::from_be_bytes(word.try_into().unwrap()))
    });
    bytes[end..].copy_from_slice(&sum.wrapping_neg().to_be_bytes());
}

#[test]
fn startup_selection_uses_target_even_when_installed_surface_is_unknown() {
    let installed = update(false, 1, 0x12, true);
    assert!(crate::startup::surface::discover(&installed.normal().image).is_none());
    let receiver = Receiver::from_installed(&installed).unwrap();
    let neutral = receiver.startup_setting_for(&[]).unwrap().unwrap();
    assert_eq!(
        (neutral.parameter, neutral.value, neutral.explicit),
        (0x9f, 0xffff, false)
    );
    let mut normal = vec![0; 0x200];
    normal[0x20..0x34].copy_from_slice(&[
        0x79, 0, 0, 0x9f, 0x5e, 0x41, 1, 0, 0x79, 0x20, 0xfe, 0x24, 0x47, 6, 0xf8, 1, 0x5e, 0x41,
        1, 0x80,
    ]);
    normal[0x180..0x186].copy_from_slice(&[0x5e, 0x40, 0x0a, 0x1a, 0x54, 0x70]);
    let setting = receiver.startup_setting_for(&normal).unwrap().unwrap();
    assert_eq!(
        (setting.parameter, setting.value, setting.explicit),
        (0x9f, 0xfe24, true)
    );
    assert_eq!(receiver.startup_setting_for(&[]).unwrap(), Some(neutral));
    assert_eq!(
        receiver.startup_setting_for(&normal).unwrap(),
        Some(setting)
    );
    let duplicate = normal[0x20..0x34].to_vec();
    normal[0x60..0x74].copy_from_slice(&duplicate);
    assert_eq!(
        receiver.startup_setting_for(&normal),
        Err(PreparationError::AmbiguousStartup)
    );
}

pub(in crate::receiver) fn update(gated: bool, marker: u8, family: u8, entry: bool) -> Update {
    let mut kernel = front_kernel();
    crate::image::handoff_fixture(&mut kernel);
    let receiver = crate::image::receiver_fixture(gated);
    // Relocate the finalizer away from the independent envelope decoder fixture.
    kernel[0x300..0x380].copy_from_slice(&receiver[0x100..0x180]);
    if gated {
        kernel[0x3000..0x3100].copy_from_slice(&receiver[0x1000..0x1100]);
        kernel[0x363..0x366].copy_from_slice(&[0x40, 0x30, 0]);
    }
    kernel[KERNEL_MARKER_OFFSET] = marker;
    fix_sum(&mut kernel);
    let mut normal = normal_image(0x2000);
    normal[0x400..0x408].copy_from_slice(&[0xf6, family, 0x6a, 0x86, 0xe4, 0x36, 0, 0]);
    if entry {
        normal[0x500..0x510].copy_from_slice(&[
            0x7a, 0x20, 0x9a, 0x78, 0x23, 0x61, 0x47, 8, 0x7a, 0x20, 1, 2, 3, 4, 0x46, 0x4e,
        ]);
    }
    fix_sum(&mut normal);
    let mut key = [0; 20];
    key[19] = 5;
    let signer = SigningKey::from_bytes(key).unwrap();
    let pair = encode_encrypted_pair(
        &BuildInputs {
            kernel_image: &kernel,
            normal_image: &normal,
            envelope_id: "PIONEER BDR-TEST",
            normal_revision: "1.00",
            normal_date: "00/00/00",
            kernel: KernelBuild::from_seed(0x123456),
            normal_key_seed: 0x47d001,
        },
        NormalSignature::Sign(&signer),
    )
    .unwrap();
    Update::load(&pair.kernel, &pair.normal).unwrap()
}

#[test]
fn prepares_patch_and_pristine_restore_before_any_io() {
    let installed = update(true, 1, 0x12, true);
    let receiver = Receiver::from_installed(&installed).unwrap();
    for marker in [0, 0xff] {
        let target = update(false, marker, 0x12, true);
        let pristine = target.kernel().image.clone();
        let normal = target.normal_transfer().to_vec();
        let plan = receiver.prepare(target).unwrap();
        assert_eq!(
            plan.first_kernel_image(),
            downgrade_patch(&pristine).unwrap().0
        );
        assert_eq!(plan.final_kernel_image(), pristine);
        assert_eq!(plan.normal_transfer(), normal);
        let first = Envelope::load(plan.kernel_transfer()).unwrap();
        let restored = Envelope::load(plan.restoration_kernel_transfer().unwrap()).unwrap();
        assert_eq!(first.image, plan.first_kernel_image());
        assert_eq!(restored.image, pristine);
        let restore = plan.restoration_receiver().unwrap();
        assert!(restore
            .entry_control(&installed.normal().image[..16])
            .is_ok());
        assert!(restore.entry_control(b"PIONEER WRONG   ").is_err());
    }
}

#[cfg(feature = "drive")]
#[test]
fn first_kernel_transport_is_selected_from_installed_loader() {
    let original = update(false, 1, 0x12, true);
    let mut kernel = original.kernel().clone();
    kernel.image[0x5000..0x5006].copy_from_slice(&[0x7a, 0x10, 0, 1, 2, 0]);
    kernel.image[0x5010..0x5014].copy_from_slice(&0x11200u32.to_be_bytes());
    kernel.image[0x5020..0x5024].copy_from_slice(&0x20400u32.to_be_bytes());
    kernel.image[0x5030..0x5034].copy_from_slice(&0x410000u32.to_be_bytes());
    fix_sum(&mut kernel.image);
    let installed = Update::load(
        &kernel.repack(&kernel.image).unwrap(),
        &original.normal().repack(&original.normal().image).unwrap(),
    )
    .unwrap();
    let target = update(false, 1, 0x12, true);
    assert_eq!(
        crate::receiver::transport::detect(&target.kernel().image),
        crate::receiver::transport::KernelReceive::Linear
    );
    let prepared = Receiver::from_installed(&installed)
        .unwrap()
        .prepare(target)
        .unwrap();
    assert_eq!(
        prepared.initial_receive,
        Some(crate::receiver::transport::KernelReceive::FrontKeyTwoRegion)
    );
}

#[test]
fn restoration_handoff_is_checked_before_the_first_pass() {
    let installed = update(true, 1, 0x12, true);
    let receiver = Receiver::from_installed(&installed).unwrap();
    let target = update(false, 0, 0x12, true);
    let mut kernel = target.kernel().clone();
    // Initial installed->target entry matches, but the new programmer would
    // restart the pristine restoration at the wrong address.
    kernel.image[0x2107] = 0x2a;
    fix_sum(&mut kernel.image);
    let target = Update::load(
        &kernel.repack(&kernel.image).unwrap(),
        &target.normal().repack(&target.normal().image).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        receiver.prepare(target),
        Err(PreparationError::KernelHandoff(
            crate::image::KernelHandoffError::Mismatch {
                installed: 0x40002a,
                target: 0x400020
            }
        ))
    ));
}

#[test]
fn ungated_receiver_preserves_every_marker_without_a_second_pass() {
    let installed = update(false, 0xff, 0x12, true);
    let receiver = Receiver::from_installed(&installed).unwrap();
    for marker in [0, 1, 0x55, 0xff] {
        let target = update(false, marker, 0x12, true);
        let expected = target.kernel_transfer().to_vec();
        let plan = receiver.prepare(target).unwrap();
        assert_eq!(plan.kernel_transfer(), expected);
        assert_eq!(plan.first_kernel_image(), plan.final_kernel_image());
        assert!(plan.restoration_kernel_transfer().is_none());
        assert!(plan.restoration_receiver().is_none());
    }
}

#[test]
fn refuses_missing_installed_evidence_and_unproven_restoration() {
    let installed = update(true, 1, 0x12, true);
    let entry_only = Receiver::detect(installed.normal()).unwrap();
    assert_eq!(
        entry_only.prepare(installed.clone()).unwrap_err(),
        PreparationError::UnknownInstalledKernel
    );
    let receiver = Receiver::from_installed(&installed).unwrap();
    assert_eq!(
        receiver.prepare(update(true, 0, 0x12, true)).unwrap_err(),
        PreparationError::UnsupportedRestoration
    );
    assert_eq!(
        receiver.prepare(update(false, 0, 0x12, false)).unwrap_err(),
        PreparationError::RestorationEntry(Error::Unsupported)
    );
    assert!(matches!(
        entry_only.prepare(update(false, 0, 0x13, true)),
        Err(PreparationError::Compatibility(
            Error::FamilyMismatch { .. }
        ))
    ));
}

#[test]
fn gated_receiver_does_not_patch_an_accepted_marker() {
    let installed = update(true, 1, 0x12, true);
    let receiver = Receiver::from_installed(&installed).unwrap();
    for marker in [1, 0x55] {
        let target = update(true, marker, 0x12, true);
        let expected = target.kernel_transfer().to_vec();
        let plan = receiver.prepare(target).unwrap();
        assert_eq!(plan.kernel_transfer(), expected);
        assert!(plan.restoration_receiver().is_none());
    }
}

#[test]
fn captured_receiver_evidence_does_not_require_a_distribution_signature() {
    let installed = update(true, 1, 0x12, true);
    let mut bytes = installed.normal_transfer().to_vec();
    bytes[crate::envelope::builder::NORMAL_SIGNATURE_RANGE].fill(0);
    let captured = Envelope::load_with_kernel(&bytes, installed.kernel()).unwrap();
    let receiver = Receiver::detect_with_kernel(&captured, installed.kernel()).unwrap();
    assert_eq!(receiver.family(), installed.family());
    assert_eq!(
        receiver.installed_kernel().unwrap().image,
        installed.kernel().image
    );
    assert!(receiver.prepare(update(false, 0, 0x12, true)).is_ok());
    assert!(Update::load(installed.kernel_transfer(), &bytes).is_err());
    assert_eq!(
        Receiver::detect_with_kernel(&captured, &captured).unwrap_err(),
        Error::KernelComponent {
            actual: crate::ComponentKind::Normal
        }
    );
    let mut mismatched = bytes;
    let hardware = mismatched[..0x200]
        .windows(8)
        .position(|s| s == b"SAT 8A10")
        .unwrap();
    mismatched[hardware + 7] = b'1';
    let mismatched = Envelope::load_with_kernel(&mismatched, installed.kernel()).unwrap();
    assert_eq!(
        Receiver::detect_with_kernel(&mismatched, installed.kernel()).unwrap_err(),
        Error::InstalledPairMismatch
    );
}

#[test]
fn explicit_family_override_does_not_waive_receiver_or_restore_checks() {
    let installed = update(true, 1, 0x12, true);
    let receiver = Receiver::from_installed(&installed).unwrap();
    assert!(receiver
        .prepare_without_family_check(update(false, 0, 0x13, true))
        .is_ok());
    assert_eq!(
        receiver
            .prepare_without_family_check(update(true, 0, 0x13, true))
            .unwrap_err(),
        PreparationError::UnsupportedRestoration
    );
    let entry_only = Receiver::detect(installed.normal()).unwrap();
    assert_eq!(
        entry_only
            .prepare_without_family_check(update(false, 0, 0x13, true))
            .unwrap_err(),
        PreparationError::UnknownInstalledKernel
    );
}

#[test]
fn normal_only_uses_installed_kernel_without_selecting_a_kernel_write() {
    let installed = update(true, 1, 0x12, true);
    let receiver = Receiver::from_installed(&installed).unwrap();
    let target = update(true, 1, 0x12, true);
    let prepared = receiver.prepare_normal(target.normal_transfer()).unwrap();
    assert_eq!(prepared.normal_transfer(), target.normal_transfer());
    assert_eq!(prepared.normal_image(), target.normal().image);

    // Kernel marker handling is immaterial when no Kernel is being written.
    let mut unknown_marker_handler = installed.kernel().clone();
    unknown_marker_handler.image[0x300] ^= 1;
    fix_sum(&mut unknown_marker_handler.image);
    let receiver =
        Receiver::detect_with_kernel(installed.normal(), &unknown_marker_handler).unwrap();
    assert!(receiver.prepare_normal(target.normal_transfer()).is_ok());
    assert_eq!(
        receiver.prepare(target).unwrap_err(),
        PreparationError::UnknownInstalledKernel
    );
}

#[test]
fn normal_only_force_waives_family_but_not_authentication_or_missing_evidence() {
    let installed = update(false, 0, 0x12, true);
    let receiver = Receiver::from_installed(&installed).unwrap();
    let other = update(false, 0, 0x13, true);
    assert!(matches!(
        receiver.prepare_normal(other.normal_transfer()),
        Err(PreparationError::Compatibility(
            Error::FamilyMismatch { .. }
        ))
    ));
    assert!(receiver
        .prepare_normal_without_family_check(other.normal_transfer())
        .is_ok());
    let mut invalid = other.normal_transfer().to_vec();
    invalid[crate::envelope::builder::NORMAL_SIGNATURE_RANGE].fill(0);
    assert_eq!(
        receiver
            .prepare_normal_without_family_check(&invalid)
            .unwrap_err(),
        PreparationError::Target(UpdateError::Authentication)
    );
    let entry_only = Receiver::detect(installed.normal()).unwrap();
    assert_eq!(
        entry_only
            .prepare_normal_without_family_check(other.normal_transfer())
            .unwrap_err(),
        PreparationError::MissingInstalledKernel
    );
}

#[test]
fn normal_only_retains_typed_target_errors_and_rejects_kernel_tag_mismatch() {
    use std::error::Error as _;
    let installed = update(false, 0, 0x12, true);
    let receiver = Receiver::from_installed(&installed).unwrap();
    let error = receiver.prepare_normal(b"malformed").unwrap_err();
    assert!(matches!(
        error,
        PreparationError::Target(UpdateError::Decode { .. })
    ));
    assert!(error.source().unwrap().source().is_some());
    let mut mismatch = installed.normal_transfer().to_vec();
    let tag = mismatch[..0x200]
        .windows(7)
        .position(|s| s == b"GENERAL")
        .unwrap();
    mismatch[tag..tag + 7].copy_from_slice(b"DIFFTAG");
    assert!(matches!(
        receiver.prepare_normal_without_family_check(&mismatch),
        Err(PreparationError::Target(UpdateError::Header { .. }))
    ));
}

#[test]
fn hardware_override_never_waives_required_settings() {
    let installed = update(false, 1, 0x12, true);
    let mut receiver = Receiver::from_installed(&installed).unwrap();
    // The captured receiver is in the scope of an identified unresolved issue;
    // target fixture does not supply the required evidence for that issue.
    receiver.settings_contract = crate::settings::update::Contract::test_unresolved_scope();
    for result in [
        receiver.prepare(installed.clone()),
        receiver.prepare_without_family_check(installed.clone()),
    ] {
        assert!(matches!(
            result,
            Err(PreparationError::Settings(
                crate::settings::update::Error::Unresolved
            ))
        ));
    }
    assert!(matches!(
        receiver.prepare_normal(installed.normal_transfer()),
        Err(PreparationError::Settings(_))
    ));
    assert!(matches!(
        receiver.prepare_normal_without_family_check(installed.normal_transfer()),
        Err(PreparationError::Settings(_))
    ));
}
