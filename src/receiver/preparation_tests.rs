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
    crate::startup::bank::fixture(&mut normal);
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

fn factory_parameters(code: &str) -> [u8; crate::production::PARAMETERS_LEN] {
    let mut bytes = [0xff; crate::production::PARAMETERS_LEN];
    bytes[0x84..0x88].copy_from_slice(b"kw01");
    bytes[0x90..0x9f].fill(b' ');
    bytes[0x90..0x90 + code.len()].copy_from_slice(code.as_bytes());
    bytes
}

#[test]
fn every_preparation_path_uses_the_receivers_startup_checks() {
    use crate::startup::{bank, checks};
    let installed = update(false, 1, 0x12, true);
    let receiver = Receiver::from_installed(&installed).unwrap();
    let baseline = receiver.prepare(installed.clone()).unwrap();
    assert!(baseline.settings().startup_plan().is_some());
    assert_eq!(receiver.startup_checks().iter().count(), 2);

    let mut normal = installed.normal().image.clone();
    for at in [0x180a, 0x190a] {
        normal[at..at + 4].copy_from_slice(&0xfedc4322u32.to_be_bytes());
    }
    fix_sum(&mut normal);
    let mut bytes = installed.normal().repack(&normal).unwrap();
    let mut key = [0; 20];
    key[19] = 5;
    SigningKey::from_bytes(key)
        .unwrap()
        .sign_normal(&mut bytes)
        .unwrap();
    let target = Update::load(installed.kernel_transfer(), &bytes).unwrap();
    let refused = |e: PreparationError| {
        assert!(matches!(
            e,
            PreparationError::Startup(checks::Error::Banks(bank::Error::ConversionRequired { .. }))
        ))
    };
    refused(receiver.prepare(target.clone()).unwrap_err());
    refused(receiver.prepare_without_family_check(target).unwrap_err());
    refused(receiver.prepare_normal(&bytes).unwrap_err());
    refused(
        receiver
            .prepare_normal_without_family_check(&bytes)
            .unwrap_err(),
    );
}

#[test]
fn held_ud02_settings_route_authenticates_and_roundtrips_through_receiver() {
    let Ok(root) = std::env::var("PIONEER_SETTINGS_HOARD") else {
        return;
    };
    let root = std::path::Path::new(&root);
    let read = |path: &str| std::fs::read(root.join(path)).unwrap();
    let source_kernel = read("dump/pioneer/sat/8410/ID84/1.00/kernel/7e1104a2843825aea6d03bde6359d94254f3cea192e576450f3f94c4afcee824.enc");
    let mut source_normal = read("dump/pioneer/sat/8410/ID84/1.00/normal/a37a4f222e2fa7e225f6451b30eb2e459f1933ab38c81a4d7967c10d77bc1373.enc");
    let kernel = Envelope::load(&source_kernel).unwrap();
    let captured = Envelope::load_with_kernel(&source_normal, &kernel).unwrap();
    // The original capture has the unsigned-backup sentinel. Model the host's
    // normal preparation: sign its transfer without changing decoded firmware.
    assert!(
        source_normal[crate::envelope::builder::NORMAL_SIGNATURE_RANGE]
            .iter()
            .all(|b| *b == 0)
    );
    let signer = SigningKey::random().unwrap();
    use crate::envelope::builder::{normal_authentication_from_kernel, NormalAuthentication};
    match normal_authentication_from_kernel(&kernel.image).unwrap() {
        NormalAuthentication::KeyAndCiphertext => signer.sign_normal(&mut source_normal).unwrap(),
        NormalAuthentication::CiphertextOnly => signer
            .sign_normal_ciphertext_only(&mut source_normal)
            .unwrap(),
        other => panic!("unexpected source authentication {other:?}"),
    }
    let installed = Update::load(&source_kernel, &source_normal).unwrap();
    assert_eq!(installed.normal().image, captured.image);
    let target = Update::load(
        &read("oem/pioneer/sat/8A10/GENERAL/1.00/kernel/36996326ae5eaa369ef34a8434514ca137b31a3f144af0955c2d12f4a8b2ea83.enc"),
        &read("oem/pioneer/sat/8A10/GENERAL/1.14/normal/8e02ed7244d8de7564f6e0606ba803f8614a6e2b87b5e24f7ee344cdcea71141.enc"),
    ).unwrap();
    let receiver = Receiver::from_installed(&installed).unwrap();
    assert!(receiver.prepare(target.clone()).is_ok());
    let mut parameters = factory_parameters("BDR-UD02TBD");
    parameters[0x84..0x88].fill(0xff);
    parameters[0xc0..0xc0 + 90].fill(b'0');
    parameters[0xc0 + 76..0xc0 + 82].copy_from_slice(b"130525");
    let prepared = receiver
        .with_original_parameters(&parameters)
        .prepare(target.clone())
        .unwrap();
    assert_eq!(
        prepared.settings().adaptation_id(),
        Some("pioneer.ud02-to-ud04-1.14")
    );
    assert_eq!(
        prepared.settings().requirements(),
        &[crate::settings::adaptation::Requirement {
            parameter: 0x28f,
            value: 1
        }]
    );
    assert_eq!(
        crate::settings::adaptation::digest(&prepared.target.normal().image),
        "ca09032288c62b8b26bb983431af11b52aaeec8da9bd0e80afcccdf3b07f0815"
    );
    let back = Receiver::from_installed(&prepared.target)
        .unwrap()
        .with_original_parameters(&parameters)
        .prepare(installed.clone())
        .unwrap();
    assert_eq!(
        back.settings().adaptation_id(),
        Some("pioneer.ud02-stock-return-1.00")
    );
    assert_eq!(back.target.normal().image, installed.normal().image);
    assert_eq!(back.target.kernel().image, installed.kernel().image);

    let ud03 = Update::load(
        &read("oem/pioneer/sat/8510/ID19/1.03/kernel/36d0e3542a34a653250295f86d489d5e1e4f7931043351d856f27e57477d72ae.enc"),
        &read("oem/pioneer/sat/8510/ID19/1.03/normal/6042da6069fec90d0e8052613f3f2d6e8ebb7e0d41dc770a5cf4c601f3960d4e.enc"),
    ).unwrap();
    for current in [&installed, &target, &prepared.target, &ud03] {
        for factory in ["BDR-UD02TBD", "BDU-UD02ABC", "BDR-UD02FAN"] {
            let receiver = Receiver::from_installed(current)
                .unwrap()
                .with_original_parameters(&factory_parameters(factory));
            let to_ud04 = receiver.prepare(target.clone()).unwrap();
            assert_eq!(
                to_ud04.target.normal().image,
                prepared.target.normal().image
            );
            let to_ud02 = receiver.prepare(installed.clone()).unwrap();
            assert_eq!(to_ud02.target.normal().image, installed.normal().image);
            for bypass in [false, true] {
                let result = if bypass {
                    receiver.prepare_without_family_check(ud03.clone())
                } else {
                    receiver.prepare(ud03.clone())
                }
                .unwrap();
                assert_eq!(
                    result.settings().adaptation_id(),
                    Some("pioneer.ud02-to-ud03-1.03")
                );
                assert_eq!(
                    crate::settings::adaptation::digest(&result.target.normal().image),
                    "f78a48ea604d36663f1da13b5eaad63396e8a0c4ccc6c18fb7f38547f1816a56"
                );
            }
        }
    }
    let ud03_latest = Update::load(
        &read("oem/pioneer/sat/8511/GENERAL/1.14/kernel/77432fcd9cf4d32e711458015e01c995ee780706d1f9cb4800ff77f4b371e224.enc"),
        &read("oem/pioneer/sat/8511/GENERAL/1.14/normal/4a5c9c055c4a31bed730618c0ea68597c807ea1e581558acfd7e873f8e32eba8.enc"),
    ).unwrap();
    let forward_latest = Receiver::from_installed(&installed)
        .unwrap()
        .with_original_parameters(&factory_parameters("BDR-UD02TBD"))
        .prepare(ud03_latest.clone())
        .unwrap();
    assert_eq!(
        crate::settings::adaptation::digest(&forward_latest.target.normal().image),
        "57d0be1d40c2c8bba7f71bd7b84e66fd4394eb56924fb385610ba92c62797f32"
    );
    // Native mechanisms select the shared inverse, while original UD02 on the
    // very same firmware selects pristine OEM return. Decode/authentication and
    // receiver readback cover the relocated routines in the Normal header too.
    for (current, original) in [
        (&ud03, "BDR-UD03FAL"),
        (&ud03_latest, "BDR-UD03ABC"),
        (&target, "BDR-UD04ABC"),
    ] {
        let parameters = factory_parameters(original);
        let inverse = Receiver::from_installed(current)
            .unwrap()
            .with_original_parameters(&parameters)
            .prepare(installed.clone())
            .unwrap();
        assert_eq!(
            inverse.settings().adaptation_id(),
            Some(if original == "BDR-UD03FAL" {
                "pioneer.ud03-to-ud02-1.00-whole"
            } else if original == "BDR-UD03ABC" {
                "pioneer.ud03-to-ud02-1.00-packed"
            } else {
                "pioneer.ud04-to-ud02-1.00"
            })
        );
        assert!(inverse.settings().requirements().is_empty());
        assert_eq!(
            crate::settings::adaptation::digest(&inverse.target.normal().image),
            if original == "BDR-UD03FAL" {
                "95e5a7a5c841a5b1b66895ac299285c869c43222f134044280ffbf8971426305"
            } else {
                "33d04b3d4f1d432f00f3498706fbb04369cdac0e29253ba5ead8f6b749905995"
            }
        );
        assert_eq!(inverse.target.kernel().image, installed.kernel().image);
        let returned = Receiver::from_installed(&inverse.target)
            .unwrap()
            .with_original_parameters(&parameters)
            .prepare(current.clone())
            .unwrap();
        assert_eq!(returned.target.normal().image, current.normal().image);
        assert_eq!(returned.target.kernel().image, current.kernel().image);
        assert!(returned.settings().requirements().is_empty());
        let reapply = Receiver::from_installed(&inverse.target)
            .unwrap()
            .with_original_parameters(&parameters)
            .prepare(installed.clone())
            .unwrap();
        assert_eq!(reapply.target.normal().image, inverse.target.normal().image);
    }
}

#[test]
fn adding_one_test_profile_changes_only_the_matching_prepared_image() {
    let installed = update(false, 1, 0x12, true);
    let target = update(false, 0, 0x12, true);
    let target_normal = target.normal().image.clone();
    let mut expected = target_normal.clone();
    expected[0x600..0x602].copy_from_slice(&[1, 2]);
    fix_sum(&mut expected);
    let profile = serde_json::json!({
        "schema_version": 1, "id": "test.single-image",
        "hardware_scheme": crate::image::FAMILY_SCHEME,
        "hardware_family": installed.family().unwrap().to_string(),
        "source_normal_sha256": [crate::settings::adaptation::digest(&installed.normal().image)],
        "mode": "adapt",
        "resolves_issue": "ud02-mechanism-convention",
        "target_normal_sha256": crate::settings::adaptation::digest(&target_normal),
        "target_model": target.normal().info().model,
        "input_length": target_normal.len(), "required_parameters": [],
        "replacements": [{ "offset": 0x600, "expected_hex": "0000", "replacement_hex": "0102" }],
        "checksum_offset": target_normal.len() - 4,
        "output_sha256": crate::settings::adaptation::digest(&expected),
    })
    .to_string();
    let receiver = Receiver::from_installed(&installed).unwrap();
    let baseline = receiver.prepare(target.clone()).unwrap();
    assert_eq!(baseline.target.normal().image, target_normal);
    assert_eq!(baseline.settings().adaptation_id(), None);

    let mut receiver = receiver.with_original_parameters(&factory_parameters("BDR-UD02TBD"));
    receiver.adaptation_profiles = Some(vec![profile]);
    let prepared = receiver.prepare(target.clone()).unwrap();
    assert_eq!(prepared.target.normal().image, expected);
    assert_eq!(
        prepared.settings().adaptation_id(),
        Some("test.single-image")
    );
    assert_eq!(prepared.final_kernel_image(), target.kernel().image);
    let normal = target.normal().repack(&target_normal).unwrap();
    let prepared = receiver.prepare_normal(&normal).unwrap();
    assert_eq!(prepared.normal_image(), expected);

    // Factory metadata is not an extra eligibility gate for a certified pair.
    let receiver = receiver.with_original_parameters(&factory_parameters("BDR-UD04"));
    assert_eq!(
        receiver.prepare(target).unwrap().target.normal().image,
        expected
    );
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
        let restored = Envelope::load(plan.final_stage_kernel_transfer().unwrap()).unwrap();
        assert_eq!(first.image, plan.first_kernel_image());
        assert_eq!(restored.image, pristine);
        let restore = plan.final_stage_receiver().unwrap();
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
        crate::receiver::transport::detect(
            &prepared.stages[0]
                .receiver
                .installed_kernel()
                .unwrap()
                .image
        ),
        crate::receiver::transport::KernelReceive::FrontKeyTwoRegion
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
        assert!(plan.final_stage_kernel_transfer().is_none());
        assert!(plan.final_stage_receiver().is_none());
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
        PreparationError::UnsupportedFinalStage
    );
    assert_eq!(
        receiver.prepare(update(false, 0, 0x12, false)).unwrap_err(),
        PreparationError::FinalStageEntry(Error::Unsupported)
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
        assert!(plan.final_stage_receiver().is_none());
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
        PreparationError::UnsupportedFinalStage
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

#[test]
fn handoff_bridge_preserves_source_normal_and_finishes_with_exact_target() {
    let source = update(false, 1, 0x12, true);
    let original_target = update(false, 1, 0x12, true);
    let mut kernel = original_target.kernel().image.clone();
    kernel.copy_within(0x20..0x30, 0x2a);
    kernel[0x20..0x2a].fill(0);
    kernel[0x2107] = 0x2a;
    fix_sum(&mut kernel);
    let target = Update::load(
        &original_target.kernel().repack(&kernel).unwrap(),
        &original_target
            .normal()
            .repack(&original_target.normal().image)
            .unwrap(),
    )
    .unwrap();
    let prepared = Receiver::from_installed(&source)
        .unwrap()
        .prepare(target.clone())
        .unwrap();
    assert_eq!(prepared.stages().len(), 2);
    let bridge = &prepared.stages()[0];
    assert_eq!(bridge.bridge(), Some(BridgeKind::KernelHandoff));
    assert_eq!(bridge.normal_image(), source.normal().image);
    let patched = bridge.kernel_image().unwrap();
    assert_eq!(crate::image::kernel_startup_entry(patched), Some(0x400020));
    assert_eq!(crate::image::kernel_handoff_entry(patched), Some(0x40002a));
    // The only allowed edits are the programmer's restart operand and checksum.
    for (at, (before, after)) in source.kernel().image.iter().zip(patched).enumerate() {
        if before != after {
            assert!(
                (0x2105..0x2108).contains(&at)
                    || (crate::envelope::KERNEL_CHECKSUM_WORD_OFFSET
                        ..crate::envelope::KERNEL_CHECKSUM_WORD_OFFSET + 4)
                        .contains(&at)
            );
        }
    }
    let final_stage = &prepared.stages()[1];
    assert_eq!(final_stage.bridge(), None);
    assert_eq!(
        final_stage.kernel_transfer().unwrap(),
        target.kernel_transfer()
    );
    assert_eq!(final_stage.normal_transfer(), target.normal_transfer());
    assert_eq!(final_stage.kernel_image().unwrap(), target.kernel().image);
}

#[test]
fn intermediate_marker_must_be_accepted_by_its_receiver() {
    let source = update(true, 0, 0x12, true);
    let receiver = Receiver::from_installed(&source).unwrap();
    // A handoff bridge retains the source marker. A source that rejects that
    // marker cannot install its own bridge, even though its final target could
    // otherwise be accepted. Stage admission must catch this before any I/O.
    let error = PreparedStage::pair(
        receiver,
        &source,
        crate::settings::update::Plan::default(),
        Some(BridgeKind::KernelHandoff),
    )
    .unwrap_err();
    assert_eq!(error, PreparationError::RejectedMarker);
}

#[test]
fn handoff_bridge_signs_unsigned_capture_without_accepting_invalid_signatures() {
    let source = update(false, 1, 0x12, true);
    let original_target = update(false, 1, 0x12, true);
    let mut kernel = original_target.kernel().image.clone();
    kernel.copy_within(0x20..0x30, 0x2a);
    kernel[0x20..0x2a].fill(0);
    kernel[0x2107] = 0x2a;
    fix_sum(&mut kernel);
    let target = Update::load(
        &original_target.kernel().repack(&kernel).unwrap(),
        &original_target
            .normal()
            .repack(&original_target.normal().image)
            .unwrap(),
    )
    .unwrap();
    for invalid in [false, true] {
        let mut bytes = source.normal().repack(&source.normal().image).unwrap();
        bytes[0x170..0x1c0].fill(0);
        if invalid {
            bytes[0x170] = 1;
        }
        let normal = Envelope::load_with_kernel(&bytes, source.kernel()).unwrap();
        let receiver = Receiver::detect_with_kernel(&normal, source.kernel()).unwrap();
        let result = receiver.prepare(target.clone());
        if invalid {
            assert!(matches!(
                result,
                Err(PreparationError::Target(UpdateError::Authentication))
            ));
        } else {
            let prepared = result.unwrap();
            let stage = &prepared.stages()[0];
            assert_eq!(stage.normal_image(), source.normal().image);
            assert!(stage.normal_transfer()[0x170..0x1c0]
                .iter()
                .any(|byte| *byte != 0));
            assert!(crate::envelope::builder::normal_authentication_valid(
                stage.normal_transfer(),
                stage.kernel_image().unwrap()
            ));
        }
    }
}
