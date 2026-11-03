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
    assert_eq!(
        receiver.startup_setting_for(&[]),
        Err(PreparationError::UnresolvedStartup)
    );
    let neutral = receiver
        .startup_setting_for(&installed.normal().image)
        .unwrap()
        .unwrap();
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
    assert_eq!(
        receiver.startup_setting_for(&normal),
        Err(PreparationError::UnresolvedStartup)
    );
    normal.resize(0x2000, 0xff);
    crate::image::layout::install_test_layout(&mut normal, 0x1000);
    normal[0x25..0x28].copy_from_slice(&[0x41, 0x10, 0]);
    let setting = receiver.startup_setting_for(&normal).unwrap().unwrap();
    assert_eq!(
        (setting.parameter, setting.value, setting.explicit),
        (0x9f, 0xfe24, true)
    );
    assert_eq!(
        receiver
            .startup_setting_for(&installed.normal().image)
            .unwrap(),
        Some(neutral)
    );
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
    normal[8..16].fill(b' ');
    crate::image::matrix::install_test_contract(&mut normal, family);
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
    let startup_plan = baseline.settings().startup_plan().unwrap();
    assert_eq!(
        startup_plan.target_checks(),
        checks::Checks::discover(&installed.normal().image, Some(&installed.kernel().image))
    );
    let selection = baseline.settings().startup_selection().unwrap();
    assert_eq!(selection.setting(), startup_plan.word_setting());
    assert!(matches!(
        selection.evidence(),
        crate::compatibility::startup::Evidence::NeutralSelection { .. }
    ));
    assert_eq!(receiver.startup_checks().iter().count(), 2);
    let normal_only = receiver
        .prepare_normal(installed.normal_transfer())
        .unwrap();
    assert_eq!(
        normal_only
            .settings()
            .startup_plan()
            .unwrap()
            .target_checks(),
        startup_plan.target_checks()
    );
    assert!(matches!(
        normal_only
            .settings()
            .startup_selection()
            .unwrap()
            .evidence(),
        crate::compatibility::startup::Evidence::NeutralSelection { .. }
    ));

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
    // Geometry is now a registered SAT8 hardware input. Strict preparation
    // rejects that native difference; a family override still cannot waive the
    // independent retained-bank startup contract.
    for error in [
        receiver.prepare(target.clone()).unwrap_err(),
        receiver.prepare_normal(&bytes).unwrap_err(),
    ] {
        assert!(matches!(
            error,
            PreparationError::Compatibility(Error::FamilyMismatch { .. })
        ));
    }
    refused(receiver.prepare_without_family_check(target).unwrap_err());
    refused(
        receiver
            .prepare_normal_without_family_check(&bytes)
            .unwrap_err(),
    );
}

#[test]
#[ignore = "set PIONEER_SETTINGS_HOARD to the settings hoard root"]
fn held_ud02_settings_route_authenticates_and_roundtrips_through_receiver() {
    fn assert_reviewed_phase(current: &Update, target: &Update, recipe: &str, actual: &[u8]) {
        use crate::image::{layout::Observation, phase};
        let Observation::Known(required) = phase::discover(&current.normal().image) else {
            panic!("installed native phase is unresolved")
        };
        let reviewed =
            crate::compatibility::mechanism::reviewed_recipe_image(recipe, &target.normal().image)
                .unwrap();
        let expected = phase::correct_normal(&reviewed, required.assignment).unwrap();
        let first_difference = actual.iter().zip(&expected).position(|(a, b)| a != b);
        assert!(
            actual == expected,
            "{recipe}: actual={}, expected={}, first difference={first_difference:?}",
            crate::compatibility::mechanism::digest(actual),
            crate::compatibility::mechanism::digest(&expected),
        );
        assert!(matches!(phase::discover(actual), Observation::Known(after) if after == required));
    }
    let root = std::env::var("PIONEER_SETTINGS_HOARD").expect("PIONEER_SETTINGS_HOARD");
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
    if let Err(error) = receiver.prepare(target.clone()) {
        panic!("held UD02 preparation: {error:?}");
    }
    let forced = receiver
        .prepare_without_family_check(target.clone())
        .unwrap();
    assert_eq!(
        forced.settings().adaptation_id(),
        Some("pioneer.ud02-to-ud04-1.14")
    );
    assert_eq!(
        forced.settings().requirements(),
        &[crate::compatibility::mechanism::Requirement {
            parameter: 0x28f,
            value: 1
        }]
    );
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
        &[crate::compatibility::mechanism::Requirement {
            parameter: 0x28f,
            value: 1
        }]
    );
    assert_eq!(
        crate::compatibility::mechanism::digest(&prepared.target.normal().image),
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
    let cohorts = [&installed, &target, &prepared.target, &ud03]
        .into_iter()
        .flat_map(|current| {
            ["BDR-UD02TBD", "BDU-UD02ABC", "BDR-UD02FAN"].map(move |factory| (current, factory))
        })
        .collect::<Vec<_>>();
    for cohort in cohorts.chunks(8) {
        std::thread::scope(|scope| {
            let mut routes = Vec::new();
            for &(current, factory) in cohort {
                let target = &target;
                let installed = &installed;
                let ud03 = &ud03;
                routes.push(scope.spawn(move || {
                    let receiver = Receiver::from_installed(current)
                        .unwrap()
                        .with_original_parameters(&factory_parameters(factory));
                    let to_ud04 = receiver.prepare(target.clone()).unwrap();
                    assert_reviewed_phase(
                        current,
                        target,
                        "pioneer.ud02-to-ud04-1.14",
                        &to_ud04.target.normal().image,
                    );
                    assert_eq!(to_ud04.target.kernel().image, target.kernel().image);
                    let to_ud02 = receiver.prepare(installed.clone()).unwrap();
                    assert_reviewed_phase(
                        current,
                        installed,
                        "pioneer.ud02-stock-return-1.00",
                        &to_ud02.target.normal().image,
                    );
                    assert_eq!(to_ud02.target.kernel().image, installed.kernel().image);
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
                        assert_reviewed_phase(
                            current,
                            ud03,
                            "pioneer.ud02-to-ud03-1.03",
                            &result.target.normal().image,
                        );
                        assert_eq!(result.target.kernel().image, ud03.kernel().image);
                    }
                }));
            }
            for route in routes {
                route.join().unwrap();
            }
        });
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
        crate::compatibility::mechanism::digest(&forward_latest.target.normal().image),
        "57d0be1d40c2c8bba7f71bd7b84e66fd4394eb56924fb385610ba92c62797f32"
    );
    // Native mechanisms select the shared inverse, while original UD02 on the
    // same firmware selects the OEM mechanism program. Both independently align
    // output phase to the installed firmware. Authentication and receiver
    // readback cover the relocated routines in the Normal header too.
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
        assert_reviewed_phase(
            current,
            &installed,
            inverse.settings().adaptation_id().unwrap(),
            &inverse.target.normal().image,
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
        "hardware_family": crate::image::legacy_family(&installed.normal().image).unwrap().to_string(),
        "source_normal_sha256": [crate::compatibility::mechanism::digest(&installed.normal().image)],
        "mode": "adapt",
        "resolves_issue": "ud02-mechanism-convention",
        "target_normal_sha256": crate::compatibility::mechanism::digest(&target_normal),
        "target_model": target.normal().info().model,
        "input_length": target_normal.len(), "required_parameters": [],
        "replacements": [{ "offset": 0x600, "expected_hex": "0000", "replacement_hex": "0102" }],
        "checksum_offset": target_normal.len() - 4,
        "output_sha256": crate::compatibility::mechanism::digest(&expected),
    })
    .to_string();
    let receiver = Receiver::from_installed(&installed).unwrap();
    let baseline = receiver.prepare(target.clone()).unwrap();
    assert_eq!(baseline.target.normal().image, target_normal);
    assert_eq!(baseline.settings().adaptation_id(), None);

    let mut receiver = receiver.with_original_parameters(&factory_parameters("BDR-UD02TBD"));
    receiver.correction_contracts = Some(vec![profile]);
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
    let tag = |b: &[u8]| b[..0x200].windows(7).position(|s| s == b"GENERAL").unwrap();
    let mut other_kernel_tag = bytes.clone();
    let at = tag(&other_kernel_tag);
    other_kernel_tag[at + 6] = b'X';
    let other_kernel_tag =
        Envelope::load_with_kernel(&other_kernel_tag, installed.kernel()).unwrap();
    assert_eq!(
        Receiver::detect_with_kernel(&other_kernel_tag, installed.kernel()).unwrap_err(),
        Error::InstalledPairMismatch
    );
    let mut blank_normal = bytes.clone();
    let at = tag(&blank_normal);
    blank_normal[at..at + 7].fill(b' ');
    let mut blank_kernel = installed.kernel_transfer().to_vec();
    let at = tag(&blank_kernel);
    blank_kernel[at..at + 7].fill(b' ');
    let blank_kernel = Envelope::load(&blank_kernel).unwrap();
    let blank_normal = Envelope::load_with_kernel(&blank_normal, &blank_kernel).unwrap();
    assert_eq!(blank_normal.info().kernel_version, "");
    assert_eq!(blank_kernel.info().kernel_version, "");
    assert_eq!(
        Receiver::detect_with_kernel(&blank_normal, &blank_kernel).unwrap_err(),
        Error::InstalledPairMismatch
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
#[ignore = "set PIONEER_SETTINGS_HOARD to the settings hoard root"]
fn held_ud04_211m_recovery_does_not_invent_a_settings_requirement() {
    let root = std::env::var("PIONEER_SETTINGS_HOARD").expect("PIONEER_SETTINGS_HOARD");
    let root = std::path::Path::new(&root);
    let read = |path: &str| std::fs::read(root.join(path)).unwrap();
    let ud04 = Update::load(
        &read("oem/pioneer/sat/8A10/GENERAL/1.00/kernel/36996326ae5eaa369ef34a8434514ca137b31a3f144af0955c2d12f4a8b2ea83.enc"),
        &read("oem/pioneer/sat/8A10/GENERAL/1.14/normal/8e02ed7244d8de7564f6e0606ba803f8614a6e2b87b5e24f7ee344cdcea71141.enc"),
    ).unwrap();
    let m211 = Update::load(
        &read("oem/pioneer/sat/8801/GENERAL/1.53/kernel/f4dc0b8072158512df7616d407a406f22bba1dc18ed22b5e7fe92b81c159b0a1.enc"),
        &read("oem/pioneer/sat/8801/GENERAL/1.53/normal/769a7bdbfd9f59ea26f8875b19dcb86b193078cfdae3b00f0d1bd52f3097702b.enc"),
    ).unwrap();
    for (installed, target, original) in
        [(&ud04, &m211, "BDR-UD04ABC"), (&m211, &ud04, "BDR-211MABC")]
    {
        for receiver in [
            Receiver::from_installed(installed).unwrap(),
            Receiver::from_installed(installed)
                .unwrap()
                .with_original_parameters(&factory_parameters(original)),
        ] {
            assert!(matches!(
                receiver.prepare(target.clone()),
                Err(PreparationError::Compatibility(
                    Error::FamilyMismatch { .. }
                ))
            ));
            let prepared = receiver
                .prepare_without_family_check(target.clone())
                .unwrap();
            assert!(prepared.settings().adaptation_id().is_none());
            let final_stage = prepared.stages().last().unwrap();
            assert_eq!(final_stage.normal_image(), target.normal().image);
            assert_eq!(final_stage.normal_transfer(), target.normal_transfer());
        }
    }
    // Original UD02 remains restricted, even when it is running UD04 firmware
    // and Recovery deliberately bypasses the independent family comparison.
    let receiver = Receiver::from_installed(&ud04)
        .unwrap()
        .with_original_parameters(&factory_parameters("BDR-UD02TBD"));
    assert!(matches!(
        receiver.prepare_without_family_check(m211),
        Err(PreparationError::Adaptation(
            crate::settings::adaptation::Error::OriginalMismatch
        ))
    ));
}

#[test]
fn hardware_override_never_waives_required_settings() {
    let installed = update(false, 1, 0x12, true);
    let mut normal = installed.normal().image.clone();
    // Both images really belong to the identified issue's family. A different
    // known family is governed by the independent family gate instead.
    let mut setup = Vec::new();
    for (address, value) in [
        (0xe436u16, 0x0d),
        (0xe43a, 0x35),
        (0xe43b, 6),
        (0xe45b, 0x0a),
        (0xe463, 7),
        (0xe46a, 0x0b),
        (0xe46b, 1),
        (0xedcc, 0),
        (0xfe94, 0x40),
        (0xfec0, 0x87),
    ] {
        setup.extend([0xf8, value, 0x6a, 0x88]);
        setup.extend(address.to_be_bytes());
    }
    setup.extend([0x7f, 0xc5, 0x72, 0x50]);
    normal[0x400..0x480].fill(0);
    normal[0x400..0x400 + setup.len()].copy_from_slice(&setup);
    // Match the historical mechanism cohort while retaining complete v6
    // observations. The short native phase form does not establish the separate
    // mechanism convention required by this cohort.
    normal[0x700..0x716].fill(0xff);
    normal[0x700..0x706].copy_from_slice(&[0x6a, 0x18, 0xff, 0xc5, 0x72, 0x50]);
    let mut phase = crate::image::phase::tests::fixture(true);
    for at in (0..phase.len() - 3).step_by(2) {
        if phase[at..at + 4] == [0x5e, 0x41, 1, 0x90] {
            phase[at..at + 4].copy_from_slice(&[0x5e, 0x41, 0x0e, 0x90]);
        }
    }
    normal[0xd00..0xf00].copy_from_slice(&phase);
    fix_sum(&mut normal);
    let mut bytes = installed.normal().repack(&normal).unwrap();
    SigningKey::random()
        .unwrap()
        .sign_normal(&mut bytes)
        .unwrap();
    let installed = Update::load(installed.kernel_transfer(), &bytes).unwrap();
    let receiver = Receiver::from_installed(&installed).unwrap();
    assert_eq!(
        crate::image::legacy_family(&installed.normal().image)
            .unwrap()
            .to_string(),
        "e4f1f98dcdf4c06b"
    );
    // Native phase evidence does not authorize the unresolved mechanism convention.
    for result in [
        receiver.prepare(installed.clone()),
        receiver.prepare_without_family_check(installed.clone()),
    ] {
        assert!(
            matches!(
                result,
                Err(PreparationError::Settings(
                    crate::settings::update::Error::Unresolved
                ))
            ),
            "unexpected preparation result: {result:?}"
        );
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
fn handoff_bridge_mismatch_reports_the_incoming_kernel_startup() {
    let shifted = |original: &Update| {
        let mut kernel = original.kernel().image.clone();
        kernel.copy_within(0x20..0x30, 0x2a);
        kernel[0x20..0x2a].fill(0);
        kernel[0x2107] = 0x2a;
        fix_sum(&mut kernel);
        Update::load(
            &original.kernel().repack(&kernel).unwrap(),
            &original.normal().repack(&original.normal().image).unwrap(),
        )
        .unwrap()
    };
    // An already-adapted source calls 0x40002a while its own startup stays
    // at 0x400020; the incoming Kernel starts at 0x40002a.
    let original = update(false, 1, 0x12, true);
    let mut kernel = original.kernel().image.clone();
    kernel[0x2107] = 0x2a;
    fix_sum(&mut kernel);
    let adapted = Update::load(
        &original.kernel().repack(&kernel).unwrap(),
        &original.normal().repack(&original.normal().image).unwrap(),
    )
    .unwrap();
    let target = shifted(&update(false, 1, 0x12, true));
    let receiver = Receiver::from_installed(&adapted).unwrap();
    assert_eq!(
        crate::receiver::handoff_bridge::prepare(&receiver, target.kernel()).unwrap_err(),
        PreparationError::KernelHandoff(crate::image::KernelHandoffError::Mismatch {
            installed: 0x40002a,
            target: crate::image::kernel_startup_entry(&target.kernel().image).unwrap(),
        })
    );
    assert_eq!(
        crate::image::kernel_startup_entry(&target.kernel().image),
        Some(0x40002a)
    );
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

#[test]
fn native_phase_preparation_is_bidirectional_for_full_and_normal_only_updates() {
    use crate::image::phase::{correct_normal, Assignment};
    let direct = update(false, 1, 0x12, true);
    let swapped_image = correct_normal(&direct.normal().image, Assignment::Swapped).unwrap();
    let mut bytes = direct.normal().repack(&swapped_image).unwrap();
    SigningKey::random()
        .unwrap()
        .sign_normal(&mut bytes)
        .unwrap();
    let kernel_bytes = direct.kernel().repack(&direct.kernel().image).unwrap();
    let swapped = Update::load(&kernel_bytes, &bytes).unwrap();
    assert_ne!(direct.family(), swapped.family());
    for (installed, target) in [(&direct, &swapped), (&swapped, &direct)] {
        fn context(pair: &Update) -> crate::compatibility::Firmware<'_> {
            crate::compatibility::Firmware {
                hardware: &pair.normal().info().hardware_version,
                normal: &pair.normal().image,
                kernel: Some(&pair.kernel().image),
            }
        }
        let plan = crate::compatibility::plan(context(installed), context(target)).unwrap();
        let prepared_file = plan
            .prepare_file(target.normal(), Some(target.kernel()))
            .unwrap()
            .unwrap();
        let prepared_pair = Update::load(&kernel_bytes, &prepared_file).unwrap();
        assert_eq!(prepared_pair.normal().image, installed.normal().image);
        assert_eq!(
            plan.prepare_file(installed.normal(), Some(target.kernel())),
            Err(crate::compatibility::Error::ComponentMismatch)
        );
        let receiver = Receiver::from_installed(installed).unwrap();
        let full = receiver.prepare(target.clone()).unwrap();
        assert_eq!(
            full.settings().adaptation_id(),
            Some("pioneer.native-correction.v1")
        );
        assert!(full.settings().requirements().is_empty());
        assert_eq!(full.target.normal().image, installed.normal().image);
        assert_eq!(full.target.kernel().image, target.kernel().image);
        assert_eq!(full.target.family(), installed.family());
        let forced = receiver
            .prepare_without_family_check(target.clone())
            .unwrap();
        assert_eq!(forced.target.normal().image, installed.normal().image);
        assert_eq!(forced.target.kernel().image, target.kernel().image);
        assert_eq!(
            forced.settings().firmware_corrections(),
            full.settings().firmware_corrections()
        );
        let target_bytes = target.normal().repack(&target.normal().image).unwrap();
        let normal = receiver.prepare_normal(&target_bytes).unwrap();
        let forced_normal = receiver
            .prepare_normal_without_family_check(&target_bytes)
            .unwrap();
        assert_eq!(forced_normal.normal_image(), installed.normal().image);
        assert_eq!(
            forced_normal.settings().firmware_corrections(),
            normal.settings().firmware_corrections()
        );
        assert_eq!(normal.normal_image(), installed.normal().image);
        assert_eq!(
            normal.settings().adaptation_id(),
            Some("pioneer.native-correction.v1")
        );
    }
    let receiver = Receiver::from_installed(&update(false, 1, 0x13, true)).unwrap();
    assert!(matches!(
        receiver.prepare(swapped),
        Err(PreparationError::Compatibility(
            Error::FamilyMismatch { .. }
        ))
    ));
}

#[test]
fn generic_kernel_steps_materialize_only_the_agreed_edits_in_both_directions() {
    use crate::compatibility::KernelStep;
    fn at_entry(pair: Update, entry: u32) -> Update {
        let mut image = pair.kernel().image.clone();
        if entry != 0x400020 {
            let offset = (entry - 0x400000) as usize;
            image.copy_within(0x20..0x30, offset);
            image[0x20..offset].fill(0);
        }
        image[0x2105..0x2108].copy_from_slice(&entry.to_be_bytes()[1..]);
        fix_sum(&mut image);
        Update::load(
            &pair.kernel().repack(&image).unwrap(),
            &pair.normal().repack(&pair.normal().image).unwrap(),
        )
        .unwrap()
    }
    fn sum(image: &[u8]) -> u32 {
        image.chunks_exact(4).fold(0u32, |s, w| {
            s.wrapping_add(u32::from_be_bytes(w.try_into().unwrap()))
        })
    }
    for (source_entry, target_entry) in [
        (0x400020, 0x400020),
        (0x400020, 0x40002a),
        (0x40002a, 0x400020),
    ] {
        for (gated, marker) in [(false, 1), (true, 0), (true, 0xff)] {
            let source = at_entry(update(gated, 1, 0x12, true), source_entry);
            let target = at_entry(update(false, marker, 0x12, true), target_entry);
            let plan = Receiver::from_installed(&source)
                .unwrap()
                .prepare(target.clone())
                .unwrap();
            let mut expected = Vec::new();
            if source_entry != target_entry {
                expected.push(KernelStep::Handoff {
                    from: source_entry,
                    to: target_entry,
                });
            }
            if gated && marker != 1 {
                expected.push(KernelStep::ReceiverMarker {
                    from: marker,
                    to: 1,
                });
            }
            expected.push(KernelStep::Target);
            assert_eq!(plan.kernel_steps(), expected);
            assert_eq!(plan.stages().len(), expected.len());
            for (step, stage) in expected.iter().zip(plan.stages()) {
                let image = stage.kernel_image().unwrap();
                assert_eq!(
                    stage.settings().startup_plan().unwrap().target_checks(),
                    crate::startup::checks::Checks::discover(stage.normal_image(), Some(image))
                );
                assert_eq!(sum(image), 0);
                crate::image::check_kernel_handoff(
                    &stage.receiver.installed_kernel().unwrap().image,
                    image,
                )
                .unwrap();
                let (original, allowed) = match step {
                    KernelStep::Handoff { to, .. } => {
                        assert_eq!(stage.bridge(), Some(BridgeKind::KernelHandoff));
                        assert_eq!(stage.normal_image(), source.normal().image);
                        assert_eq!(
                            crate::image::kernel_startup_entry(image),
                            Some(source_entry)
                        );
                        assert_eq!(crate::image::kernel_handoff_entry(image), Some(*to));
                        let operands =
                            crate::image::kernel_handoff_contract(&source.kernel().image)
                                .unwrap()
                                .operands;
                        let allowed: Vec<usize> =
                            operands.into_iter().flat_map(|at| at..at + 3).collect();
                        (source.kernel().image.as_slice(), allowed)
                    }
                    KernelStep::ReceiverMarker { to, .. } => {
                        assert_eq!(stage.bridge(), Some(BridgeKind::ReceiverMarker));
                        assert_eq!(image[KERNEL_MARKER_OFFSET], *to);
                        (target.kernel().image.as_slice(), vec![KERNEL_MARKER_OFFSET])
                    }
                    KernelStep::Target => {
                        assert_eq!(stage.bridge(), None);
                        assert_eq!(image, target.kernel().image);
                        (target.kernel().image.as_slice(), Vec::new())
                    }
                };
                for (offset, (before, after)) in original.iter().zip(image).enumerate() {
                    if before != after {
                        assert!(
                            allowed.contains(&offset)
                                || (crate::envelope::KERNEL_CHECKSUM_WORD_OFFSET
                                    ..crate::envelope::KERNEL_CHECKSUM_WORD_OFFSET + 4)
                                    .contains(&offset),
                            "unexpected Kernel edit at {offset:#x}"
                        );
                    }
                }
            }
            assert_eq!(plan.final_kernel_image(), target.kernel().image);
            assert_eq!(plan.target.normal().image, target.normal().image);
        }
    }
}

#[test]
fn registry_native_planning_runs_every_owner_even_when_family_hashes_match() {
    let installed = update(false, 1, 0x12, true);
    let receiver = Receiver::from_installed(&installed).unwrap();
    assert_eq!(
        receiver.check_family_with_kernel(installed.normal(), installed.kernel()),
        installed.family().ok_or(Error::UnknownTargetFamily)
    );
    for check_family in [true, false] {
        let native = receiver
            .plan_native_correction(installed.normal(), installed.kernel(), check_family)
            .unwrap()
            .unwrap();
        let expected: Vec<_> = crate::filters::filters()
            .iter()
            .map(|owner| owner.id())
            .collect();
        assert_eq!(
            native
                .filters()
                .iter()
                .map(|decision| decision.id)
                .collect::<Vec<_>>(),
            expected
        );
        let startup = native
            .filters()
            .iter()
            .find(|decision| decision.id == "startup-prerequisite")
            .unwrap();
        assert_eq!(startup.target.role, crate::filters::Role::Operational);
        assert!(matches!(
            startup.target.finding,
            crate::filters::Finding::Unresolved(_)
        ));
        assert!(!startup.waived);
    }
}

#[test]
fn startup_selection_uses_exact_architecture_and_never_gives_ata_or_scsi_h8_actions() {
    let installed = update(false, 1, 0x12, true);
    let receiver = Receiver::from_installed(&installed).unwrap();
    for hardware in ["ATA 0005", "SCSI0001"] {
        assert!(receiver
            .startup_plan_for(crate::compatibility::Firmware {
                hardware,
                normal: &installed.normal().image,
                kernel: Some(&installed.kernel().image),
            })
            .unwrap()
            .is_none());
    }
}

#[test]
fn forced_full_and_normal_only_keep_declared_native_layout_and_phase_effects() {
    use crate::image::{layout, phase};
    fn file(base: &Update, image: &[u8]) -> Update {
        let mut key = [0; 20];
        key[19] = 5;
        let signer = SigningKey::from_bytes(key).unwrap();
        let pair = encode_encrypted_pair(
            &BuildInputs {
                kernel_image: &base.kernel().image,
                normal_image: image,
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
    fn normal_checksum(image: &mut [u8]) {
        image[16..20].fill(0);
        let sum = image.chunks_exact(4).fold(0u32, |sum, word| {
            sum.wrapping_add(u32::from_be_bytes(word.try_into().unwrap()))
        });
        image[16..20].copy_from_slice(&sum.wrapping_neg().to_be_bytes());
    }
    let original = update(false, 1, 0x12, true);
    let mut kernel = original.kernel().image.clone();
    let selector = [
        0x6b, 0x28, 0, 0x5c, 0xff, 0xfe, 0x6b, 0x20, 0, 0x5d, 0xff, 0xfe, 0x79, 0x28, 0xff, 0xff,
        0x47, 0x12, 0x79, 0x20, 0xff, 0xff, 0x47, 4, 0x1d, 8, 0x43, 8, 0x7a, 0, 0, 0x5c, 0, 0,
        0x40, 6, 0x7a, 0, 0, 0x5d, 0, 0, 0x54, 0x70,
    ];
    kernel[0x46fa..0x46fa + selector.len()].copy_from_slice(&selector);
    kernel[0x4800..0x4806].copy_from_slice(&[0x5e, 0x40, 0x46, 0xfa, 0x54, 0x70]);
    fix_sum(&mut kernel);
    let base = Update::load(
        &original.kernel().repack(&kernel).unwrap(),
        original.normal_transfer(),
    )
    .unwrap();
    let mut image = normal_image(0x10000);
    image[0x500..0x510].copy_from_slice(&original.normal().image[0x500..0x510]);
    image[8..16].fill(b' ');
    crate::image::matrix::install_test_contract(&mut image, 0x12);
    layout::install_test_layout_variant(&mut image, 0x1000, 8);
    // This case supplies fixed-bank geometry below instead of the shared
    // fixture's marker-bank initializer and selector. Retaining both would
    // correctly yield conflicting native geometry.
    image[0x17e0..0x1a00].fill(0xff);
    let calculation = [
        0x5d, 0x60, 0x7a, 2, 0, 0x5d, 0x51, 0x60, 0x7a, 0x20, 0, 0x5c, 0, 0, 0x46, 4, 0x79, 0x0a,
        0, 0x5c, 0x0f, 0xa0, 0x69, 0x21,
    ];
    image[0x7000..0x7000 + calculation.len()].copy_from_slice(&calculation);
    normal_checksum(&mut image);
    let installed = file(&base, &image);
    let mut shifted = image.clone();
    for at in (34..image.len() - 3).step_by(2) {
        if image[at - 2] == 0x7a && image[at..at + 4] == 0x9984u32.to_be_bytes() {
            shifted[at..at + 4].copy_from_slice(&0x5984u32.to_be_bytes());
        }
    }
    normal_checksum(&mut shifted);
    let shifted = phase::correct_normal(&shifted, phase::Assignment::Swapped).unwrap();
    let target = file(&base, &shifted);
    let candidate = |pair: &Update| {
        crate::image::matrix::discover(
            &pair.normal().info().hardware_version,
            &pair.normal().image,
            Some(&pair.kernel().image),
        )
        .unwrap_or_else(|| {
            panic!(
                "required fields: {:?}",
                crate::filters::inspect(crate::compatibility::Firmware {
                    hardware: &pair.normal().info().hardware_version,
                    normal: &pair.normal().image,
                    kernel: Some(&pair.kernel().image),
                })
            )
        })
        .candidate
    };
    assert_ne!(candidate(&installed), candidate(&target));
    for (installed, target) in [(&installed, &target), (&target, &installed)] {
        let receiver = Receiver::from_installed(installed).unwrap();
        let full = receiver
            .prepare_without_family_check(target.clone())
            .unwrap();
        let normal = receiver
            .prepare_normal_without_family_check(target.normal_transfer())
            .unwrap();
        assert_eq!(full.target.normal().image, installed.normal().image);
        assert_eq!(normal.normal_image(), installed.normal().image);
        assert_eq!(full.target.kernel().image, target.kernel().image);
        assert!(full
            .settings()
            .firmware_corrections()
            .iter()
            .any(|effect| matches!(
                effect,
                crate::compatibility::Correction::PersistentParameterLayout { .. }
            )));
        assert_eq!(
            full.settings().firmware_corrections(),
            normal.settings().firmware_corrections()
        );
    }
}

#[test]
fn reviewed_mechanism_cannot_change_an_unrelated_family_fact_under_either_force_api() {
    let installed = update(false, 1, 0x12, true);
    let target = update(false, 1, 0x12, true);
    let mut output = target.normal().image.clone();
    output[0x701] = 0x13;
    fix_sum(&mut output);
    let profile = serde_json::json!({
        "schema_version": 1, "id": "test.unrelated-native-field",
        "hardware_scheme": crate::image::FAMILY_SCHEME,
        "hardware_family": crate::image::legacy_family(&installed.normal().image).unwrap().to_string(),
        "source_normal_sha256": [crate::compatibility::mechanism::digest(&installed.normal().image)],
        "mode": "adapt", "resolves_issue": "ud02-mechanism-convention",
        "target_normal_sha256": crate::compatibility::mechanism::digest(&target.normal().image),
        "target_model": target.normal().info().model,
        "input_length": output.len(), "required_parameters": [],
        "replacements": [{"offset": 0x701, "expected_hex": "12", "replacement_hex": "13"}],
        "checksum_offset": output.len()-4,
        "output_sha256": crate::compatibility::mechanism::digest(&output),
    }).to_string();
    let mut receiver = Receiver::from_installed(&installed).unwrap();
    receiver.correction_contracts = Some(vec![profile]);
    for error in [
        receiver
            .prepare_without_family_check(target.clone())
            .map(|_| ())
            .unwrap_err(),
        receiver
            .prepare_normal_without_family_check(target.normal_transfer())
            .map(|_| ())
            .unwrap_err(),
    ] {
        assert_eq!(
            error,
            PreparationError::Adaptation(crate::compatibility::mechanism::Error::Guard)
        );
    }
}
