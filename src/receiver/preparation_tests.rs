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

#[test]
fn receiver_settings_never_select_persistent_startup_writes() {
    let installed = update(false, 1, 0x12, true);
    let receiver = Receiver::from_installed(&installed).unwrap();
    for restore in [false, true] {
        let settings = receiver
            .settings_plan_for(installed.normal(), installed.kernel(), restore)
            .unwrap();
        assert!(settings.startup_setting().is_none());
        assert!(settings.startup_selection().is_none());
        assert!(settings.filter_actions().is_empty());
        assert_eq!(settings.entries().len(), usize::from(restore));
        assert!(settings.entries().iter().all(|entry| matches!(
            entry.effect(),
            crate::settings::update::Effect::TemporaryKernelMarker
        )));
    }
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
    let mut normal = normal_image(crate::startup::coverage::sink_fixture::IMAGE_LEN);
    crate::startup::bank::fixture(&mut normal);
    normal[8..16].fill(b' ');
    crate::image::matrix::install_test_contract(&mut normal, family);
    crate::startup::coverage::sink_fixture::install(&mut normal);
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

fn update_with_bound_startup(gated: bool, marker: u8, family: u8, entry: bool) -> Update {
    let original = update(gated, marker, family, entry);
    let mut normal = original.normal().image.clone();
    normal[0x680..0x694].copy_from_slice(&[
        0x79, 0, 0, 0x9f, 0x5e, 0x41, 0x10, 0, 0x79, 0x20, 0xfe, 0x24, 0x47, 6, 0xf8, 1, 0x5e,
        0x41, 0x06, 0xa0,
    ]);
    normal[0x6a0..0x6a6].copy_from_slice(&[0x5e, 0x40, 0x0a, 0x1a, 0x54, 0x70]);
    fix_sum(&mut normal);
    let mut wire = original.normal().repack(&normal).unwrap();
    let mut key = [0; 20];
    key[19] = 5;
    SigningKey::from_bytes(key)
        .unwrap()
        .sign_normal(&mut wire)
        .unwrap();
    Update::load(original.kernel_transfer(), &wire).unwrap()
}

#[test]
fn ordinary_preparation_keeps_the_receivers_bank_checks() {
    use crate::startup::{bank, checks};
    let installed = update(false, 1, 0x12, true);
    let receiver = Receiver::from_installed(&installed).unwrap();
    let baseline = receiver.prepare(installed.clone()).unwrap();
    let startup_plan = baseline.settings().startup_plan().unwrap();
    assert_eq!(
        startup_plan.policy(),
        crate::startup::checks::Policy::CompatibleBanks
    );
    assert_eq!(
        startup_plan.target_checks(),
        checks::Checks::discover(&installed.normal().image, Some(&installed.kernel().image))
    );
    assert!(baseline.settings().startup_selection().is_none());
    assert!(baseline.settings().startup_setting().is_none());
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
    assert!(normal_only.settings().startup_selection().is_none());
    assert!(normal_only.settings().startup_setting().is_none());

    let mut normal = installed.normal().image.clone();
    for at in [
        0x180a,
        0x190a,
        crate::startup::coverage::sink_fixture::MAGIC_OFFSET,
    ] {
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

/// Re-sign `installed` with its bank header magic replaced: FEDC4321 is the
/// BDR-212U-style magic, FEDC4322 the BDR-213U-style magic.
fn with_bank_magic(installed: &Update, magic: u32) -> Update {
    let mut normal = installed.normal().image.clone();
    for at in [
        0x180a,
        0x190a,
        crate::startup::coverage::sink_fixture::MAGIC_OFFSET,
    ] {
        normal[at..at + 4].copy_from_slice(&magic.to_be_bytes());
    }
    fix_sum(&mut normal);
    let mut bytes = installed.normal().repack(&normal).unwrap();
    let mut key = [0; 20];
    key[19] = 5;
    SigningKey::from_bytes(key)
        .unwrap()
        .sign_normal(&mut bytes)
        .unwrap();
    Update::load(installed.kernel_transfer(), &bytes).unwrap()
}

#[test]
fn bdr_212u_and_213u_banks_refuse_in_both_directions_strict_and_recovery() {
    use crate::startup::{bank, checks};
    let base = update(false, 1, 0x12, true);
    let u212 = with_bank_magic(&base, 0xfedc_4321);
    let u213 = with_bank_magic(&base, 0xfedc_4322);
    let banks = |pair: &Update| {
        bank::analyze_pair(&pair.normal().image, Some(&pair.kernel().image)).unwrap()
    };
    assert_ne!(banks(&u212), banks(&u213));
    for (installed, target) in [(&u212, &u213), (&u213, &u212)] {
        let receiver = Receiver::from_installed(installed).unwrap();
        let conversion = |error: PreparationError| {
            assert_eq!(
                error,
                PreparationError::Startup(checks::Error::Banks(bank::Error::ConversionRequired {
                    installed: banks(installed),
                    target: banks(target),
                }))
            )
        };
        // Strict: the registered geometry filter already differs, so the
        // family gate refuses before the bank gate is reached.
        for error in [
            receiver.prepare(target.clone()).unwrap_err(),
            receiver
                .prepare_normal(target.normal_transfer())
                .unwrap_err(),
        ] {
            assert!(
                matches!(
                    error,
                    PreparationError::Compatibility(Error::FamilyMismatch { .. })
                ),
                "{error:?}"
            );
        }
        // The bank gate itself refuses under both startup policies.
        for policy in [
            checks::Policy::CompatibleBanks,
            checks::Policy::ExplicitCrossflash,
        ] {
            conversion(
                receiver
                    .prepare_startup_with_policy(
                        &target.normal().image,
                        Some(&target.kernel().image),
                        policy,
                    )
                    .unwrap_err(),
            );
        }
        // Recovery family override waives the family gate, never the banks.
        conversion(
            receiver
                .prepare_without_family_check(target.clone())
                .unwrap_err(),
        );
        conversion(
            receiver
                .prepare_normal_without_family_check(target.normal_transfer())
                .unwrap_err(),
        );
    }
}

#[test]
fn explicit_crossflash_refuses_unknown_banks() {
    use crate::startup::{bank, checks};
    let installed = update(false, 1, 0x12, true);
    let receiver = Receiver::from_installed(&installed).unwrap();
    let mut normal = installed.normal().image.clone();
    normal[0x1800..0x1a00].fill(0);
    normal[0x2200..0x229c].fill(0);
    fix_sum(&mut normal);
    let mut bytes = installed.normal().repack(&normal).unwrap();
    let mut key = [0; 20];
    key[19] = 5;
    SigningKey::from_bytes(key)
        .unwrap()
        .sign_normal(&mut bytes)
        .unwrap();
    let target = Update::load(installed.kernel_transfer(), &bytes).unwrap();
    // Persistent geometry is a registered family input, so strict preparation
    // refuses the unknown layout at the family gate before startup planning.
    assert!(matches!(
        receiver.prepare(target.clone()),
        Err(PreparationError::Compatibility(Error::UnknownTargetFamily))
    ));
    assert!(matches!(
        receiver.prepare_startup(&normal, Some(&installed.kernel().image)),
        Err(PreparationError::Startup(checks::Error::Banks(
            bank::Error::UnknownTarget
        )))
    ));
    assert!(matches!(
        receiver.prepare_without_family_check(target),
        Err(PreparationError::Startup(checks::Error::Banks(
            bank::Error::UnknownTarget
        )))
    ));
    assert!(matches!(
        receiver.prepare_normal_without_family_check(&bytes),
        Err(PreparationError::Startup(checks::Error::Banks(
            bank::Error::UnknownTarget
        )))
    ));
}

#[test]
fn explicit_crossflash_refuses_changed_bank_magic_even_with_a_target_word() {
    let installed = update(false, 1, 0x12, true);
    let receiver = Receiver::from_installed(&installed).unwrap();
    let mut normal = installed.normal().image.clone();
    for at in [
        0x180a,
        0x190a,
        crate::startup::coverage::sink_fixture::MAGIC_OFFSET,
    ] {
        normal[at..at + 4].copy_from_slice(&0xfedc4322u32.to_be_bytes());
    }
    normal[0x600..0x614].copy_from_slice(&[
        0x79, 0, 0, 0x9f, 0x5e, 0x41, 1, 0, 0x79, 0x20, 0xfe, 0x24, 0x47, 6, 0xf8, 1, 0x5e, 0x41,
        6, 0x80,
    ]);
    normal[0x680..0x686].copy_from_slice(&[0x5e, 0x40, 0x0a, 0x1a, 0x54, 0x70]);
    fix_sum(&mut normal);
    let mut bytes = installed.normal().repack(&normal).unwrap();
    let mut key = [0; 20];
    key[19] = 5;
    SigningKey::from_bytes(key)
        .unwrap()
        .sign_normal(&mut bytes)
        .unwrap();
    let target = Update::load(installed.kernel_transfer(), &bytes).unwrap();
    use crate::startup::{bank, checks};
    let explicit = checks::Policy::ExplicitCrossflash;
    let kernel = Some(installed.kernel().image.as_slice());
    // The registered correction planner cannot resolve this synthetic target's
    // identity and refuses first; the startup layer independently still
    // refuses the changed bank contract under the explicit policy.
    for error in [
        receiver.prepare_without_family_check(target).unwrap_err(),
        receiver
            .prepare_normal_without_family_check(&bytes)
            .unwrap_err(),
    ] {
        assert!(
            matches!(
                error,
                PreparationError::PhaseCorrection(_)
                    | PreparationError::Startup(checks::Error::Banks(
                        bank::Error::ConversionRequired { .. }
                    ))
            ),
            "{error:?}"
        );
    }
    assert!(matches!(
        receiver.prepare_startup_with_policy(&normal, kernel, explicit),
        Err(PreparationError::Startup(checks::Error::Banks(
            bank::Error::ConversionRequired { .. }
        )))
    ));
    // With bank compatibility established, bypass still cannot select between
    // conflicting startup words. Do not couple this check to error priority.
    for at in [
        0x180a,
        0x190a,
        crate::startup::coverage::sink_fixture::MAGIC_OFFSET,
    ] {
        normal[at..at + 4].copy_from_slice(&0xfedc4321u32.to_be_bytes());
    }
    let duplicate = normal[0x600..0x614].to_vec();
    normal[0x620..0x634].copy_from_slice(&duplicate);
    fix_sum(&mut normal);
    let mut ambiguous = installed.normal().repack(&normal).unwrap();
    SigningKey::from_bytes(key)
        .unwrap()
        .sign_normal(&mut ambiguous)
        .unwrap();
    let target = Update::load(installed.kernel_transfer(), &ambiguous).unwrap();
    for error in [
        receiver.prepare_without_family_check(target).unwrap_err(),
        receiver
            .prepare_normal_without_family_check(&ambiguous)
            .unwrap_err(),
    ] {
        assert!(
            matches!(
                error,
                PreparationError::PhaseCorrection(_)
                    | PreparationError::Startup(checks::Error::AmbiguousWord)
            ),
            "{error:?}"
        );
    }
    assert!(matches!(
        receiver.prepare_startup_with_policy(&normal, kernel, explicit),
        Err(PreparationError::Startup(checks::Error::AmbiguousWord))
    ));
}

#[test]
fn prepares_patch_and_pristine_restore_before_any_io() {
    // Final components carry a bound startup gate; this test exercises the
    // intermediate marker patch and restoration after their admission.
    let installed = update_with_bound_startup(true, 1, 0x12, true);
    let receiver = Receiver::from_installed(&installed).unwrap();
    for marker in [0, 0xff] {
        let target = update_with_bound_startup(false, marker, 0x12, true);
        let pristine = target.kernel().image.clone();
        let normal = target.normal().image.clone();
        let plan = receiver.prepare(target).unwrap();
        assert_eq!(
            plan.first_kernel_image(),
            downgrade_patch(&pristine).unwrap().0
        );
        assert_eq!(plan.final_kernel_image(), pristine);
        let first = Envelope::load(plan.kernel_transfer()).unwrap();
        let restored = Envelope::load(plan.final_stage_kernel_transfer().unwrap()).unwrap();
        // A bound read-only prerequisite may rebuild the signed envelope.
        let transferred = Envelope::load_with_kernel(plan.normal_transfer(), &restored).unwrap();
        assert_eq!(transferred.image, normal);
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
    let installed = update_with_bound_startup(true, 1, 0x12, true);
    let entry_only = Receiver::from_firmware(installed.normal()).unwrap();
    assert_eq!(
        entry_only.prepare(installed.clone()).unwrap_err(),
        PreparationError::UnknownInstalledKernel
    );
    let receiver = Receiver::from_installed(&installed).unwrap();
    assert_eq!(
        receiver
            .prepare(update_with_bound_startup(true, 0, 0x12, true))
            .unwrap_err(),
        PreparationError::UnsupportedFinalStage
    );
    assert_eq!(
        receiver
            .prepare(update_with_bound_startup(false, 0, 0x12, false))
            .unwrap_err(),
        PreparationError::FinalStageEntry(Error::Unsupported)
    );
    assert!(matches!(
        entry_only.prepare(update_with_bound_startup(false, 0, 0x13, true)),
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
    let receiver = Receiver::from_firmware_with_kernel(&captured, installed.kernel()).unwrap();
    assert_eq!(receiver.family(), installed.family());
    assert_eq!(
        receiver.installed_kernel().unwrap().image,
        installed.kernel().image
    );
    assert!(receiver.prepare(update(false, 0, 0x12, true)).is_ok());
    assert!(Update::load(installed.kernel_transfer(), &bytes).is_err());
    assert_eq!(
        Receiver::from_firmware_with_kernel(&captured, &captured).unwrap_err(),
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
        Receiver::from_firmware_with_kernel(&other_kernel_tag, installed.kernel()).unwrap_err(),
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
        Receiver::from_firmware_with_kernel(&blank_normal, &blank_kernel).unwrap_err(),
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
        Receiver::from_firmware_with_kernel(&mismatched, installed.kernel()).unwrap_err(),
        Error::InstalledPairMismatch
    );
}

#[test]
fn explicit_family_override_does_not_waive_native_owner_receiver_or_restore_checks() {
    let installed = update_with_bound_startup(true, 1, 0x12, true);
    let receiver = Receiver::from_installed(&installed).unwrap();
    // The family byte is a native loading-input fact. R1A makes this
    // uncorrectable owner mismatch mandatory even with a family override.
    assert_eq!(
        receiver
            .prepare_without_family_check(update_with_bound_startup(false, 0, 0x13, true))
            .unwrap_err(),
        PreparationError::PhaseCorrection(crate::compatibility::Error::Incompatible)
    );
    assert!(receiver
        .prepare_without_family_check(update_with_bound_startup(false, 0, 0x12, true))
        .is_ok());
    assert_eq!(
        receiver
            .prepare_without_family_check(update_with_bound_startup(true, 0, 0x12, true))
            .unwrap_err(),
        PreparationError::UnsupportedFinalStage
    );
    let entry_only = Receiver::from_firmware(installed.normal()).unwrap();
    assert_eq!(
        entry_only
            .prepare_without_family_check(update_with_bound_startup(false, 0, 0x12, true))
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
        Receiver::from_firmware_with_kernel(installed.normal(), &unknown_marker_handler).unwrap();
    assert!(receiver.prepare_normal(target.normal_transfer()).is_ok());
    assert_eq!(
        receiver.prepare(target).unwrap_err(),
        PreparationError::UnknownInstalledKernel
    );
}

#[test]
fn normal_only_force_preserves_native_owner_authentication_and_missing_evidence_checks() {
    let installed = update_with_bound_startup(false, 0, 0x12, true);
    let receiver = Receiver::from_installed(&installed).unwrap();
    let other = update_with_bound_startup(false, 0, 0x13, true);
    assert!(matches!(
        receiver.prepare_normal(other.normal_transfer()),
        Err(PreparationError::Compatibility(
            Error::FamilyMismatch { .. }
        ))
    ));
    // Broad family override cannot waive the loading-input owner's failure.
    assert_eq!(
        receiver
            .prepare_normal_without_family_check(other.normal_transfer())
            .unwrap_err(),
        PreparationError::PhaseCorrection(crate::compatibility::Error::Incompatible)
    );
    assert!(receiver
        .prepare_normal_without_family_check(installed.normal_transfer())
        .is_ok());
    let mut invalid = other.normal_transfer().to_vec();
    invalid[crate::envelope::builder::NORMAL_SIGNATURE_RANGE].fill(0);
    assert_eq!(
        receiver
            .prepare_normal_without_family_check(&invalid)
            .unwrap_err(),
        PreparationError::Target(UpdateError::Authentication)
    );
    let entry_only = Receiver::from_firmware(installed.normal()).unwrap();
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
fn held_ud04_211m_family_override_refuses_differing_input_initialization() {
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
    for (installed, target) in [(&ud04, &m211), (&m211, &ud04)] {
        let receiver = Receiver::from_installed(installed).unwrap();
        assert!(matches!(
            receiver.prepare(target.clone()),
            Err(PreparationError::Compatibility(
                Error::FamilyMismatch { .. }
            ))
        ));
        // The override waives only the family gate: the hardware
        // startup-inputs-initialization filter differs and has no correction,
        // so no route (and no settings requirement) is prepared.
        assert!(matches!(
            receiver.prepare_without_family_check(target.clone()),
            Err(PreparationError::PhaseCorrection(
                crate::compatibility::Error::Incompatible
            ))
        ));
    }
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
        let receiver = Receiver::from_firmware_with_kernel(&normal, source.kernel()).unwrap();
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
    let direct = update_with_bound_startup(false, 1, 0x12, true);
    let swapped_image = correct_normal(&direct.normal().image, Assignment::Swapped).unwrap();
    let mut bytes = direct.normal().repack(&swapped_image).unwrap();
    SigningKey::random()
        .unwrap()
        .sign_normal(&mut bytes)
        .unwrap();
    let kernel_bytes = direct.kernel().repack(&direct.kernel().image).unwrap();
    let swapped = Update::load(&kernel_bytes, &bytes).unwrap();
    // Matching families exclude the correctable phase assignment.
    assert_eq!(direct.family(), swapped.family());
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
            full.settings().correction_id(),
            Some("pioneer.native-correction.v1")
        );
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
            normal.settings().correction_id(),
            Some("pioneer.native-correction.v1")
        );
    }
    let receiver =
        Receiver::from_installed(&update_with_bound_startup(false, 1, 0x13, true)).unwrap();
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
fn family_override_does_not_admit_unproved_startup_across_layouts() {
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
    // Both the uncorrectable layout and unproved startup remain blocked.
    // R1A retains the layout owner's Incompatible refusal ahead of startup's
    // UnresolvedIdentity. The independent phase rewrite preserves layout bytes.
    for (installed, target) in [(&installed, &target), (&target, &installed)] {
        fn context(pair: &Update) -> crate::filters::Context<'_> {
            crate::filters::Context::new(crate::compatibility::Firmware {
                hardware: &pair.normal().info().hardware_version,
                normal: &pair.normal().image,
                kernel: Some(&pair.kernel().image),
            })
        }
        let (a, b) = (context(installed), context(target));
        let plan = crate::filters::runner::evaluate(
            &a,
            &b,
            crate::filters::runner::Policy::FamilyOverride,
        )
        .unwrap();
        for (id, error) in [
            (
                "persistent-parameter-layout",
                crate::compatibility::Error::Incompatible,
            ),
            (
                "startup-prerequisite",
                crate::compatibility::Error::UnresolvedIdentity,
            ),
        ] {
            let decision = plan
                .decisions()
                .iter()
                .find(|decision| decision.id == id)
                .unwrap();
            assert_eq!(decision.blocked(), Some(error));
            assert!(!decision.waived);
            assert!(decision.operation().is_none());
        }
        let receiver = Receiver::from_installed(installed).unwrap();
        for result in [
            receiver
                .prepare_without_family_check(target.clone())
                .map(|_| ()),
            receiver
                .prepare_normal_without_family_check(target.normal_transfer())
                .map(|_| ()),
        ] {
            assert!(matches!(
                result,
                Err(PreparationError::PhaseCorrection(
                    crate::compatibility::Error::Incompatible
                ))
            ));
        }
        let layout::Observation::Known(required) = phase::discover(&installed.normal().image)
        else {
            panic!("installed phase");
        };
        let changed = phase::correct_normal(&target.normal().image, required.assignment).unwrap();
        let layout::Observation::Known(before_layout) =
            layout::normal_reader(&target.normal().image)
        else {
            panic!("target reader");
        };
        let layout::Observation::Known(after_layout) = layout::normal_reader(&changed) else {
            panic!("corrected reader");
        };
        assert_eq!(before_layout, after_layout);
        assert_ne!(changed, installed.normal().image);
    }
}
