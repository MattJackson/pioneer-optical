//! Actual signed-file preparation through reviewed recipes and native replanning.
use super::*;
use crate::{
    compatibility::{self, Firmware, Verification},
    envelope::{
        builder::{encode_encrypted_pair, BuildInputs, KernelBuild, NormalSignature},
        signature::SigningKey,
        synthetic_roundtrip_tests::{front_kernel, normal_image},
        Envelope,
    },
    filters::{self, runner::Policy},
    image::phase,
};
use alloc::{format, vec::Vec};

fn checksum(image: &mut [u8]) {
    image[16..20].fill(0);
    let sum = image.chunks_exact(4).fold(0u32, |sum, word| {
        sum.wrapping_add(u32::from_be_bytes(word.try_into().unwrap()))
    });
    image[16..20].copy_from_slice(&sum.wrapping_neg().to_be_bytes());
}
fn components(normal: Option<Vec<u8>>) -> (Envelope, Envelope) {
    let kernel = front_kernel();
    let normal = normal.unwrap_or_else(|| {
        let mut image = normal_image(0x2000);
        crate::startup::bank::fixture(&mut image);
        image[8..16].fill(b' ');
        crate::image::matrix::install_test_contract(&mut image, 0x12);
        image[0x400..0x408].copy_from_slice(&[0xf6, 0x12, 0x6a, 0x86, 0xe4, 0x36, 0, 0]);
        checksum(&mut image);
        image
    });
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
    let kernel = Envelope::load(&pair.kernel).unwrap();
    let normal = Envelope::load_with_kernel(&pair.normal, &kernel).unwrap();
    (normal, kernel)
}
fn firmware<'a>(normal: &'a Envelope, kernel: &'a Envelope) -> Firmware<'a> {
    Firmware {
        hardware: &normal.info().hardware_version,
        normal: &normal.image,
        kernel: Some(&kernel.image),
    }
}
fn document(source: &[u8], target: &Envelope, output: &[u8], stock: bool) -> alloc::string::String {
    let replacements:Vec<_>=target.image.iter().zip(output).enumerate().filter(|(at,(a,b))|a!=b&&!(16..20).contains(at)).map(|(at,(before,after))|serde_json::json!({"offset":at,"expected_hex":format!("{before:02x}"),"replacement_hex":format!("{after:02x}")})).collect();
    serde_json::json!({"schema_version":1,"id":"test.reviewed-owner","hardware_scheme":crate::image::FAMILY_SCHEME,"hardware_family":crate::image::legacy_family(source).unwrap().to_string(),"source_normal_sha256":[mechanism::digest(source)],"mode":if stock{"stock_return"}else{"adapt"},"resolves_issue":"test.owner","target_normal_sha256":mechanism::digest(&target.image),"target_model":target.info().model,"input_length":target.image.len(),"required_parameters":[],"replacements":replacements,"checksum_offset":16,"output_sha256":mechanism::digest(output)}).to_string()
}

#[test]
fn reviewed_image_is_replanned_and_a_new_native_mismatch_refuses() {
    let (normal, kernel) = components(None);
    let native =
        compatibility::plan(firmware(&normal, &kernel), firmware(&normal, &kernel)).unwrap();
    let source = mechanism::Contract::discover(&normal.image);
    let mut allowed = normal.image.clone();
    allowed[0x600] = 1;
    checksum(&mut allowed);
    let documents = [document(&normal.image, &normal, &allowed, false)];
    let prepared = prepare(
        Some(&native),
        None,
        &source,
        &normal,
        &kernel,
        None,
        None,
        Some(&documents),
    )
    .unwrap()
    .unwrap();
    assert_eq!(prepared.image, allowed);
    assert_eq!(
        prepared.verification,
        Verification::ReviewedMechanismAndRegisteredFilters
    );
    assert!(prepared.verified_by_filters());
    // A reviewed test recipe cannot smuggle an unrelated native host change
    // through the mechanism-specific certification path.
    let mut forbidden = normal.image.clone();
    forbidden[0x711] = 0x80;
    checksum(&mut forbidden);
    let documents = [document(&normal.image, &normal, &forbidden, false)];
    assert!(matches!(
        prepare(
            Some(&native),
            None,
            &source,
            &normal,
            &kernel,
            None,
            None,
            Some(&documents)
        ),
        Err(PreparationError::Mechanism(mechanism::Error::Guard))
    ));
    let facts = filters::inspect(firmware(&normal, &kernel));
    assert!(facts
        .iter()
        .all(|f| !matches!(f.finding, filters::Finding::Conflicting(_))));
}

#[test]
fn post_mechanism_native_phase_operation_is_applied_and_clears_stock_authentication() {
    let (installed, kernel) = components(None);
    let swapped = phase::correct_normal(&installed.image, phase::Assignment::Swapped).unwrap();
    let (target, target_kernel) = components(Some(swapped));
    let native = compatibility::plan_with_policy(
        firmware(&installed, &kernel),
        firmware(&target, &target_kernel),
        Policy::Strict,
    )
    .unwrap();
    let mut source = mechanism::Contract::discover(&installed.image);
    // The legacy admission cache is not the generic phase owner. Remove its
    // optional phase hint so only the retained native snapshot can authorize
    // and perform this post-recipe correction.
    source.phase_evidence = None;
    let documents = [document(&installed.image, &target, &target.image, true)];
    let prepared = prepare(
        Some(&native),
        None,
        &source,
        &target,
        &target_kernel,
        None,
        None,
        Some(&documents),
    )
    .unwrap()
    .unwrap();
    assert_eq!(prepared.image, installed.image);
    assert!(!prepared.stock_return());
    assert_eq!(
        prepared.verification,
        Verification::ReviewedMechanismAndRegisteredFilters
    );
    assert!(prepared.verified_by_filters());
    assert!(prepared
        .corrections
        .contains(&compatibility::Correction::Phase {
            from: phase::Assignment::Swapped,
            to: phase::Assignment::Direct,
        }));
}

#[test]
fn raw_reviewed_effect_does_not_grant_missing_global_native_admission() {
    let (normal, kernel) = components(None);
    let source = mechanism::Contract::discover(&normal.image);
    let mut output = normal.image.clone();
    output[0x600] = 1;
    checksum(&mut output);
    let documents = [document(&normal.image, &normal, &output, false)];
    let raw =
        mechanism::prepare_documents(&documents, &source, &normal.image, &normal.info().model)
            .unwrap()
            .unwrap();
    assert_eq!(raw.verification, Verification::ReviewedMechanism);
    assert!(!raw.verified_by_filters());
    assert!(matches!(
        prepare(
            None,
            None,
            &source,
            &normal,
            &kernel,
            None,
            None,
            Some(&documents)
        ),
        Err(PreparationError::Firmware(
            compatibility::Error::UnresolvedIdentity
        ))
    ));
}
