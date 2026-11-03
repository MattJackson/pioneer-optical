use super::*;
const FIXTURE: &str = include_str!("fixture.json");

fn source() -> crate::settings::update::Contract {
    let mut contract = crate::settings::update::Contract::discover(b"fixture-ud02");
    contract.hardware_family = Some("1111111111111111".into());
    contract
}
fn target() -> Vec<u8> {
    let mut bytes = vec![0; 32];
    bytes[..4].copy_from_slice(&[1, 2, 3, 4]);
    bytes[28..].copy_from_slice(&0x01020304u32.wrapping_neg().to_be_bytes());
    bytes
}
fn value() -> serde_json::Value {
    serde_json::from_str(FIXTURE).unwrap()
}
fn registry(v: &serde_json::Value) -> Result<Contracts, Error> {
    Contracts::parse(&[&v.to_string()])
}

#[test]
fn production_profiles_do_not_change_unrelated_images_or_routes() {
    assert!(has_corrections());
    assert!(prepare(&source(), &target(), "TEST-UD03")
        .unwrap()
        .is_none());
}

#[test]
fn production_routes_are_valid_unique_and_bound_to_exact_firmware_pairs() {
    let registry = Contracts::new(contracts::definitions()).unwrap();
    assert_eq!(registry.0.len(), 11);
    assert_eq!(
        registry
            .0
            .iter()
            .filter(|p| p.required_parameters
                == [Requirement {
                    parameter: 0x28f,
                    value: 1
                }])
            .count(),
        4
    );
}

#[test]
fn held_ud02_ud04_images_reproduce_the_tested_output_and_pristine_return() {
    let Ok(original) = std::env::var("PIONEER_UD02_NORMAL") else {
        return;
    };
    let ud02 = std::fs::read(original).unwrap();
    let ud04 = std::fs::read(std::env::var("PIONEER_UD04_NORMAL").unwrap()).unwrap();
    let from = crate::settings::update::Contract::discover(&ud02);
    assert_eq!(
        digest(&ud02),
        "84fab289c44ce2de98e96272e607869de4501b45f8f4badc43e492920ce07750"
    );
    assert_eq!(
        digest(&ud04),
        "87e8152f1de1d3be53eb4ad9144c1bb0c45a9be6f78713a0b7487a637f989bf1"
    );
    let adapted = prepare(&from, &ud04, "BDR-UD04").unwrap().unwrap();
    assert_eq!(
        digest(&adapted.image),
        "ca09032288c62b8b26bb983431af11b52aaeec8da9bd0e80afcccdf3b07f0815"
    );
    from.check_resolving(
        &crate::settings::update::Contract::discover(&adapted.image),
        Some(&adapted.resolves_issue),
    )
    .unwrap();
    let back = crate::settings::update::Contract::discover(&adapted.image);
    let returned = prepare(&back, &ud02, "BDR-UD02D").unwrap().unwrap();
    assert!(returned.stock_return());
    assert_eq!(returned.image, ud02);
    // Native UHD firmware is not a certified source for the stock-return route.
    let native = crate::settings::update::Contract::discover(&ud04);
    assert!(prepare(&native, &ud02, "BDR-UD02D").unwrap().is_some());
    let mut changed = ud04.clone();
    changed[0x1000] ^= 1;
    assert!(prepare(&from, &changed, "BDR-UD04").unwrap().is_none());
    assert!(prepare(&from, &ud04, "BDR-UD03").unwrap().is_none());
}

fn repair_normal_sum(bytes: &mut [u8]) {
    bytes[16..20].fill(0);
    let sum = bytes.chunks_exact(4).fold(0u32, |sum, word| {
        sum.wrapping_add(u32::from_be_bytes(word.try_into().unwrap()))
    });
    bytes[16..20].copy_from_slice(&sum.wrapping_neg().to_be_bytes());
}

fn native_normal(assignment: crate::image::phase::Assignment) -> Vec<u8> {
    let mut bytes = crate::image::phase::tests::fixture(false);
    bytes[..16].copy_from_slice(b"PIONEER TEST    ");
    let size = bytes.len() as u32;
    bytes[20..24].copy_from_slice(&size.to_be_bytes());
    repair_normal_sum(&mut bytes);
    crate::image::phase::correct_normal(&bytes, assignment).unwrap()
}

fn native_contract(bytes: &[u8]) -> Contract {
    let mut result = Contract::discover(bytes);
    result.hardware_family = Some("1111111111111111".into());
    result.phase_evidence = requirements::phase_evidence(bytes, &result.normal_sha256);
    result
}

fn native_recipe() -> (serde_json::Value, Vec<u8>, Vec<u8>, Vec<u8>) {
    use crate::image::phase::Assignment;
    let source = native_normal(Assignment::Direct);
    let mut target = native_normal(Assignment::Swapped);
    target[476] = 0x55;
    repair_normal_sum(&mut target);
    let mut reviewed_output = target.clone();
    reviewed_output[480..482].copy_from_slice(&[0xa1, 0xb2]);
    repair_normal_sum(&mut reviewed_output);
    let mut definition = value();
    definition["source_normal_sha256"] = serde_json::json!([digest(&source)]);
    definition["target_normal_sha256"] = digest(&target).into();
    definition["input_length"] = target.len().into();
    definition["checksum_offset"] = 16.into();
    definition["replacements"] = serde_json::json!([{
        "offset": 480, "expected_hex": "ffff", "replacement_hex": "a1b2"
    }]);
    definition["output_sha256"] = digest(&reviewed_output).into();
    (definition, source, target, reviewed_output)
}

#[test]
fn exact_mechanism_guards_compose_with_every_proven_phase_variant() {
    use crate::image::phase::{self, Assignment};
    let (definition, source, target, reviewed_output) = native_recipe();
    let registry = registry(&definition).unwrap();
    for required in [Assignment::Direct, Assignment::Swapped] {
        let installed = phase::correct_normal(&source, required).unwrap();
        let expected = phase::correct_normal(&reviewed_output, required).unwrap();
        for supplied in [Assignment::Direct, Assignment::Swapped] {
            let target = phase::correct_normal(&target, supplied).unwrap();
            let selected = registry
                .prepare(&native_contract(&installed), &target, "TEST-UD03")
                .unwrap()
                .unwrap();
            assert_eq!(selected.image, expected);
            assert_eq!(
                selected.requirements,
                [Requirement {
                    parameter: 0x28f,
                    value: 1
                }]
            );
            assert!(selected.requires_normal_runtime);
            assert!(!selected.stock_return());
            assert_eq!(
                selected.corrections,
                if supplied == required {
                    Vec::new()
                } else {
                    vec![crate::compatibility::Correction::Phase {
                        from: supplied,
                        to: required,
                    }]
                }
            );
        }
    }
}

#[test]
fn phase_equivalence_does_not_waive_other_bytes_checksums_or_stale_evidence() {
    use crate::image::phase::{self, Assignment};
    let (definition, source, target, _) = native_recipe();
    let registry = registry(&definition).unwrap();
    let installed = phase::correct_normal(&source, Assignment::Swapped).unwrap();
    let mut altered = installed.clone();
    altered[484] ^= 1;
    repair_normal_sum(&mut altered);
    assert!(registry
        .prepare(&native_contract(&altered), &target, "TEST-UD03")
        .unwrap()
        .is_none());
    let mut altered_target = target.clone();
    altered_target[484] ^= 1;
    repair_normal_sum(&mut altered_target);
    assert!(registry
        .prepare(&native_contract(&installed), &altered_target, "TEST-UD03")
        .unwrap()
        .is_none());
    let mut invalid_checksum = phase::correct_normal(&target, Assignment::Direct).unwrap();
    invalid_checksum[16] ^= 1;
    assert!(registry
        .prepare(&native_contract(&installed), &invalid_checksum, "TEST-UD03")
        .unwrap()
        .is_none());
    let mut stale = native_contract(&installed);
    stale.normal_sha256 = digest(b"unrelated-image");
    assert!(registry
        .prepare(&stale, &target, "TEST-UD03")
        .unwrap()
        .is_none());
}

#[test]
fn phase_equivalent_registered_targets_are_ambiguous_not_order_dependent() {
    use crate::image::phase::{self, Assignment};
    let (first, source, target, _) = native_recipe();
    let mut second = first.clone();
    second["id"] = "other-reviewed-target".into();
    let other_target = phase::correct_normal(&target, Assignment::Direct).unwrap();
    let mut other_output = other_target.clone();
    other_output[480..482].copy_from_slice(&[0xa1, 0xb2]);
    repair_normal_sum(&mut other_output);
    second["target_normal_sha256"] = digest(&other_target).into();
    second["output_sha256"] = digest(&other_output).into();
    let registry = Contracts::parse(&[&first.to_string(), &second.to_string()]).unwrap();
    assert!(matches!(
        registry.prepare(&native_contract(&source), &target, "TEST-UD03"),
        Err(Error::Registry)
    ));
}

#[test]
fn stock_return_preserves_authentication_only_when_the_final_image_is_pristine() {
    use crate::image::phase::{self, Assignment};
    let (mut definition, source, target, _) = native_recipe();
    definition["mode"] = "stock_return".into();
    definition["replacements"] = serde_json::json!([]);
    definition["output_sha256"] = definition["target_normal_sha256"].clone();
    let registry = registry(&definition).unwrap();
    for required in [Assignment::Direct, Assignment::Swapped] {
        let installed = phase::correct_normal(&source, required).unwrap();
        let selected = registry
            .prepare(&native_contract(&installed), &target, "TEST-UD03")
            .unwrap()
            .unwrap();
        let expected = phase::correct_normal(&target, required).unwrap();
        assert_eq!(selected.image, expected);
        assert_eq!(selected.stock_return(), expected == target);
    }
}

#[test]
fn held_reviewed_mechanism_is_closed_under_phase_and_preserves_native_reverse() {
    use crate::image::phase::{self, Assignment};
    let Ok(original) = std::env::var("PIONEER_UD02_NORMAL") else {
        return;
    };
    let ud02 = std::fs::read(original).unwrap();
    let ud04 = std::fs::read(std::env::var("PIONEER_UD04_NORMAL").unwrap()).unwrap();
    let canonical = prepare(&Contract::discover(&ud02), &ud04, "BDR-UD04")
        .unwrap()
        .unwrap();
    for installed_phase in [Assignment::Direct, Assignment::Swapped] {
        let installed = phase::correct_normal(&ud02, installed_phase).unwrap();
        let expected_converted = phase::correct_normal(&canonical.image, installed_phase).unwrap();
        for target_phase in [Assignment::Direct, Assignment::Swapped] {
            let target = phase::correct_normal(&ud04, target_phase).unwrap();
            let converted = prepare(&Contract::discover(&installed), &target, "BDR-UD04")
                .unwrap()
                .unwrap();
            assert_eq!(converted.image, expected_converted);
            assert_eq!(
                converted.requirements,
                [Requirement {
                    parameter: 0x28f,
                    value: 1
                }]
            );
            let requested_stock = phase::correct_normal(&ud02, target_phase).unwrap();
            let returned = prepare(
                &Contract::discover(&converted.image),
                &requested_stock,
                "BDR-UD02D",
            )
            .unwrap()
            .unwrap();
            assert_eq!(returned.image, installed);
            assert_eq!(returned.stock_return(), returned.image == requested_stock);
            let native_reverse =
                prepare(&Contract::discover(&target), &requested_stock, "BDR-UD02D")
                    .unwrap()
                    .unwrap();
            assert!(
                matches!((phase::discover(&native_reverse.image), phase::discover(&target)), (crate::image::layout::Observation::Known(a),crate::image::layout::Observation::Known(b)) if a==b)
            );
            assert!(native_reverse.requirements.is_empty());
        }
    }
}

#[test]
fn one_compiled_test_json_matches_exactly_one_direction_and_image() {
    let registry = Contracts::parse(&[FIXTURE]).unwrap();
    let from = source();
    let before = target();
    let adapted = registry
        .prepare(&from, &before, "TEST-UD03")
        .unwrap()
        .unwrap();
    assert_eq!(&adapted.image[..4], &[5, 6, 3, 4]);
    assert_eq!(before, target());
    assert_eq!(
        digest(&adapted.image),
        value()["output_sha256"].as_str().unwrap()
    );
    assert_eq!(
        adapted.image.chunks_exact(4).fold(0u32, |s, w| s
            .wrapping_add(u32::from_be_bytes(w.try_into().unwrap()))),
        0
    );
    let mut changed_target = before.clone();
    changed_target[4] = 1;
    assert!(registry
        .prepare(&from, &changed_target, "TEST-UD03")
        .unwrap()
        .is_none());
    let mut changed_source = from.clone();
    changed_source.normal_sha256 = digest(b"another-source");
    assert!(registry
        .prepare(&changed_source, &before, "TEST-UD03")
        .unwrap()
        .is_none());
    changed_source = from.clone();
    changed_source.hardware_family = Some("2222222222222222".into());
    assert!(registry
        .prepare(&changed_source, &before, "TEST-UD03")
        .unwrap()
        .is_none());
    assert!(registry
        .prepare(&from, &adapted.image, "TEST-UD03")
        .unwrap()
        .is_none());
}

#[test]
fn certified_pair_requires_no_factory_sku_record() {
    let registry = Contracts::parse(&[FIXTURE]).unwrap();
    assert!(registry
        .prepare(&source(), &target(), "TEST-UD03")
        .unwrap()
        .is_some());
}

#[test]
fn stock_return_is_pristine_for_the_certified_source_pair() {
    let mut v = value();
    v["mode"] = "stock_return".into();
    v["replacements"] = serde_json::json!([]);
    v["output_sha256"] = v["target_normal_sha256"].clone();
    let registry = registry(&v).unwrap();
    let returned = registry
        .prepare(&source(), &target(), "TEST-UD03")
        .unwrap()
        .unwrap();
    assert!(returned.stock_return());
    assert_eq!(returned.image, target());
}

#[test]
fn malformed_conflicting_or_overlapping_profiles_are_rejected_before_use() {
    for mutate in 0..9 {
        let mut v = value();
        match mutate {
            0 => v["replacements"][0]["offset"] = 31.into(),
            1 => v["replacements"][0]["offset"] = 28.into(),
            2 => v["replacements"][0]["replacement_hex"] = "00".into(),
            3 => v["replacements"][0]["expected_hex"] = "zzzz".into(),
            4 => {
                let x = v["replacements"][0].clone();
                v["replacements"].as_array_mut().unwrap().push(x);
            }
            5 => v["schema_version"] = 2.into(),
            6 => v["required_parameters"][0]["parameter"] = 1024.into(),
            7 => v["unexpected"] = true.into(),
            _ => v["source_normal_sha256"] = serde_json::json!([]),
        }
        assert!(
            matches!(registry(&v), Err(Error::Registry)),
            "case {mutate}"
        );
    }
    assert!(matches!(
        Contracts::parse(&[FIXTURE, FIXTURE]),
        Err(Error::Registry)
    ));
}

#[test]
fn wrong_expected_bytes_or_output_digest_abort_without_mutating_input() {
    for field in ["expected", "output"] {
        let mut v = value();
        if field == "expected" {
            v["replacements"][0]["expected_hex"] = "ffff".into();
        } else {
            v["output_sha256"] = "0".repeat(64).into();
        }
        let input = target();
        assert_eq!(
            registry(&v)
                .unwrap()
                .prepare(&source(), &input, "TEST-UD03")
                .unwrap_err(),
            Error::Guard
        );
        assert_eq!(input, target());
    }
}

#[test]
fn typed_recipes_and_hardware_rules_preserve_every_dev_1_5_field() {
    let reviewed = Contracts::parse(PROFILES).unwrap();
    assert_eq!(contracts::definitions(), reviewed.0);
    assert_eq!(contracts::rules(), reviewed.1);
}

#[test]
#[ignore = "requires PIONEER_NORMAL_CORPUS; covers every reviewed dev 1.5 mechanism recipe"]
fn held_every_dev15_recipe_preserves_exact_output_and_composes_every_phase() {
    use crate::image::{
        layout::Observation,
        phase::{self, Assignment},
    };
    let corpus = std::path::PathBuf::from(std::env::var("PIONEER_NORMAL_CORPUS").unwrap());
    let registry = super::registry().unwrap();
    let wanted: std::collections::BTreeSet<_> = registry
        .0
        .iter()
        .map(|p| p.target_normal_sha256.clone())
        .collect();
    let sizes: std::collections::BTreeSet<_> =
        registry.0.iter().map(|p| p.input_length as u64).collect();
    let mut images = std::collections::BTreeMap::new();
    for entry in std::fs::read_dir(corpus).unwrap() {
        let path = entry.unwrap().path();
        if !path.is_file() || !sizes.contains(&path.metadata().unwrap().len()) {
            continue;
        }
        let bytes = std::fs::read(path).unwrap();
        let hash = digest(&bytes);
        if wanted.contains(&hash) {
            images.insert(hash, bytes);
        }
    }
    assert_eq!(
        images.len(),
        wanted.len(),
        "every reviewed native target must be held"
    );
    let ud02_hash = "84fab289c44ce2de98e96272e607869de4501b45f8f4badc43e492920ce07750";
    let ud02 = images[ud02_hash].clone();
    let ud02_contract = Contract::discover(&ud02);
    // Add the three independently SHA-checked forward outputs as source states.
    for p in &registry.0 {
        if p.id.starts_with("pioneer.ud02-to-") {
            let adapted = registry
                .prepare(
                    &ud02_contract,
                    &images[&p.target_normal_sha256],
                    &p.target_model,
                )
                .unwrap()
                .unwrap();
            assert_eq!(digest(&adapted.image), p.output_sha256);
            images.insert(p.output_sha256.clone(), adapted.image);
        }
    }
    let mut checked = 0;
    for p in &registry.0 {
        let target = &images[&p.target_normal_sha256];
        let source = p
            .source_normal_sha256
            .iter()
            .find_map(|hash| images.get(hash))
            .unwrap_or(target);
        let original = if p.id.starts_with("pioneer.ud02-") {
            "BDR-UD02TBD"
        } else if p.id.starts_with("pioneer.ud03-") {
            "BDR-UD03"
        } else {
            "BDR-UD04"
        };
        let canonical = prepare_hardware(
            &Contract::discover(source),
            target,
            &p.target_model,
            original,
        )
        .unwrap()
        .unwrap();
        assert_eq!(canonical.id, p.id);
        assert_eq!(
            digest(&canonical.image),
            p.output_sha256,
            "canonical {}",
            p.id
        );
        if phase::correct_normal(source, Assignment::Direct)
            == Err(phase::CorrectionError::InvalidNormal)
        {
            // The pinned dev 1.5 UD04 1.11 image has a nonzero original sum.
            // Preserve its exact native route, but never repair it in order to
            // invent a phase-equivalent reviewed image.
            assert_eq!(p.id, "pioneer.ud04-native-1.11");
            assert_eq!(canonical.image, *target);
            let Observation::Known(native) = phase::discover(target) else {
                panic!("native phase must remain identifiable")
            };
            let opposite = match native.assignment {
                Assignment::Direct => Assignment::Swapped,
                Assignment::Swapped => Assignment::Direct,
            };
            assert_eq!(
                phase::correct_normal(target, opposite),
                Err(phase::CorrectionError::InvalidNormal)
            );
            let valid_ud04 =
                &images["87e8152f1de1d3be53eb4ad9144c1bb0c45a9be6f78713a0b7487a637f989bf1"];
            let opposite_source = phase::correct_normal(valid_ud04, opposite).unwrap();
            assert!(matches!(
                prepare_hardware(
                    &Contract::discover(&opposite_source),
                    target,
                    &p.target_model,
                    original
                ),
                Err(Error::Guard)
            ));
            println!(
                "{} exact={} native unchanged; invalid original checksum blocks phase edits",
                p.id, p.output_sha256
            );
            checked += 1;
            continue;
        }
        for installed in [Assignment::Direct, Assignment::Swapped] {
            let source_variant = phase::correct_normal(source, installed).unwrap();
            let source_contract = Contract::discover(&source_variant);
            let expected = phase::correct_normal(&canonical.image, installed).unwrap();
            for supplied in [Assignment::Direct, Assignment::Swapped] {
                let target_variant = phase::correct_normal(target, supplied).unwrap();
                let corrected =
                    prepare_hardware(&source_contract, &target_variant, &p.target_model, original)
                        .unwrap()
                        .unwrap();
                assert_eq!(corrected.id, p.id);
                assert_eq!(
                    corrected.image, expected,
                    "{} {installed:?}/{supplied:?}",
                    p.id
                );
                assert!(
                    matches!(phase::discover(&corrected.image), Observation::Known(value) if value.assignment == installed)
                );
                assert_eq!(
                    corrected.stock_return(),
                    p.mode == Mode::StockReturn && corrected.image == target_variant
                );
                assert_eq!(
                    corrected.requirements,
                    if p.mode == Mode::StockReturn {
                        Vec::new()
                    } else {
                        p.required_parameters.clone()
                    }
                );
                let again = prepare_hardware(
                    &source_contract,
                    &corrected.image,
                    &p.target_model,
                    original,
                )
                .unwrap()
                .unwrap();
                assert_eq!(again.image, corrected.image, "{} idempotence", p.id);
            }
        }
        println!(
            "{} exact={} four phase combinations and idempotence",
            p.id, p.output_sha256
        );
        checked += 1;
    }
    assert_eq!(checked, 11);
}
