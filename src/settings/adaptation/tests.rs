use super::*;
const FIXTURE: &str = include_str!("fixture.json");

fn source(code: Option<&str>) -> super::super::update::Contract {
    let mut contract = super::super::update::Contract::discover(b"fixture-ud02");
    contract.hardware_family = Some("1111111111111111".into());
    contract.original_product_code = code.map(str::to_owned);
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
fn registry(v: &serde_json::Value) -> Result<Registry, Error> {
    Registry::parse(&[&v.to_string()])
}

#[test]
fn production_profiles_do_not_change_unrelated_images_or_routes() {
    assert!(has_profiles());
    for code in [None, Some("BDR-UD02TBD"), Some("BDR-UD04")] {
        assert!(prepare(&source(code), &target(), "TEST-UD03")
            .unwrap()
            .is_none());
    }
}

#[test]
fn production_routes_are_valid_unique_and_only_for_original_ud02_hardware() {
    let registry = Registry::parse(PROFILES).unwrap();
    assert_eq!(registry.0.len(), 2);
    for p in &registry.0 {
        assert_eq!(p.original_product_codes, ["BDR-UD02TBD"]);
        assert_eq!(
            p.required_parameters,
            [Requirement {
                parameter: 0x28f,
                value: 1
            }]
        );
    }
}

#[test]
fn held_ud02_ud04_images_reproduce_the_tested_output_and_pristine_return() {
    let Ok(original) = std::env::var("PIONEER_UD02_NORMAL") else {
        return;
    };
    let ud02 = std::fs::read(original).unwrap();
    let ud04 = std::fs::read(std::env::var("PIONEER_UD04_NORMAL").unwrap()).unwrap();
    let mut from = super::super::update::Contract::discover(&ud02);
    assert_eq!(
        digest(&ud02),
        "84fab289c44ce2de98e96272e607869de4501b45f8f4badc43e492920ce07750"
    );
    assert_eq!(
        digest(&ud04),
        "87e8152f1de1d3be53eb4ad9144c1bb0c45a9be6f78713a0b7487a637f989bf1"
    );
    assert_eq!(
        prepare(&from, &ud04, "BDR-UD04").unwrap_err(),
        Error::OriginalRequired
    );
    from.original_product_code = Some("BDR-UD04".into());
    assert_eq!(
        prepare(&from, &ud04, "BDR-UD04").unwrap_err(),
        Error::OriginalMismatch
    );
    from.original_product_code = Some("BDR-UD02TBD".into());
    let adapted = prepare(&from, &ud04, "BDR-UD04").unwrap().unwrap();
    assert_eq!(
        digest(&adapted.image),
        "ca09032288c62b8b26bb983431af11b52aaeec8da9bd0e80afcccdf3b07f0815"
    );
    from.check_resolving(
        &super::super::update::Contract::discover(&adapted.image),
        Some(&adapted.resolves_issue),
    )
    .unwrap();
    let mut back = super::super::update::Contract::discover(&adapted.image);
    back.original_product_code = Some("BDR-UD02TBD".into());
    let returned = prepare(&back, &ud02, "BDR-UD02D").unwrap().unwrap();
    assert!(returned.stock_return());
    assert_eq!(returned.image, ud02);
    back.original_product_code = Some("BDR-UD04".into());
    assert_eq!(
        prepare(&back, &ud02, "BDR-UD02D").unwrap_err(),
        Error::OriginalMismatch
    );
    let mut changed = ud04.clone();
    changed[0x1000] ^= 1;
    assert!(prepare(&from, &changed, "BDR-UD04").unwrap().is_none());
    assert!(prepare(&from, &ud04, "BDR-UD03").unwrap().is_none());
}

#[test]
fn one_compiled_test_json_matches_exactly_one_direction_and_image() {
    let registry = Registry::parse(&[FIXTURE]).unwrap();
    let from = source(Some("BDR-UD02TBD"));
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
fn running_firmware_cannot_substitute_for_original_hardware() {
    let registry = Registry::parse(&[FIXTURE]).unwrap();
    assert_eq!(
        registry
            .prepare(&source(None), &target(), "TEST-UD03")
            .unwrap_err(),
        Error::OriginalRequired
    );
    assert_eq!(
        registry
            .prepare(&source(Some("BDR-UD04")), &target(), "TEST-UD03")
            .unwrap_err(),
        Error::OriginalMismatch
    );
}

#[test]
fn stock_ud02_return_is_pristine_and_requires_original_ud02() {
    let mut v = value();
    v["mode"] = "stock_return".into();
    v["replacements"] = serde_json::json!([]);
    v["output_sha256"] = v["target_normal_sha256"].clone();
    let registry = registry(&v).unwrap();
    let returned = registry
        .prepare(&source(Some("BDR-UD02TBD")), &target(), "TEST-UD03")
        .unwrap()
        .unwrap();
    assert!(returned.stock_return());
    assert_eq!(returned.image, target());
    for code in ["BDR-UD03FAL", "BDR-UD04"] {
        assert_eq!(
            registry
                .prepare(&source(Some(code)), &target(), "TEST-UD03")
                .unwrap_err(),
            Error::OriginalMismatch
        );
    }
    assert_eq!(
        registry
            .prepare(&source(None), &target(), "TEST-UD03")
            .unwrap_err(),
        Error::OriginalRequired
    );
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
            _ => v["original_product_codes"] = serde_json::json!([]),
        }
        assert!(
            matches!(registry(&v), Err(Error::Registry)),
            "case {mutate}"
        );
    }
    assert!(matches!(
        Registry::parse(&[FIXTURE, FIXTURE]),
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
                .prepare(&source(Some("BDR-UD02TBD")), &input, "TEST-UD03")
                .unwrap_err(),
            Error::Guard
        );
        assert_eq!(input, target());
    }
}
