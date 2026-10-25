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
fn no_production_profiles_means_no_image_or_route_changes() {
    assert!(!has_profiles());
    for code in [None, Some("BDR-UD02TBD"), Some("BDR-UD04")] {
        assert!(prepare(&source(code), &target(), "TEST-UD03")
            .unwrap()
            .is_none());
    }
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
