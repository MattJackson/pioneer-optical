use super::*;
const FIXTURE: &str = include_str!("fixture.json");

fn source() -> super::super::update::Contract {
    let mut contract = super::super::update::Contract::discover(b"fixture-ud02");
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
fn registry(v: &serde_json::Value) -> Result<Registry, Error> {
    Registry::parse(&[&v.to_string()])
}

#[test]
fn production_profiles_do_not_change_unrelated_images_or_routes() {
    assert!(has_profiles());
    assert!(prepare(&source(), &target(), "TEST-UD03")
        .unwrap()
        .is_none());
}

#[test]
fn production_routes_are_valid_unique_and_bound_to_exact_firmware_pairs() {
    let registry = Registry::parse(PROFILES).unwrap();
    assert_eq!(registry.0.len(), 11);
    for p in &registry.0 {
        if p.id.starts_with("pioneer.ud02-to-") {
            assert_eq!(
                p.required_parameters,
                [Requirement {
                    parameter: 0x28f,
                    value: 1
                }]
            );
        }
        assert!(!p.policy().is_empty());
    }
}

#[test]
fn ud02_original_hardware_routes_do_not_inherit_installed_firmware_permissions() {
    use super::super::routing::Decision;
    for original in ["BDR-UD02TBD", "BDU-UD02ABC", "bdr ud02fan"] {
        assert_eq!(
            hardware_route(original, "BDR-UD04"),
            Ok(Decision::Profile("pioneer.ud02-to-ud04-1.14"))
        );
        assert_eq!(
            hardware_route(original, "BDR-UD03"),
            Ok(Decision::Profile("pioneer.ud02-to-ud03"))
        );
        assert_eq!(
            hardware_route(original, "BDR-UD02D"),
            Ok(Decision::OriginalPlatform)
        );
    }
    for original in ["BDR-209XJB", "BDR-UD020TBD"] {
        for destination in ["BDR-UD02D", "BDR-UD03", "BDR-UD04"] {
            assert_eq!(
                hardware_route(original, destination),
                Ok(Decision::Unscoped)
            );
        }
        assert_eq!(
            hardware_route(original, "SBC-06D2X-U"),
            Ok(Decision::Unscoped)
        );
        assert_eq!(
            hardware_route(original, "unclassified alias"),
            Ok(Decision::Unscoped)
        );
    }
}

#[test]
fn catalogue_scopes_are_the_same_compiled_hardware_rules() {
    let rules = hardware_rules().unwrap();
    assert_eq!(rules[0].hardware.platform, "UD02");
    assert_eq!(rules[0].destination.platform, "UD04");
    assert_eq!(rules[0].profile, "pioneer.ud02-to-ud04-1.14");
}

#[test]
fn inverse_exceptions_do_not_remove_native_oem_routes() {
    use super::super::routing::Decision;
    for destination in ["SlimtypeEB1", "SBW-06D2X-U", "SBC-06D2X-U"] {
        assert_eq!(
            hardware_route("BDR-UD02TBD", destination),
            Err(Error::OriginalMismatch)
        );
        for original in ["BDR-UD03FAL", "BDR-UD04ABC"] {
            assert_eq!(
                hardware_route(original, destination),
                Ok(Decision::Unscoped)
            );
        }
    }
}

#[test]
fn central_registry_rejects_missing_policies_and_ambiguous_hardware_before_use() {
    let base: serde_json::Value = serde_json::from_str(PROFILES[0]).unwrap();
    let parse = |v: &serde_json::Value| Registry::parse(&[&v.to_string()]);
    assert!(parse(&base).is_ok());
    for change in 0..5 {
        let mut value = base.clone();
        match change {
            0 => value["hardware_rules"][0]["profile"] = "missing".into(),
            1 => value["hardware_rules"][0]["hardware"]["platform"] = "UD02 extra".into(),
            2 => {
                let mut duplicate = value["hardware_rules"][0].clone();
                duplicate["hardware"]["platform"] = "ud02".into();
                value["hardware_rules"]
                    .as_array_mut()
                    .unwrap()
                    .push(duplicate);
            }
            3 => {
                let mut overlap = value["hardware_rules"][0].clone();
                overlap["hardware"]["suffix"] = "TBD".into();
                value["hardware_rules"]
                    .as_array_mut()
                    .unwrap()
                    .push(overlap);
            }
            _ => value["schema_version"] = 2.into(),
        }
        assert!(parse(&value).is_err(), "invalid configuration {change}");
    }
}

#[test]
fn held_original_hardware_current_firmware_destination_matrix() {
    let Ok(original_path) = std::env::var("PIONEER_UD02_NORMAL") else {
        return;
    };
    let ud02 = std::fs::read(original_path).unwrap();
    let ud04 = std::fs::read(std::env::var("PIONEER_UD04_NORMAL").unwrap()).unwrap();
    let ud03 = std::fs::read(std::env::var("PIONEER_UD03_NORMAL").unwrap()).unwrap();
    let registry = Registry::parse(PROFILES).unwrap();
    let converted = registry
        .prepare_hardware(
            &super::super::update::Contract::discover(&ud02),
            &ud04,
            "BDR-UD04",
            "BDR-UD02TBD",
        )
        .unwrap()
        .unwrap()
        .image;
    let inverse = registry
        .prepare_hardware(
            &super::super::update::Contract::discover(&ud04),
            &ud02,
            "BDR-UD02D",
            "BDR-UD04ABC",
        )
        .unwrap()
        .unwrap()
        .image;
    let inverse_whole = registry
        .prepare_hardware(
            &super::super::update::Contract::discover(&ud03),
            &ud02,
            "BDR-UD02D",
            "BDR-UD03FAL",
        )
        .unwrap()
        .unwrap()
        .image;
    let converted03 = registry
        .prepare_hardware(
            &super::super::update::Contract::discover(&ud02),
            &ud03,
            "BDR-UD03",
            "BDR-UD02TBD",
        )
        .unwrap()
        .unwrap()
        .image;
    // Running firmware is deliberately varied independently of factory hardware.
    for (current_name, current) in [
        ("UD02 OEM", &ud02),
        ("UD03 OEM", &ud03),
        ("UD04 OEM", &ud04),
        ("UD03 on UD02", &converted03),
        ("UD04 on UD02", &converted),
        ("UD02 on UD03/UD04", &inverse),
    ] {
        let source = super::super::update::Contract::discover(current);
        for original in [
            "BDR-UD02TBD",
            "BDU-UD02ABC",
            "bdr ud02fan",
            "BDR-UD03FAL",
            "BDU-UD03ABC",
            "BDR-UD04ABC",
            "BDU-UD04TBD",
        ] {
            for (model, target) in [
                ("BDR-UD02D", &ud02),
                ("BDR-UD03", &ud03),
                ("BDR-UD04", &ud04),
            ] {
                let prepared = registry
                    .prepare_hardware(&source, target, model, original)
                    .unwrap()
                    .unwrap();
                let scope = hardware_rules()
                    .unwrap()
                    .iter()
                    .find(|r| {
                        r.hardware
                            .matches(crate::production::ProductCode::parse(original).unwrap())
                    })
                    .unwrap()
                    .hardware;
                let symbolic = registry
                    .prepare_scope(&source, target, model, scope)
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    symbolic.image, prepared.image,
                    "symbolic and factory evidence select the same exact profile"
                );
                let original02 = crate::production::ProductCode::parse(original)
                    .unwrap()
                    .platform_is("UD02");
                let expected = match (original02, model) {
                    (true, "BDR-UD03") => &converted03,
                    (true, "BDR-UD04") => &converted,
                    (false, "BDR-UD02D")
                        if crate::production::ProductCode::parse(original)
                            .unwrap()
                            .platform_is("UD03")
                            && source.calibration
                                == Some(super::super::update::Calibration::WholeWord) =>
                    {
                        &inverse_whole
                    }
                    (false, "BDR-UD02D") => &inverse,
                    _ => target,
                };
                assert_eq!(
                    &prepared.image, expected,
                    "{current_name}, original {original}, destination {model}"
                );
                source
                    .check_resolving(
                        &super::super::update::Contract::discover(&prepared.image),
                        Some(&prepared.resolves_issue),
                    )
                    .unwrap();
                HardwareGuard::new(model, &prepared.image, Some(&prepared.id))
                    .check(&factory_code(original))
                    .unwrap();
                let repeated = registry
                    .prepare_hardware(&source, &prepared.image, model, original)
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    repeated.image, prepared.image,
                    "reapplying must be idempotent"
                );
                if original02 && model != "BDR-UD02D" {
                    assert_eq!(
                        prepared.requirements,
                        [Requirement {
                            parameter: 0x28f,
                            value: 1
                        }]
                    );
                } else {
                    assert!(prepared.requirements.is_empty());
                }
            }
            if crate::production::ProductCode::parse(original)
                .unwrap()
                .platform_is("UD02")
            {
                assert_eq!(
                    registry
                        .prepare_hardware(&source, &ud04, "BDR-209", original)
                        .unwrap_err(),
                    Error::OriginalMismatch
                );
            } else {
                assert_eq!(
                    hardware_route(original, "BDR-209"),
                    Ok(super::super::routing::Decision::Unscoped)
                );
            }
        }
    }
}

fn factory_code(code: &str) -> Vec<u8> {
    let mut parameters = vec![0xff; crate::production::PARAMETERS_LEN];
    parameters[0x84..0x88].copy_from_slice(b"kw01");
    parameters[0x90..0x9f].fill(b' ');
    parameters[0x90..0x90 + code.len()].copy_from_slice(code.as_bytes());
    parameters
}

#[test]
fn execution_guard_rejects_unreviewed_bytes_in_every_scoped_platform() {
    for model in ["BDR-UD02D", "BDR-UD03", "BDR-UD04"] {
        let guard = HardwareGuard::new(model, b"unreviewed firmware", None);
        for code in ["BDR-UD02TBD", "BDU-UD02ABC", "BDR-UD03FAL", "BDR-UD04ABC"] {
            assert!(guard.check(&factory_code(code)).is_err());
        }
        assert_eq!(
            guard.check(&[0xff; crate::production::PARAMETERS_LEN]),
            Err(Error::OriginalRequired)
        );
    }
}

#[test]
fn held_execution_guard_binds_original_hardware_adaptation_and_pristine_return() {
    let Ok(path) = std::env::var("PIONEER_UD02_NORMAL") else {
        return;
    };
    let ud02 = std::fs::read(path).unwrap();
    let ud04 = std::fs::read(std::env::var("PIONEER_UD04_NORMAL").unwrap()).unwrap();
    let source = super::super::update::Contract::discover(&ud02);
    let prepared = prepare_hardware(&source, &ud04, "BDR-UD04", "BDR-UD02TBD")
        .unwrap()
        .unwrap();
    let adapted = HardwareGuard::new("BDR-UD04", &prepared.image, Some(&prepared.id));
    let pristine = HardwareGuard::new("BDR-UD04", &ud04, None);
    let returned = HardwareGuard::new("BDR-UD02D", &ud02, None);
    for original in ["BDR-UD02TBD", "BDU-UD02ABC", "BDR-UD02FAN"] {
        let parameters = factory_code(original);
        assert_eq!(adapted.check(&parameters), Ok(()));
        assert!(pristine.check(&parameters).is_err());
        assert_eq!(returned.check(&parameters), Ok(()));
    }
    let native = factory_code("BDR-UD03FAL");
    assert!(adapted.check(&native).is_err());
    assert_eq!(pristine.check(&native), Ok(()));
    let mut corrupt = ud02;
    corrupt[0x400] ^= 1;
    let bad_return = HardwareGuard::new("BDR-UD02D", &corrupt, None);
    assert_eq!(
        bad_return.check(&factory_code("BDR-UD02TBD")),
        Err(Error::Guard)
    );
}

#[test]
fn held_ud02_ud04_images_reproduce_the_tested_output_and_pristine_return() {
    let Ok(original) = std::env::var("PIONEER_UD02_NORMAL") else {
        return;
    };
    let ud02 = std::fs::read(original).unwrap();
    let ud04 = std::fs::read(std::env::var("PIONEER_UD04_NORMAL").unwrap()).unwrap();
    let from = super::super::update::Contract::discover(&ud02);
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
        &super::super::update::Contract::discover(&adapted.image),
        Some(&adapted.resolves_issue),
    )
    .unwrap();
    let back = super::super::update::Contract::discover(&adapted.image);
    let returned = prepare(&back, &ud02, "BDR-UD02D").unwrap().unwrap();
    assert!(returned.stock_return());
    assert_eq!(returned.image, ud02);
    // Native UD04 uses the inverse mechanism recipe, never UD02's pristine return.
    let native = super::super::update::Contract::discover(&ud04);
    let inverse = prepare(&native, &ud02, "BDR-UD02D").unwrap().unwrap();
    assert!(!inverse.stock_return());
    assert_ne!(inverse.image, ud02);
    let mut changed = ud04.clone();
    changed[0x1000] ^= 1;
    assert!(prepare(&from, &changed, "BDR-UD04").unwrap().is_none());
    assert!(prepare(&from, &ud04, "BDR-UD03").unwrap().is_none());
}

#[test]
fn one_compiled_test_json_matches_exactly_one_direction_and_image() {
    let registry = Registry::parse(&[FIXTURE]).unwrap();
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
    let registry = Registry::parse(&[FIXTURE]).unwrap();
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
    for mutate in 0..10 {
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
            9 => v["hardware_scheme"] = "pioneer.hardware.v5".into(),
            _ => v["source_normal_sha256"] = serde_json::json!([]),
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
                .prepare(&source(), &input, "TEST-UD03")
                .unwrap_err(),
            Error::Guard
        );
        assert_eq!(input, target());
    }
}

#[test]
fn compiled_routes_reject_overlapping_broad_and_specific_hardware_scopes() {
    let mut document: serde_json::Value = serde_json::from_str(PROFILES[0]).unwrap();
    document["hardware_rules"][1]["hardware"]["prefix"] = serde_json::json!("BDR");
    assert!(matches!(
        Registry::parse(&[&document.to_string()]),
        Err(Error::Registry)
    ));
}

#[test]
fn arbitrary_oem_destination_has_identical_live_and_symbolic_policy_and_guard() {
    let registry = Registry::parse(PROFILES).unwrap();
    let rules = hardware_rules().unwrap();
    let mut scopes = Vec::new();
    for rule in rules {
        if !scopes.contains(&rule.hardware) {
            scopes.push(rule.hardware);
        }
    }
    for scope in scopes {
        let original = format!(
            "{}-{}{}",
            scope.prefix.unwrap_or("BDR"),
            scope.platform,
            scope.suffix.unwrap_or("")
        );
        let restricted = rules.iter().any(|r| r.hardware == scope && r.restricted);
        for model in ["Arbitrary OEM Name", "SBC-06D2X-U", "SlimtypeEB1"] {
            let live = registry.prepare_hardware(&source(), &target(), model, &original);
            let symbolic = registry.prepare_scope(&source(), &target(), model, scope);
            if restricted {
                assert_eq!(live.unwrap_err(), Error::OriginalMismatch);
                assert_eq!(symbolic.unwrap_err(), Error::OriginalMismatch);
            } else {
                assert!(live.unwrap().is_none());
                assert!(symbolic.unwrap().is_none());
                let guard = HardwareGuard::new(model, &target(), None).with_scope(Some(scope));
                assert_eq!(guard.scope(), Some(scope));
                assert_eq!(guard.check(&factory_code(&original)), Ok(()));
                assert_eq!(
                    guard.check(&factory_code("BDR-UD02TBD")),
                    Err(Error::OriginalMismatch)
                );
                assert_eq!(
                    guard.check(&[0xff; crate::production::PARAMETERS_LEN]),
                    Err(Error::OriginalRequired)
                );
            }
        }
    }
}
