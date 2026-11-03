//! Startup selections checked against the independently traced native gates.
#![cfg(feature = "image")]
use pioneer_optical::startup;

#[test]
#[ignore = "requires PIONEER_STARTUP_AUDIT and PIONEER_NORMAL_CORPUS"]
fn all_audited_positive_startup_gates_select_an_accepted_word() {
    let audit = std::path::PathBuf::from(std::env::var("PIONEER_STARTUP_AUDIT").unwrap());
    let corpus = std::path::PathBuf::from(std::env::var("PIONEER_NORMAL_CORPUS").unwrap());
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(audit.join("audit.json")).unwrap()).unwrap();
    let mut errors = Vec::new();
    let mut count = 0;
    for row in manifest["images"].as_array().unwrap() {
        let component = row["component"].as_str().unwrap();
        let raw = std::fs::read(corpus.join(format!("{component}.bin"))).unwrap();
        let expected = u16::from_str_radix(
            row["required_value"]
                .as_str()
                .unwrap()
                .trim_start_matches("0x"),
            16,
        )
        .unwrap();
        let result = startup::setting(&raw);
        let pioneer_optical::image::layout::Observation::Known(bound) =
            startup::bound_selection(&raw)
        else {
            errors.push(format!("{component}: native getter binding unresolved"));
            count += 1;
            continue;
        };
        assert_eq!(
            (bound.requirement.parameter, bound.requirement.required),
            (0x9f, expected),
            "{component}"
        );
        let plan = pioneer_optical::compatibility::startup::plan(&raw)
            .unwrap_or_else(|error| panic!("{component}: bound startup planning failed: {error}"));
        assert_eq!(
            (plan.setting().parameter, plan.setting().value),
            (0x9f, expected)
        );
        assert!(matches!(
            plan.evidence(),
            pioneer_optical::compatibility::startup::Evidence::BoundComparison(_)
        ));
        let mut wrong_register = raw.clone();
        wrong_register[(bound.requirement.check_address - 0x410000) as usize + 1] ^= 1;
        assert!(
            !matches!(
                startup::bound_selection(&wrong_register),
                pioneer_optical::image::layout::Observation::Known(_)
            ),
            "{component}: mismatched getter ABI accepted"
        );
        let mut corrupted = raw.clone();
        corrupted[(bound.requirement.getter_address - 0x410000) as usize] ^= 1;
        assert!(
            !matches!(
                startup::bound_selection(&corrupted),
                pioneer_optical::image::layout::Observation::Known(_)
            ),
            "{component}: corrupt getter accepted"
        );
        assert!(
            pioneer_optical::compatibility::startup::plan(&wrong_register).is_err(),
            "{component}: mismatched ABI authorized a startup write"
        );
        assert!(
            pioneer_optical::compatibility::startup::plan(&corrupted).is_err(),
            "{component}: corrupt getter authorized a startup write"
        );
        if result
            != Ok(startup::Setting {
                parameter: 0x9f,
                value: expected,
                explicit: true,
            })
        {
            errors.push(format!(
                "{component}: expected {expected:04x}, found {result:?}"
            ));
        }
        count += 1;
    }
    // FE23 is the unconditional accepted value. FE09 additionally needs the
    // independently audited runtime predicate; this test does not erase it.
    let conditional: serde_json::Value = serde_json::from_slice(
        &std::fs::read(audit.join("conditional-009f-predicate.json")).unwrap(),
    )
    .unwrap();
    let raw = std::fs::read(corpus.join(format!(
        "{}.bin",
        conditional["component"].as_str().unwrap()
    )))
    .unwrap();
    assert_eq!(
        startup::setting(&raw),
        Ok(startup::Setting {
            parameter: 0x9f,
            value: 0xfe23,
            explicit: true
        })
    );
    let pioneer_optical::image::layout::Observation::Known(bound) = startup::bound_selection(&raw)
    else {
        panic!("conditional getter binding unresolved");
    };
    assert_eq!(bound.requirement.required, 0xfe23);
    assert_eq!(count, 60);
    assert!(
        errors.is_empty(),
        "{} startup mismatches:\n{}",
        errors.len(),
        errors.join("\n")
    );
}

#[test]
#[ignore = "requires PIONEER_STARTUP_AUDIT, PIONEER_LAYOUT_AUDIT and PIONEER_NORMAL_CORPUS"]
fn absence_of_a_bound_positive_gate_is_not_an_absence_certificate() {
    use pioneer_optical::image::layout::Observation;
    let audit = std::path::PathBuf::from(std::env::var("PIONEER_STARTUP_AUDIT").unwrap());
    let layouts = std::path::PathBuf::from(std::env::var("PIONEER_LAYOUT_AUDIT").unwrap());
    let corpus = std::path::PathBuf::from(std::env::var("PIONEER_NORMAL_CORPUS").unwrap());
    let fixed: serde_json::Value =
        serde_json::from_slice(&std::fs::read(audit.join("audit.json")).unwrap()).unwrap();
    let conditional: serde_json::Value = serde_json::from_slice(
        &std::fs::read(audit.join("conditional-009f-predicate.json")).unwrap(),
    )
    .unwrap();
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(layouts.join("all-platform-layouts.json")).unwrap())
            .unwrap();
    let mut positive: std::collections::BTreeSet<_> = fixed["images"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["component"].as_str().unwrap())
        .collect();
    positive.insert(conditional["component"].as_str().unwrap());
    let mut known = 0;
    let mut other = 0;
    for component in manifest["images"].as_object().unwrap().keys() {
        let bytes = std::fs::read(corpus.join(format!("{component}.bin"))).unwrap();
        let observed = matches!(startup::bound_selection(&bytes), Observation::Known(_));
        assert_eq!(
            observed,
            positive.contains(component.as_str()),
            "{component}"
        );
        if observed {
            known += 1;
        } else {
            other += 1;
        }
    }
    assert_eq!((known, other), (61, 661));
}

#[test]
#[ignore = "requires PIONEER_STARTUP_REFERENCES and PIONEER_NORMAL_CORPUS"]
fn r0_reference_inventory_matches_every_audited_call_and_pointer() {
    use pioneer_optical::{
        image::layout::Observation,
        startup::coverage::{references, CallKind},
    };
    let audit = std::path::PathBuf::from(std::env::var("PIONEER_STARTUP_REFERENCES").unwrap());
    let corpus = std::path::PathBuf::from(std::env::var("PIONEER_NORMAL_CORPUS").unwrap());
    let read = |name: &str| -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(audit.join(name)).unwrap()).unwrap()
    };
    let direct = read("009f-r0-generic-direct-complete.json");
    let pointers = read("dynamic-r0-sat9-reuse/dynamic-pointer-bindings.json");
    let relative = read("dynamic-r0-sat9-reuse/relative-getter-calls.json");
    let index = |value: &serde_json::Value| -> usize {
        usize::from_str_radix(value.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
            - 0x410000
    };
    let mut count = 0;
    for row in direct["images"].as_array().unwrap() {
        let component = row["component"].as_str().unwrap();
        let raw = std::fs::read(corpus.join(format!("{component}.bin"))).unwrap();
        let Observation::Known(actual) = references(&raw) else {
            panic!("{component}: reader unresolved");
        };
        assert_eq!(actual.argument_register, 0);
        let expected: std::collections::BTreeSet<_> = row["calls"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| index(&r["site"]))
            .collect();
        let found: std::collections::BTreeSet<_> = actual
            .calls
            .iter()
            .filter(|c| c.kind == CallKind::Absolute)
            .map(|c| c.offset)
            .collect();
        assert_eq!(found, expected, "{component}: absolute calls");
        let rr = relative["images"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["component"] == component)
            .unwrap();
        let expected: std::collections::BTreeSet<_> = rr["calls"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| index(&r["site"]))
            .collect();
        let found: std::collections::BTreeSet<_> = actual
            .calls
            .iter()
            .filter(|c| c.kind != CallKind::Absolute)
            .map(|c| c.offset)
            .collect();
        assert_eq!(found, expected, "{component}: relative calls");
        let pp = pointers["images"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["component"] == component)
            .unwrap();
        let expected: std::collections::BTreeSet<_> = pp["consumers"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|c| c["matches"].as_array().unwrap())
            .flat_map(|m| m["getter_pointers"].as_array().unwrap())
            .map(index)
            .collect();
        let found: std::collections::BTreeSet<_> =
            actual.pointers.iter().map(|p| p.offset).collect();
        assert_eq!(found, expected, "{component}: literal getter pointers");
        assert_eq!(found.len(), pp["literal_count"].as_u64().unwrap() as usize);
        count += 1;
    }
    assert_eq!(count, 190);
}

#[test]
#[ignore = "requires PIONEER_STARTUP_REFERENCES and PIONEER_NORMAL_CORPUS"]
fn direct_consumer_blocks_match_audit_and_leave_other_calls_uncovered() {
    use pioneer_optical::{image::layout::Observation, startup::coverage::direct};
    let audit = std::path::PathBuf::from(std::env::var("PIONEER_STARTUP_REFERENCES").unwrap());
    let corpus = std::path::PathBuf::from(std::env::var("PIONEER_NORMAL_CORPUS").unwrap());
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(audit.join("dynamic-r0-sat9-reuse/dynamic-consumer-bindings.json")).unwrap(),
    )
    .unwrap();
    let mut count = 0;
    let mut blocks = 0;
    for row in manifest["images"].as_array().unwrap() {
        let component = row["component"].as_str().unwrap();
        let raw = std::fs::read(corpus.join(format!("{component}.bin"))).unwrap();
        let Observation::Known(actual) = direct::discover(&raw) else {
            panic!("{component}: unresolved consumers");
        };
        let mut expected = Vec::new();
        for consumer in row["consumers"].as_array().unwrap() {
            for m in consumer["matches"].as_array().unwrap() {
                let offset = usize::from_str_radix(
                    m["entry"].as_str().unwrap().trim_start_matches("0x"),
                    16,
                )
                .unwrap()
                    - 0x410000;
                let calls: Vec<_> = m["getter_sites"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| {
                        usize::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16)
                            .unwrap()
                            - 0x410000
                    })
                    .collect();
                expected.push((offset, consumer["kind"].as_str().unwrap(), calls));
            }
        }
        expected.sort();
        let found: Vec<_> = actual
            .blocks
            .iter()
            .map(|b| (b.offset, b.kind.as_str(), b.calls.clone()))
            .collect();
        assert_eq!(found, expected, "{component}");
        assert!(
            !actual.uncovered.is_empty(),
            "partial block coverage was mistaken for completeness"
        );
        for block in &actual.blocks {
            assert!(block
                .calls
                .iter()
                .all(|call| !actual.uncovered.contains(call)));
        }
        blocks += actual.blocks.len();
        count += 1;
    }
    assert_eq!((count, blocks), (190, 1312));
}

#[test]
#[ignore = "requires PIONEER_STARTUP_REFERENCES and PIONEER_NORMAL_CORPUS"]
fn pointer_lifetimes_tails_and_callers_match_the_native_audit() {
    use pioneer_optical::{image::layout::Observation, startup::coverage::pointer};
    let audit = std::path::PathBuf::from(std::env::var("PIONEER_STARTUP_REFERENCES").unwrap());
    let corpus = std::path::PathBuf::from(std::env::var("PIONEER_NORMAL_CORPUS").unwrap());
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(audit.join("dynamic-r0-sat9-reuse/dynamic-pointer-bindings.json")).unwrap(),
    )
    .unwrap();
    let error_tails: serde_json::Value = serde_json::from_slice(
        &std::fs::read(audit.join("dynamic-r0-sat9-reuse/near9f-tail-inventory.json")).unwrap(),
    )
    .unwrap();
    let offset = |v: &serde_json::Value| {
        usize::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap() - 0x410000
    };
    let mut images = 0;
    let mut pointers = 0;
    for row in manifest["images"].as_array().unwrap() {
        let component = row["component"].as_str().unwrap();
        let raw = std::fs::read(corpus.join(format!("{component}.bin"))).unwrap();
        let Observation::Known(actual) = pointer::discover(&raw) else {
            panic!("{component}: pointer evidence unresolved");
        };
        let mut expected = Vec::new();
        for consumer in row["consumers"].as_array().unwrap() {
            for m in consumer["matches"].as_array().unwrap() {
                let sites: Vec<_> = m["getter_pointers"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(offset)
                    .collect();
                let tail = m
                    .get("pointer_lifetime_tail")
                    .map(|t| offset(&t["entry"]))
                    .or_else(|| {
                        error_tails["images"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .find(|r| {
                                r["component"] == component && r["near9f_entry"] == m["entry"]
                            })
                            .map(|r| offset(&r["error_tail_entry"]))
                    });
                let callers: Vec<_> = m
                    .get("direct_callers")
                    .and_then(|v| v.as_array())
                    .into_iter()
                    .flatten()
                    .map(|c| {
                        (
                            offset(&c["site"]),
                            u16::from_str_radix(
                                c["index"].as_str().unwrap().trim_start_matches("0x"),
                                16,
                            )
                            .unwrap(),
                        )
                    })
                    .collect();
                expected.push((
                    offset(&m["entry"]),
                    consumer["kind"].as_str().unwrap(),
                    sites,
                    tail,
                    callers,
                ));
            }
        }
        expected.sort();
        let found: Vec<_> = actual
            .blocks
            .iter()
            .map(|b| {
                (
                    b.offset,
                    b.form,
                    b.pointers.clone(),
                    b.lifetime_tail,
                    b.callers
                        .iter()
                        .map(|c| (c.offset, c.index))
                        .collect::<Vec<_>>(),
                )
            })
            .collect();
        assert_eq!(found, expected, "{component}");
        assert!(
            actual.uncovered.is_empty(),
            "{component}: uncovered {:?}",
            actual.uncovered
        );
        pointers += actual
            .blocks
            .iter()
            .flat_map(|b| b.pointers.iter().copied())
            .collect::<std::collections::BTreeSet<_>>()
            .len();
        images += 1;
    }
    assert_eq!((images, pointers), (190, 2426));
}

#[test]
#[ignore = "requires PIONEER_STARTUP_REFERENCES and PIONEER_NORMAL_CORPUS"]
fn seven_word_rom_tables_match_every_native_index_and_call() {
    use pioneer_optical::{image::layout::Observation, startup::coverage::table};
    let audit = std::path::PathBuf::from(std::env::var("PIONEER_STARTUP_REFERENCES").unwrap());
    let corpus = std::path::PathBuf::from(std::env::var("PIONEER_NORMAL_CORPUS").unwrap());
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(audit.join("dynamic-r0/helper-proof.json")).unwrap())
            .unwrap();
    let parse = |v: &serde_json::Value| {
        usize::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
    };
    let mut count = 0;
    for row in manifest["templates"][0]["matches"].as_array().unwrap() {
        let component = row["component"].as_str().unwrap();
        let raw = std::fs::read(corpus.join(format!("{component}.bin"))).unwrap();
        let Observation::Known(blocks) = table::discover(&raw) else {
            panic!("{component}: unresolved")
        };
        assert_eq!(blocks.len(), 1, "{component}");
        let block = &blocks[0];
        assert_eq!(block.offset, parse(&row["native"]["start"]) - 0x410000);
        assert_eq!(
            block.dynamic_call,
            parse(&row["dynamic_getter_call"]) - 0x410000
        );
        assert_eq!(block.table_offset, parse(&row["table"]["start"]) - 0x410000);
        let expected: Vec<_> = row["indices"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| parse(v) as u16)
            .collect();
        assert_eq!(block.indices.as_slice(), expected, "{component}");
        assert!(!block.indices.contains(&0x9f));
        count += 1;
    }
    assert_eq!(count, 190);
}

#[test]
#[ignore = "requires PIONEER_STARTUP_REFERENCES and PIONEER_NORMAL_CORPUS"]
fn local_argument_domains_match_the_independent_226_image_trace() {
    use pioneer_optical::{
        image::layout::Observation,
        startup::coverage::argument::{self, Domain},
    };
    let audit = std::path::PathBuf::from(std::env::var("PIONEER_STARTUP_REFERENCES").unwrap());
    let corpus = std::path::PathBuf::from(std::env::var("PIONEER_NORMAL_CORPUS").unwrap());
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(audit.join("009f-226-argument-dataflow.json")).unwrap(),
    )
    .unwrap();
    let mut images = 0;
    let mut calls = 0;
    for row in manifest["images"].as_array().unwrap() {
        let component = row["component"].as_str().unwrap();
        let raw = std::fs::read(corpus.join(format!("{component}.bin"))).unwrap();
        let Observation::Known(actual) = argument::discover(&raw) else {
            panic!("{component}: unresolved getter")
        };
        for c in row["direct_calls"].as_array().unwrap() {
            let at =
                usize::from_str_radix(c["site"].as_str().unwrap().trim_start_matches("0x"), 16)
                    .unwrap()
                    - 0x410000;
            let found = actual.iter().find(|v| v.call == at).unwrap();
            let expected = &c["argument"];
            let domain = match expected["kind"].as_str().unwrap() {
                "constant" => Domain::Constant(expected["value"].as_u64().unwrap() as u16),
                "zero_extended_dynamic_byte" => Domain::BytePlus {
                    register: expected["register"].as_u64().unwrap() as u8,
                    addend: expected["base"].as_u64().unwrap() as u16,
                },
                "uncovered_dataflow" => Domain::Unresolved {
                    register: expected["register"].as_u64().unwrap() as u8,
                    addend: expected["addend"].as_u64().unwrap() as u16,
                },
                other => panic!("unknown independent domain {other}"),
            };
            assert_eq!(found.domain, domain, "{component} {at:x}");
            assert_eq!(
                found.start,
                at - expected["bytes"].as_str().unwrap().len() / 2,
                "{component} {at:x}"
            );
            calls += 1;
        }
        images += 1;
    }
    assert_eq!(images, 226);
    assert_eq!(
        calls,
        manifest["direct_call_counts"]
            .as_object()
            .unwrap()
            .values()
            .map(|v| v.as_u64().unwrap() as usize)
            .sum::<usize>()
    );
}

#[test]
#[ignore = "requires PIONEER_STARTUP_REFERENCES and PIONEER_NORMAL_CORPUS"]
fn two_word_functions_and_direct_callers_match_native_audit() {
    use pioneer_optical::{
        image::layout::Observation,
        startup::coverage::{argument::Domain, word_pair, CallKind},
    };
    let audit = std::path::PathBuf::from(std::env::var("PIONEER_STARTUP_REFERENCES").unwrap());
    let corpus = std::path::PathBuf::from(std::env::var("PIONEER_NORMAL_CORPUS").unwrap());
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(audit.join("009f-226-argument-dataflow.json")).unwrap(),
    )
    .unwrap();
    let offset = |v: &serde_json::Value| {
        usize::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap() - 0x410000
    };
    let mut images = 0;
    let mut blocks = 0;
    for row in manifest["images"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["argument_register"] == 0)
    {
        let component = row["component"].as_str().unwrap();
        let raw = std::fs::read(corpus.join(format!("{component}.bin"))).unwrap();
        let Observation::Known(actual) = word_pair::discover(&raw) else {
            panic!("{component}: unresolved")
        };
        let expected = row["two_word_wrappers"].as_array().unwrap();
        assert_eq!(actual.len(), expected.len(), "{component}");
        for w in expected {
            let found = actual
                .iter()
                .find(|b| b.offset == offset(&w["entry"]))
                .unwrap();
            assert_eq!(found.formatter, found.offset + 62);
            let calls: Vec<_> = found
                .callers
                .iter()
                .filter(|c| c.kind == CallKind::Absolute)
                .collect();
            let expected_calls = w["callers"].as_array().unwrap();
            assert_eq!(calls.len(), expected_calls.len(), "{component}");
            for (a, b) in calls.iter().zip(expected_calls) {
                assert_eq!(a.offset, offset(&b["site"]));
                let v = b["argument"]["value"]
                    .as_u64()
                    .expect("audited callers have constant indices") as u16;
                assert_eq!(a.first_index, Domain::Constant(v));
                assert!(![v, v.wrapping_add(1)].contains(&0x9f));
            }
        }
        blocks += actual.len();
        images += 1;
    }
    assert_eq!((images, blocks), (190, 344));
}

#[test]
#[ignore = "requires PIONEER_STARTUP_REFERENCES and PIONEER_NORMAL_CORPUS"]
fn packed_high_word_helpers_match_all_audited_callers() {
    use pioneer_optical::{image::layout::Observation, startup::coverage::packed};
    let audit = std::path::PathBuf::from(std::env::var("PIONEER_STARTUP_REFERENCES").unwrap());
    let corpus = std::path::PathBuf::from(std::env::var("PIONEER_NORMAL_CORPUS").unwrap());
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(audit.join("009f-r0-packed-helper-proof.json")).unwrap(),
    )
    .unwrap();
    let parse = |v: &serde_json::Value| {
        usize::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
    };
    let mut count = 0;
    let mut callers = 0;
    for row in manifest["images"].as_array().unwrap() {
        let component = row["component"].as_str().unwrap();
        let raw = std::fs::read(corpus.join(format!("{component}.bin"))).unwrap();
        let Observation::Known(blocks) = packed::discover(&raw) else {
            panic!("{component}: unresolved")
        };
        assert_eq!(blocks.len(), 1);
        let block = &blocks[0];
        assert_eq!(block.offset, parse(&row["entry"]) - 0x410000);
        assert_eq!(block.getter_call, parse(&row["getter_site"]) - 0x410000);
        assert!(block.other_references.is_empty());
        let expected = row["callers"].as_array().unwrap();
        assert_eq!(block.callers.len(), expected.len());
        for (a, b) in block.callers.iter().zip(expected) {
            assert_eq!(a.offset, parse(&b["site"]) - 0x410000);
            assert_eq!(
                a.words,
                Some((parse(&b["index"]) as u16, parse(&b["low_word"]) as u16))
            );
            callers += 1;
        }
        count += 1;
    }
    assert_eq!((count, callers), (6, 18));
}

#[test]
#[ignore = "requires PIONEER_STARTUP_REFERENCES and PIONEER_NORMAL_CORPUS"]
fn bulk_cache_and_accessor_bindings_match_all_226_images() {
    use pioneer_optical::{image::layout::Observation, startup::coverage::cache};
    let audit = std::path::PathBuf::from(std::env::var("PIONEER_STARTUP_REFERENCES").unwrap());
    let corpus = std::path::PathBuf::from(std::env::var("PIONEER_NORMAL_CORPUS").unwrap());
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(audit.join("009f-226-bulk-read-proof.json")).unwrap(),
    )
    .unwrap();
    let accessors: serde_json::Value =
        serde_json::from_slice(&std::fs::read(audit.join("009f-cache-consumers.json")).unwrap())
            .unwrap();
    let parse = |v: &serde_json::Value| {
        usize::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
    };
    let mut count = 0;
    for row in manifest["images"].as_array().unwrap() {
        let component = row["component"].as_str().unwrap();
        let raw = std::fs::read(corpus.join(format!("{component}.bin"))).unwrap();
        let Observation::Known(blocks) = cache::discover(&raw) else {
            panic!("{component}: unresolved")
        };
        assert_eq!(blocks.len(), 1, "{component}");
        let block = &blocks[0];
        assert_eq!(block.offset, parse(&row["loop"]) - 0x410000);
        assert_eq!(block.ram_base, parse(&row["ram_base"]) as u32);
        assert_eq!(
            block.ram_base + 126,
            parse(&row["parameter009F_cache_addresses"][0]) as u32
        );
        assert_eq!(
            block.ram_base + 127,
            parse(&row["parameter009F_cache_addresses"][1]) as u32
        );
        let expected = &accessors["images"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["component"] == component)
            .unwrap()["accessor"];
        assert_eq!(block.accessors.len(), 1, "{component}");
        assert_eq!(
            block.accessors[0].offset,
            parse(&expected["entry"]) - 0x410000
        );
        assert_eq!(
            block.accessors[0].argument_register,
            expected["argument_register"].as_u64().unwrap() as u8
        );
        count += 1;
    }
    assert_eq!(count, 226);
}

#[test]
#[ignore = "requires PIONEER_STARTUP_REFERENCES and PIONEER_NORMAL_CORPUS"]
fn indirect_cache_domains_match_all_native_control_flow_traces() {
    use pioneer_optical::{image::layout::Observation, startup::coverage::cache_flow};
    let audit = std::path::PathBuf::from(std::env::var("PIONEER_STARTUP_REFERENCES").unwrap());
    let corpus = std::path::PathBuf::from(std::env::var("PIONEER_NORMAL_CORPUS").unwrap());
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(audit.join("009f-r0-indirect-bound.json")).unwrap())
            .unwrap();
    let offset =
        |s: &str| usize::from_str_radix(s.trim_start_matches("0x"), 16).unwrap() - 0x410000;
    let mut images = 0;
    let mut functions = 0;
    let mut calls = 0;
    for row in manifest["images"].as_array().unwrap() {
        let component = row["component"].as_str().unwrap();
        let raw = std::fs::read(corpus.join(format!("{component}.bin"))).unwrap();
        let Observation::Known(evidence) = cache_flow::discover(&raw) else {
            panic!("{component}: unresolved")
        };
        assert_eq!(evidence.len(), 1);
        let found = &evidence[0];
        assert_eq!(
            found.uncovered.len(),
            row["non_mov_references"].as_array().unwrap().len(),
            "{component}: uncovered references {:?}",
            found.uncovered
        );
        let expected = row["functions"].as_array().unwrap();
        assert_eq!(found.functions.len(), expected.len(), "{component}");
        for e in expected {
            let f = found
                .functions
                .iter()
                .find(|f| f.start == offset(e["entry"].as_str().unwrap()))
                .unwrap();
            assert!(
                f.issues.is_empty(),
                "{component} {:x}: {:?}",
                f.start,
                f.issues
            );
            assert_eq!(f.end, offset(e["end"].as_str().unwrap()));
            let expected_calls = e["calls"].as_object().unwrap();
            assert_eq!(f.calls.len(), expected_calls.len());
            for c in &f.calls {
                let values = expected_calls
                    .get(&format!("0x{:x}", c.offset + 0x410000))
                    .unwrap();
                let v: Vec<_> = values
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|n| Some(n.as_u64().unwrap() as u8))
                    .collect();
                assert_eq!(c.indices, v, "{component} {:x}", c.offset);
                assert!(!c.indices.contains(&Some(126)));
                assert!(!c.indices.contains(&Some(127)));
                calls += 1;
            }
            let visited: Vec<_> = e["visited"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| offset(v.as_str().unwrap()))
                .collect();
            assert_eq!(f.visited, visited, "{component} {:x}", f.start);
            functions += 1;
        }
        images += 1;
    }
    assert_eq!((images, functions, calls), (190, 927, 6288));
}

#[test]
#[ignore = "requires PIONEER_NORMAL_CORPUS"]
fn native_cache_flow_mutations_expose_009f_and_changed_preservation() {
    use pioneer_optical::{image::layout::Observation, startup::coverage::cache_flow};
    let corpus = std::path::PathBuf::from(std::env::var("PIONEER_NORMAL_CORPUS").unwrap());
    let mut raw = std::fs::read(
        corpus.join("10074482e4e69b0ecaae472a89b17072e817dc3c6df43e1f6ce35afaf7bab325.bin"),
    )
    .unwrap();
    let at = 0x54e7de - 0x410000;
    assert_eq!(raw[at..at + 4], [0xf8, 0x78, 0x7a, 5]);
    raw[at + 1] = 0x7e;
    let Observation::Known(found) = cache_flow::discover(&raw) else {
        panic!("bound accessor")
    };
    assert!(found
        .iter()
        .flat_map(|e| &e.functions)
        .flat_map(|f| &f.calls)
        .any(|c| c.indices.contains(&Some(126))));
    let mut raw = std::fs::read(
        corpus.join("a2b16fd06c10030faa5998605411e642f2b3f8c6371a6e7f1ac6fb4a1280d6f8.bin"),
    )
    .unwrap();
    assert_eq!(raw[0x557656 - 0x410000], 1);
    raw[0x557656 - 0x410000] = 0;
    let Observation::Known(found) = cache_flow::discover(&raw) else {
        panic!("bound accessor")
    };
    let f = found
        .iter()
        .flat_map(|e| &e.functions)
        .find(|f| f.start == 0x5572fe - 0x410000)
        .unwrap();
    assert!(!f.issues.is_empty());
}

#[test]
#[ignore = "requires PIONEER_STARTUP_REFERENCES and PIONEER_NORMAL_CORPUS"]
fn direct_cache_call_coverage_retains_every_audited_site() {
    use pioneer_optical::{
        image::layout::Observation,
        startup::coverage::cache_flow::{self, Reference},
    };
    let audit = std::path::PathBuf::from(std::env::var("PIONEER_STARTUP_REFERENCES").unwrap());
    let corpus = std::path::PathBuf::from(std::env::var("PIONEER_NORMAL_CORPUS").unwrap());
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(audit.join("009f-cache-consumers.json")).unwrap())
            .unwrap();
    let mut totals = [0usize; 5];
    let mut report = Vec::new();
    for row in manifest["images"].as_array().unwrap() {
        let component = row["component"].as_str().unwrap();
        let raw = std::fs::read(corpus.join(format!("{component}.bin"))).unwrap();
        let Observation::Known(found) = cache_flow::discover_direct(&raw) else {
            panic!("{component}: unresolved")
        };
        assert_eq!(found.len(), 1);
        let found = &found[0];
        report.push(serde_json::json!({
            "component":component,
            "uncovered":found.uncovered.iter().map(|r|format!("{r:?}")).collect::<Vec<_>>(),
            "functions":found.functions.iter().map(|f|serde_json::json!({
                "start":f.start,"end":f.end,
                "issues":f.issues.iter().map(|i|format!("{i:?}")).collect::<Vec<_>>(),
                "calls":f.calls.iter().map(|c|serde_json::json!({"offset":c.offset,"indices":c.indices})).collect::<Vec<_>>()
            })).collect::<Vec<_>>()
        }));
        for call in row["accessor"]["calls"].as_array().unwrap() {
            let at =
                usize::from_str_radix(call["site"].as_str().unwrap().trim_start_matches("0x"), 16)
                    .unwrap()
                    - 0x410000;
            totals[0] += 1;
            if found.uncovered.contains(&Reference::Stored(at + 1)) {
                totals[1] += 1;
                continue;
            }
            let f = found
                .functions
                .iter()
                .find(|f| at >= f.start && at < f.end)
                .expect("every site retains a boundary or an uncovered reference");
            if !f.issues.is_empty() {
                totals[2] += 1;
                continue;
            }
            let c = f
                .calls
                .iter()
                .find(|c| c.offset == at)
                .expect("bound direct call must be reachable or explicitly unresolved");
            if c.indices.contains(&None) {
                totals[3] += 1;
            } else {
                totals[4] += 1;
            }
            if let Some(value) = call["immediate_byte_offset"].as_u64() {
                assert!(c.indices.contains(&Some(value as u8)), "{component} {at:x}");
            }
        }
    }
    eprintln!("direct cache calls: total / missing boundary / CFG issue / unknown index / known index = {totals:?}");
    if let Ok(path) = std::env::var("PIONEER_CACHE_DIRECT_REPORT") {
        std::fs::write(
            path,
            serde_json::to_vec_pretty(&serde_json::json!({"counts":totals,"images":report}))
                .unwrap(),
        )
        .unwrap();
    }
    assert_eq!(totals[0], 1578);
    assert_eq!(totals[0], totals[1..].iter().sum::<usize>());
}

#[test]
#[ignore = "requires PIONEER_STARTUP_REFERENCES and PIONEER_NORMAL_CORPUS"]
fn r0_cache_helpers_bind_all_byte_and_pair_caller_inputs() {
    use pioneer_optical::{
        image::layout::Observation,
        startup::coverage::{
            cache_helpers::{self, Kind},
            CallKind,
        },
    };
    let audit = std::path::PathBuf::from(std::env::var("PIONEER_STARTUP_REFERENCES").unwrap());
    let corpus = std::path::PathBuf::from(std::env::var("PIONEER_NORMAL_CORPUS").unwrap());
    let pairs: serde_json::Value = serde_json::from_slice(
        &std::fs::read(audit.join("009f-cache-pair-consumer-proof.json")).unwrap(),
    )
    .unwrap();
    let bytes: serde_json::Value = serde_json::from_slice(
        &std::fs::read(audit.join("009f-cache-byte-consumer-proof.json")).unwrap(),
    )
    .unwrap();
    let offset = |v: &serde_json::Value| {
        usize::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap() - 0x410000
    };
    let mut counts = [0; 4];
    for row in pairs["images"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["pair_wrapper"]["argument_register"] == 0)
    {
        let component = row["component"].as_str().unwrap();
        let raw = std::fs::read(corpus.join(format!("{component}.bin"))).unwrap();
        let Observation::Known(found) = cache_helpers::discover(&raw) else {
            panic!("{component}: unresolved")
        };
        let bs = bytes["images"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["component"] == component)
            .unwrap()["byte_wrappers"]
            .as_array()
            .unwrap();
        assert_eq!(found.len(), 1 + bs.len(), "{component}");
        for (kind, w) in std::iter::once((Kind::Pair, &row["pair_wrapper"]))
            .chain(bs.iter().map(|w| (Kind::Byte, w)))
        {
            let helper = found
                .iter()
                .find(|h| h.offset == offset(&w["entry"]))
                .unwrap();
            assert_eq!(helper.kind, kind);
            assert!(helper.other_references.is_empty());
            let expected = w[if kind == Kind::Pair {
                "callers"
            } else {
                "clients"
            }]
            .as_array()
            .unwrap();
            let callers: Vec<_> = helper
                .callers
                .iter()
                .filter(|c| c.kind == CallKind::Absolute)
                .collect();
            assert_eq!(callers.len(), expected.len());
            for (a, b) in callers.iter().zip(expected) {
                assert_eq!(a.offset, offset(&b["site"]));
                let indices: Vec<_> = if kind == Kind::Pair {
                    b["offsets"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|n| n.as_u64().unwrap() as u8)
                        .collect()
                } else {
                    vec![b["offset"].as_u64().unwrap() as u8]
                };
                assert_eq!(a.indices, Some(indices));
                counts[3] += 1;
            }
            counts[if kind == Kind::Pair { 1 } else { 2 }] += 1;
        }
        counts[0] += 1;
    }
    assert_eq!(counts, [190, 190, 183, 1490]);
}

#[test]
#[ignore = "requires PIONEER_STARTUP_REFERENCES and PIONEER_NORMAL_CORPUS"]
fn rom_cache_helpers_bind_tables_selectors_and_preserving_validators() {
    use pioneer_optical::{
        image::layout::Observation,
        startup::coverage::{cache_rom, CallKind},
    };
    let audit = std::path::PathBuf::from(std::env::var("PIONEER_STARTUP_REFERENCES").unwrap());
    let corpus = std::path::PathBuf::from(std::env::var("PIONEER_NORMAL_CORPUS").unwrap());
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(audit.join("009f-cache-table-consumer-proof.json")).unwrap(),
    )
    .unwrap();
    let offset = |v: &serde_json::Value| {
        usize::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap() - 0x410000
    };
    let mut counts = [0; 3];
    for row in manifest["images"].as_array().unwrap() {
        let component = row["component"].as_str().unwrap();
        let raw = std::fs::read(corpus.join(format!("{component}.bin"))).unwrap();
        let Observation::Known(found) = cache_rom::discover(&raw) else {
            panic!("{component}: unresolved")
        };
        let expected = row["helpers"].as_array().unwrap();
        assert_eq!(found.len(), expected.len(), "{component}");
        for e in expected {
            let h = found
                .iter()
                .find(|h| h.offset == offset(&e["helper"]))
                .unwrap();
            assert_eq!(h.table_offset, offset(&e["ROM"]));
            let values: Vec<_> = e["offsets"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_u64().unwrap() as u8)
                .collect();
            assert_eq!(h.first_indices.as_slice(), values);
            let calls: Vec<_> = h
                .callers
                .iter()
                .filter(|c| c.kind == CallKind::Absolute)
                .collect();
            let expected = e["callers"].as_array().unwrap();
            assert_eq!(calls.len(), expected.len());
            for (a, b) in calls.iter().zip(expected) {
                assert_eq!(a.offset, offset(&b["site"]));
                assert!(a.modes.is_some(), "{component} {:x}", a.offset);
                let indices = h
                    .indices_for(a)
                    .expect("proven selector resolves ROM indices");
                assert!(!indices.contains(&126) && !indices.contains(&127));
                counts[2] += 1;
            }
            counts[1] += 1;
        }
        counts[0] += 1;
    }
    assert_eq!(counts, [190, 190, 215]);
}

#[test]
#[ignore = "requires PIONEER_STARTUP_REFERENCES, PIONEER_LAYOUT_AUDIT and PIONEER_NORMAL_CORPUS"]
fn r1_pair_initializers_constructors_and_callers_match_native_graphs() {
    use pioneer_optical::{
        image::layout::Observation,
        startup::coverage::{r1_pair, CallKind},
    };
    let audit = std::path::PathBuf::from(std::env::var("PIONEER_STARTUP_REFERENCES").unwrap());
    let layout = std::path::PathBuf::from(std::env::var("PIONEER_LAYOUT_AUDIT").unwrap());
    let corpus = std::path::PathBuf::from(std::env::var("PIONEER_NORMAL_CORPUS").unwrap());
    let deps: serde_json::Value = serde_json::from_slice(
        &std::fs::read(layout.join("startup-r1-pair-initializers.json")).unwrap(),
    )
    .unwrap();
    let callers: serde_json::Value = serde_json::from_slice(
        &std::fs::read(audit.join("009f-cache-pair-consumer-proof.json")).unwrap(),
    )
    .unwrap();
    let offset = |v: &serde_json::Value| {
        usize::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap() - 0x410000
    };
    let mut counts = [0; 2];
    for row in deps["images"].as_array().unwrap() {
        let component = row["component"].as_str().unwrap();
        let raw = std::fs::read(corpus.join(format!("{component}.bin"))).unwrap();
        let Observation::Known(found) = r1_pair::discover(&raw) else {
            panic!("{component}: unresolved")
        };
        assert_eq!(found.len(), 1, "{component}");
        let g = &found[0];
        assert_eq!(
            (g.offset, g.initializer, g.constructor),
            (
                offset(&row["wrapper"]),
                offset(&row["initializer"]),
                offset(&row["constructor"])
            )
        );
        assert_eq!(g.flag + 2, g.object);
        assert_eq!(
            g.external_calls[0] as usize,
            offset(&row["constructor_calls"][0]["target"]) + 0x410000
        );
        assert_eq!(
            g.external_calls[1] as usize,
            offset(&row["constructor_calls"][10]["target"]) + 0x410000
        );
        let expected = &callers["images"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["component"] == component)
            .unwrap()["pair_wrapper"]["callers"];
        let actual: Vec<_> = g
            .callers
            .iter()
            .filter(|c| c.kind == CallKind::Absolute)
            .collect();
        assert_eq!(actual.len(), expected.as_array().unwrap().len());
        for (a, b) in actual.iter().zip(expected.as_array().unwrap()) {
            assert_eq!(a.offset, offset(&b["site"]));
            let values = b["offsets"].as_array().unwrap();
            assert_eq!(
                a.indices,
                Some([
                    values[0].as_u64().unwrap() as u8,
                    values[1].as_u64().unwrap() as u8
                ])
            );
            counts[1] += 1;
        }
        counts[0] += 1;
    }
    assert_eq!(counts, [36, 144]);
}

#[test]
#[ignore = "requires PIONEER_STARTUP_REFERENCES and PIONEER_NORMAL_CORPUS"]
fn combined_direct_cache_indices_resolve_all_1578_audited_calls() {
    use pioneer_optical::{image::layout::Observation, startup::coverage::cache_indices};
    let audit = std::path::PathBuf::from(std::env::var("PIONEER_STARTUP_REFERENCES").unwrap());
    let corpus = std::path::PathBuf::from(std::env::var("PIONEER_NORMAL_CORPUS").unwrap());
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(audit.join("009f-cache-consumers.json")).unwrap())
            .unwrap();
    let mut count = 0;
    for row in manifest["images"].as_array().unwrap() {
        let component = row["component"].as_str().unwrap();
        let raw = std::fs::read(corpus.join(format!("{component}.bin"))).unwrap();
        let Observation::Known(found) = cache_indices::discover(&raw) else {
            panic!("{component}: unresolved")
        };
        for call in row["accessor"]["calls"].as_array().unwrap() {
            let offset =
                usize::from_str_radix(call["site"].as_str().unwrap().trim_start_matches("0x"), 16)
                    .unwrap()
                    - 0x410000;
            let c = found
                .calls
                .iter()
                .find(|c| c.offset == offset)
                .expect("held direct call has coverage");
            let values = c
                .indices
                .as_ref()
                .unwrap_or_else(|| panic!("{component} {offset:x}: unknown index"));
            assert!(!values.is_empty());
            assert!(
                !values.contains(&126) && !values.contains(&127),
                "{component} {offset:x}: {values:?}"
            );
            count += 1;
        }
    }
    assert_eq!(count, 1578);
}

#[test]
#[ignore = "requires PIONEER_NORMAL_CORPUS"]
fn combined_cache_coverage_exposes_changed_inputs_and_broken_r1_initializers() {
    use pioneer_optical::{image::layout::Observation, startup::coverage::cache_indices};
    let corpus = std::path::PathBuf::from(std::env::var("PIONEER_NORMAL_CORPUS").unwrap());
    let path = corpus.join("10074482e4e69b0ecaae472a89b17072e817dc3c6df43e1f6ce35afaf7bab325.bin");
    let mut raw = std::fs::read(&path).unwrap();
    let call = 0x54e91a - 0x410000;
    assert_eq!(raw[call - 4..call], [0x79, 0, 0, 40]);
    raw[call - 1] = 126;
    let Observation::Known(found) = cache_indices::discover(&raw) else {
        panic!("native graph")
    };
    assert!(found
        .calls
        .iter()
        .any(|c| c.offset == 0x54ea56 - 0x410000
            && c.indices.as_ref().is_some_and(|v| v.contains(&126))));
    let mut raw = std::fs::read(&path).unwrap();
    assert_eq!(raw[0x5a461c - 0x410000], 116);
    raw[0x5a461c - 0x410000] = 126;
    let Observation::Known(found) = cache_indices::discover(&raw) else {
        panic!("native graph")
    };
    for (pc, byte) in [(0x53f2da, 126), (0x53f2e4, 127)] {
        assert!(found
            .calls
            .iter()
            .any(|c| c.offset == pc - 0x410000
                && c.indices.as_ref().is_some_and(|v| v.contains(&byte))));
    }
    let mut raw = std::fs::read(
        corpus.join("300ac90c29810191d3353413b25a199a816965ad5341e8d756d18fdd46c22e44.bin"),
    )
    .unwrap();
    assert_eq!(raw[0x5e47e6 - 0x410000], 1);
    raw[0x5e47e6 - 0x410000] = 0;
    let Observation::Known(found) = cache_indices::discover(&raw) else {
        panic!("native cache remains bound")
    };
    for pc in [0x5e6318, 0x5e6328] {
        assert!(found
            .calls
            .iter()
            .any(|c| c.offset == pc - 0x410000 && c.indices.is_none()));
    }
}

#[test]
#[ignore = "requires PIONEER_NORMAL_CORPUS"]
fn rom_helper_literal_overlap_requires_the_entire_native_instruction_context() {
    use pioneer_optical::{
        image::layout::Observation,
        startup::coverage::{cache_flow::Reference, cache_rom},
    };
    let corpus = std::path::PathBuf::from(std::env::var("PIONEER_NORMAL_CORPUS").unwrap());
    let mut raw = std::fs::read(
        corpus.join("17c183f6d92592ee80f77b826bba1b70574b40e455dc436a6ebef386bcdf4fbc.bin"),
    )
    .unwrap();
    let at = 0x56726e - 0x410000;
    let Observation::Known(found) = cache_rom::discover(&raw) else {
        panic!("native graph")
    };
    assert_eq!(found[0].instruction_overlaps, vec![at]);
    assert!(found[0].other_references.is_empty());
    for p in at - 8..at {
        raw[p] ^= 1;
        let Observation::Known(found) = cache_rom::discover(&raw) else {
            panic!("native graph")
        };
        assert!(found[0].instruction_overlaps.is_empty());
        assert!(found[0].other_references.contains(&Reference::Stored(at)));
        raw[p] ^= 1;
    }
}

#[test]
#[ignore = "requires PIONEER_NORMAL_CORPUS"]
fn rom_helper_address_inside_stack_increment_is_not_a_pointer() {
    use pioneer_optical::{
        image::layout::Observation,
        startup::coverage::{cache_flow::Reference, cache_rom},
    };
    let corpus = std::path::PathBuf::from(std::env::var("PIONEER_NORMAL_CORPUS").unwrap());
    let mut raw = std::fs::read(
        corpus.join("548e7b371a52f1196b9919c977f08ffbb7c22a3d8fa8e65855924a9259b83cc3.bin"),
    )
    .unwrap();
    let at = 0x506c4c - 0x410000;
    let Observation::Known(found) = cache_rom::discover(&raw) else {
        panic!("native graph")
    };
    assert!(found[0].instruction_overlaps.contains(&at));
    assert!(found[0].other_references.is_empty());
    // Preserve the address literal while independently corrupting every surrounding byte.
    for p in (at - 2..at).chain(at + 4..at + 8) {
        raw[p] ^= 1;
        let Observation::Known(found) = cache_rom::discover(&raw) else {
            panic!("native graph")
        };
        assert!(!found[0].instruction_overlaps.contains(&at));
        assert!(found[0].other_references.contains(&Reference::Stored(at)));
        raw[p] ^= 1;
    }
}
