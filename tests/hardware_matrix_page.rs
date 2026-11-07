//! Snapshot of the hardware matrix page generator on a small synthetic set.
//!
//! The model is compared with `tests/fixtures/hardware-matrix-sample.json`.
//! After an intended change, regenerate it with
//! `PIONEER_UPDATE_SNAPSHOTS=1 cargo test --all-features --test hardware_matrix_page`
//! and review the diff.
#![cfg(feature = "envelope")]
#[path = "../examples/hardware_matrix/page.rs"]
mod page;

use pioneer_optical::filters::{self, Assessment, Role, Value};
use serde_json::{json, Value as Json};

fn package(model: &str, hardware: &str, revision: &str, component: &str) -> page::Package {
    page::Package {
        model: model.into(),
        hardware: hardware.into(),
        destination: "GENERAL".into(),
        revision: revision.into(),
        component: component.into(),
        kernel: None,
        path: format!("packages/{model}/{revision}.tar"),
        members: (format!("{component}.enc"), None),
    }
}

fn component(n: u8) -> String {
    format!("{n:02x}").repeat(32)
}

/// Known findings for every registered filter, with one varied value.
fn known(
    component: String,
    hardware: &str,
    phase: u8,
    as_is: &str,
    candidate: &str,
) -> page::Analysis {
    let value = |id: &str| match id {
        "persistent-storage-geometry" => {
            Value::Variant(1, vec![Value::U32(0xfedc_4321), Value::U32(0x10000)])
        }
        "startup-inputs-initialization" => Value::Variant(
            1,
            vec![Value::U16(0xe46b), Value::U8(0x11), Value::U8(0x01)],
        ),
        "host-interface-setup" => Value::Variant(
            1,
            vec![Value::U16(0xfe94), Value::U8(0x80), Value::U8(0x80)],
        ),
        "loading-input-interrupt-setup" => Value::Variant(
            1,
            vec![Value::Variant(
                0,
                vec![Value::U16(0xffc5), Value::U8(0xdf), Value::U8(0)],
            )],
        ),
        "persistent-parameter-layout" => Value::Variant(
            1,
            vec![
                Value::Sequence(vec![Value::Sequence(vec![
                    Value::U32(0x9984),
                    Value::U8(1),
                    Value::Variant(0, vec![]),
                    Value::U32(320),
                    Value::U16(20),
                    Value::U16(40),
                    Value::U8(0),
                ])]),
                Value::U8(0),
                Value::Sequence(vec![]),
            ],
        ),
        "phase" => Value::Variant(
            1,
            vec![
                Value::U8(0),
                Value::Variant(
                    1,
                    vec![
                        Value::U16(0xf910),
                        Value::U16(0xf911),
                        Value::U16(0xf912),
                        Value::U16(0xf913),
                    ],
                ),
                Value::U8(phase),
            ],
        ),
        _ => Value::Variant(1, vec![Value::U16(0x9f), Value::U16(0xffff)]),
    };
    page::Analysis {
        component,
        hardware: hardware.into(),
        as_is: Some(as_is.into()),
        candidate: Some(candidate.into()),
        filters: filters::filters()
            .iter()
            .map(|f| {
                let role = f.rules().unwrap().role;
                Assessment::known(f.id(), role, value(f.id()), "synthetic native evidence")
            })
            .collect(),
    }
}

fn sample() -> Json {
    let blank = vec![0xff; 0x400];
    let mut packages = Vec::new();
    let mut analyses = Vec::new();
    // Real registry runs on synthetic bytes: every finding stays unresolved.
    for (n, model, hardware) in [
        (1, "BDR-UD04", "SAT 8600"),
        (2, "BDR-211M", "SAT 1050"),
        (3, "DVR-105", "ATA 0004"),
        (4, "DVR-SCSI", "SCSI0001"),
        (5, "OTHER", "XYZ 0001"),
    ] {
        packages.push(package(model, hardware, "1.00", &component(n)));
        analyses.push(page::analyze(&page::Image {
            component: component(n),
            hardware: hardware.into(),
            normal: &blank,
            kernel: None,
        }));
    }
    // Synthetic established identities exercise families and labels.
    for (n, model, hardware, phase, as_is) in [
        (6, "BDR-UD03", "SAT 8800", 0, "00000000000000a0"),
        (7, "BDR-UD02D", "SAT 8301", 1, "00000000000000a1"),
        (8, "BDR-212U", "SAT 8301", 0, "00000000000000a0"),
    ] {
        packages.push(package(model, hardware, "1.00", &component(n)));
        analyses.push(known(
            component(n),
            hardware,
            phase,
            as_is,
            "00000000000000c0",
        ));
    }
    packages.push(package("BDR-UD03", "SAT 8800", "1.01", &component(6)));
    let mut conflicting = known(
        component(9),
        "SAT 8600",
        0,
        "00000000000000b0",
        "00000000000000b0",
    );
    conflicting.filters[1] = Assessment::conflicting(
        "startup-inputs-initialization",
        Role::Hardware,
        "two native programs disagree",
    );
    conflicting.as_is = None;
    conflicting.candidate = None;
    packages.push(package("BDR-213U", "SAT 8600", "1.00", &component(9)));
    analyses.push(conflicting);
    packages.push(package("BROKEN", "ATA 0003", "1.31", &component(10)));
    let failures = vec![page::Failure {
        component: component(10),
        path: "packages/BROKEN/1.31.tar".into(),
        error: "unsupported firmware envelope layout".into(),
    }];
    let source = page::Source {
        crate_version: "0.0.0-test".into(),
        revision: "0000000".into(),
        hoard: "sha256:test".into(),
    };
    let routes = json!({
        "format": "freemkv-crossflash-routes",
        "version": 1,
        "routes": [{"from": "BDR-UD04 1.00", "to": "BDR-UD03 1.01", "status": "untested",
                    "steps": ["</script><script>alert(1)</script>"], "evidence": []}]
    });
    // Input order must not matter.
    packages.reverse();
    analyses.reverse();
    page::data(&packages, &analyses, &failures, &source, Some(&routes)).unwrap()
}

#[test]
fn generator_model_matches_the_committed_snapshot() {
    let data = sample();
    let text = serde_json::to_string_pretty(&data).unwrap() + "\n";
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/hardware-matrix-sample.json"
    );
    if std::env::var_os("PIONEER_UPDATE_SNAPSHOTS").is_some() {
        std::fs::write(path, &text).unwrap();
    }
    let expected = std::fs::read_to_string(path).expect("snapshot; see module docs");
    assert!(
        text == expected,
        "page model changed; see module docs to regenerate"
    );
}

#[test]
fn page_is_deterministic_self_contained_and_escapes_script_text() {
    let data = sample();
    let html = page::render(&data);
    assert_eq!(html, page::render(&sample()));
    assert!(!html.contains("__MATRIX_DATA__"));
    assert!(!html.contains("alert(1)</script>"));
    assert!(!html.contains("src=\"http") && !html.contains("<link"));
    let start = html
        .find(r#"<script id="matrix-data" type="application/json">"#)
        .unwrap();
    let body = &html[start..];
    let body = &body[body.find('>').unwrap() + 1..body.find("</script>").unwrap()];
    let embedded: Json = serde_json::from_str(body).unwrap();
    assert_eq!(embedded, data);
    // Presentation preserves the exact native findings and supplied route payload.
    assert_eq!(embedded["images"], data["images"]);
    assert_eq!(embedded["routes"], data["routes"]);
    assert_eq!(html.matches("<section id=\"definitions\"").count(), 1);
    assert!(html.contains("<section id=\"groups\""));
    assert!(html.contains("f?.inspection?.label||f?.summary||findingState(f)"));
    assert!(html.contains("function inspectionDetails(f)"));
    assert!(html.contains("const anchor=t.startsWith('definition-')?t:null"));
}

#[test]
fn every_rule_statement_comes_from_code_not_the_template() {
    let data = sample();
    let filters = data["filters"].as_array().unwrap();
    assert_eq!(filters.len(), filters::filters().len());
    for (f, owner) in filters.iter().zip(filters::filters()) {
        let rules = owner.rules().unwrap();
        assert_eq!(f["id"], owner.id());
        assert_eq!(f["description"], rules.description);
        assert_eq!(f["correction"], rules.correction);
        // The template names no filter and states no rule of its own.
        for quoted in [format!("'{}'", owner.id()), format!("\"{}\"", owner.id())] {
            assert!(!page::TEMPLATE.contains(&quoted), "{quoted}");
        }
        assert!(!page::TEMPLATE.contains(rules.correction));
        assert!(!page::TEMPLATE.contains(rules.description));
    }
    // The one Definitions renderer owns these fields; value and comparison rows link to it.
    for field in ["esc(o.description)", "esc(o.correction)", "o.policies.map"] {
        assert_eq!(page::TEMPLATE.matches(field).count(), 1, "{field}");
    }
    for rule in pioneer_optical::filters::identity::RULES {
        assert!(!page::TEMPLATE.contains(rule));
    }
}

#[test]
fn unresolved_images_carry_reasons_and_no_family() {
    let data = sample();
    for image in data["images"].as_array().unwrap() {
        let unresolved = image["unresolved"].as_array().unwrap();
        assert_eq!(image["candidate"].is_null(), !unresolved.is_empty());
        for id in unresolved {
            let finding = image["filters"]
                .as_array()
                .unwrap()
                .iter()
                .find(|f| f["id"] == *id)
                .unwrap();
            assert!(matches!(
                finding["state"].as_str(),
                Some("Unresolved" | "Conflicting")
            ));
            assert!(finding["label"].as_str().unwrap().len() > "Unresolved: ".len());
        }
    }
    assert_eq!(data["summary"]["failures"].as_array().unwrap().len(), 1);
    assert_eq!(
        data["summary"]["phase_normalized"]["00000000000000c0"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn malformed_route_exports_are_refused() {
    for bad in [json!([]), json!({"routes": {}}), json!({"routes": [1]})] {
        assert!(page::check_routes(&bad).is_err());
    }
    assert!(page::check_routes(&json!({"routes": []})).is_ok());
}
