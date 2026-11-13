//! IRQ/input values and retained observations against the independent audit.
#![cfg(feature = "image")]
#![cfg(feature = "internals")]
use pioneer_optical::image::{
    irq::{discover, Value},
    layout::Observation,
};
fn value(v: Value) -> serde_json::Value {
    match v {
        Value::Controller { and_mask, or_mask } => {
            serde_json::json!(["controller", and_mask, or_mask])
        }
        Value::Input(t) => serde_json::json!(["input", t.address, t.bit, u8::from(t.active)]),
        Value::TrayCloseRoute => serde_json::json!(["route", 0x58, 0x60, 0xfffdff30u32, 1]),
    }
}
#[test]
#[ignore = "requires PIONEER_PHASE_AUDIT and PIONEER_NORMAL_CORPUS"]
fn every_sat_irq_projection_and_supporting_observation_matches() {
    let audit = std::path::PathBuf::from(std::env::var("PIONEER_PHASE_AUDIT").unwrap());
    let corpus = std::path::PathBuf::from(std::env::var("PIONEER_NORMAL_CORPUS").unwrap());
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(audit.join("irq-reextraction.json")).unwrap())
            .unwrap();
    let mut count = 0;
    for row in manifest["results"].as_array().unwrap() {
        let component = row["component"].as_str().unwrap();
        let raw = std::fs::read(corpus.join(format!("{component}.bin"))).unwrap();
        let result = discover(&raw);
        let Observation::Known(selected) = result.selected else {
            panic!("{component}: {result:?}");
        };
        assert_eq!(value(selected), row["expected"], "{component}");
        let actual: std::collections::BTreeSet<_> = result
            .observations
            .into_iter()
            .map(|v| value(v).to_string())
            .collect();
        let expected: std::collections::BTreeSet<_> = row["actual"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.to_string())
            .collect();
        assert_eq!(actual, expected, "{component}");
        count += 1;
    }
    assert_eq!(count, 530);
}
