//! Role-bound SAT8 physical predicates against the independent native audit.
#![cfg(feature = "image")]
use pioneer_optical::image::{
    inputs::{discover, Encoding, Term},
    layout::Observation,
};
fn terms(v: &serde_json::Value) -> Vec<Term> {
    let values = if let Some(a) = v.as_array() {
        a.iter().collect::<Vec<_>>()
    } else {
        vec![v]
    };
    values
        .into_iter()
        .map(|t| Term {
            address: u32::from_str_radix(t["register"].as_str().unwrap(), 16).unwrap(),
            encoding: if t["address_encoding"] == "absolute16" {
                Encoding::Absolute16
            } else {
                Encoding::Absolute32
            },
            bit: t["bit"].as_u64().unwrap() as u8,
            active: t.get("required").unwrap_or(&t["active"]).as_u64().unwrap() == 1,
        })
        .collect()
}
#[test]
#[ignore = "requires PIONEER_PHASE_AUDIT and PIONEER_NORMAL_CORPUS"]
fn all_sat8_predicates_and_feature_projections_match() {
    let audit = std::path::PathBuf::from(std::env::var("PIONEER_PHASE_AUDIT").unwrap());
    let corpus = std::path::PathBuf::from(std::env::var("PIONEER_NORMAL_CORPUS").unwrap());
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(audit.join("sat8-reextraction.json")).unwrap())
            .unwrap();
    let mut count = 0;
    for row in manifest["results"].as_array().unwrap() {
        let component = row["component"].as_str().unwrap();
        let raw = std::fs::read(corpus.join(format!("{component}.bin"))).unwrap();
        let result = discover(&raw);
        let Observation::Known(pred) = result else {
            panic!("{component}: {result:?}");
        };
        let expected = &row["native_contracts"][0];
        assert_eq!(pred.closed, terms(&expected["closed"]), "{component}");
        assert_eq!(pred.opened, terms(&expected["open"]), "{component}");
        assert_eq!(
            pred.feature_flags(),
            Some(row["projection"].as_u64().unwrap() as u8),
            "{component}"
        );
        count += 1;
    }
    assert_eq!(count, 391);
}
