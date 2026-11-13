//! Register projections compared with the independent native audit.
#![cfg(feature = "image")]
#![cfg(feature = "internals")]
use pioneer_optical::image::{
    layout::Observation,
    registers::{self, Startup},
};
#[test]
#[ignore = "requires PIONEER_PHASE_AUDIT and PIONEER_NORMAL_CORPUS"]
fn every_sat_native_register_projection_matches_audit() {
    let audit = std::path::PathBuf::from(std::env::var("PIONEER_PHASE_AUDIT").unwrap());
    let corpus = std::path::PathBuf::from(std::env::var("PIONEER_NORMAL_CORPUS").unwrap());
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(audit.join("register-reextraction.json")).unwrap())
            .unwrap();
    let mut count = 0;
    for row in manifest["images"].as_array().unwrap() {
        let component = row["component"].as_str().unwrap();
        let raw = std::fs::read(corpus.join(format!("{component}.bin"))).unwrap();
        let host = registers::host(&raw);
        let startup = registers::startup(&raw);
        for (field, result) in [
            ("host", host),
            (
                "startup",
                match startup {
                    Observation::Known(Startup::Register(r)) => Observation::Known(r),
                    Observation::Known(Startup::LegacyProgram {
                        initializer,
                        wrapper,
                    }) => {
                        let expected = &row["extracted"]["startup"];
                        assert_eq!(expected["kind"], "legacy_initialization_program");
                        assert_eq!(
                            expected["initializer_offset"].as_u64().unwrap(),
                            initializer as u64
                        );
                        assert_eq!(expected["wrapper_offset"].as_u64().unwrap(), wrapper as u64);
                        count += 1;
                        Observation::Unresolved(
                            pioneer_optical::image::layout::Unresolved::ReaderNotRecognized,
                        )
                    }
                    Observation::Unresolved(r) => Observation::Unresolved(r),
                    Observation::Conflicting => Observation::Conflicting,
                },
            ),
        ] {
            let expected = &row["extracted"][field];
            if expected["kind"] == "legacy_initialization_program" {
                continue;
            }
            match result {
                Observation::Known(value) => {
                    assert_eq!(expected["status"], "recognized", "{component} {field}");
                    assert_eq!(
                        format!("0x{:02X}", value.value),
                        expected["value"].as_str().unwrap(),
                        "{component} {field}"
                    );
                    let mut expected_sites: Vec<_> = expected["sites"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|s| {
                            (
                                s["offset"].as_u64().unwrap() as usize,
                                s["full_u8"].as_u64().unwrap() as u8,
                            )
                        })
                        .collect();
                    expected_sites.sort_unstable();
                    assert_eq!(
                        value
                            .writes
                            .iter()
                            .map(|w| (w.offset, w.value))
                            .collect::<Vec<_>>(),
                        expected_sites,
                        "{component} {field}"
                    );
                }
                Observation::Conflicting => {
                    assert_eq!(expected["status"], "conflicting", "{component} {field}")
                }
                Observation::Unresolved(_) => {
                    assert_eq!(expected["status"], "unrecognized", "{component} {field}")
                }
            }
            count += 1;
        }
    }
    assert_eq!(count, 1060);
}
