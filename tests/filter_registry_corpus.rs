//! Optional native registry parity replay; firmware remains outside the crate.
#![cfg(feature = "envelope")]
use pioneer_optical::{compatibility::Firmware, filters};
use std::path::PathBuf;

#[test]
#[ignore = "requires PIONEER_REGISTRY_STARTUP_AUDIT and PIONEER_STARTUP_CORPUS"]
fn every_platform_reports_every_owner() {
    let manifest = PathBuf::from(std::env::var("PIONEER_REGISTRY_STARTUP_AUDIT").unwrap());
    let corpus = PathBuf::from(std::env::var("PIONEER_STARTUP_CORPUS").unwrap());
    let audit: serde_json::Value =
        serde_json::from_slice(&std::fs::read(manifest).unwrap()).unwrap();
    let rows = audit["components"].as_array().unwrap();
    assert_eq!(rows.len(), 722);
    assert_eq!(
        rows.iter()
            .filter(
                |row| row["startup_prerequisite_fact"]["requirement"]["parameter"] == "0x00D9"
                    && row["startup_prerequisite_fact"]["requirement"]["accepted"] == "0xFFFF"
            )
            .count(),
        85,
        "independent native D9 cohort changed"
    );
    let owner_ids: Vec<_> = filters::filters().iter().map(|owner| owner.id()).collect();
    let mut output = Vec::new();
    // Independent images can be inspected in bounded parallel chunks.
    std::thread::scope(|scope| {
        let handles: Vec<_> = rows.chunks(rows.len().div_ceil(8)).map(|chunk| {
            let corpus = &corpus;
            let owner_ids = &owner_ids;
            scope.spawn(move || chunk.iter().map(|row| {
                let component = row["component"].as_str().unwrap();
                let hardware = row["hardware"].as_str().unwrap();
                let normal = std::fs::read(corpus.join("normal").join(format!("{component}.bin"))).unwrap();
                let kernel = row["kernel_component"].as_str().map(|sha|
                    std::fs::read(corpus.join("kernel").join(format!("{sha}.bin"))).unwrap());
                let context = filters::Context::new(Firmware { hardware, normal: &normal, kernel: kernel.as_deref() });
                let findings = context.filters();
                assert_eq!(findings.iter().map(|finding| finding.id).collect::<Vec<_>>(), *owner_ids, "{component}: missing owner");
                if row["startup_prerequisite_fact"]["kind"] == "architecture_native_requirement"
                    && row["startup_prerequisite_fact"]["requirement"]["parameter"] == "0x00D9"
                    && row["startup_prerequisite_fact"]["requirement"]["accepted"] == "0xFFFF" {
                    let startup = findings.iter().find(|finding| finding.id == "startup-prerequisite").unwrap();
                    assert!(matches!(&startup.finding, filters::Finding::Known(filters::Value::Variant(10, fields))
                        if fields == &vec![filters::Value::U16(0xd9), filters::Value::U16(0xffff)]),
                        "{component}: independent native D9=FFFF requirement was not recognized: {:?}",startup.finding);
                }
                let current = filters::identity::discover(&context);
                if let Some(identity) = &current {
                    assert_eq!(identity.as_is.entries().len(), findings.iter().filter(|finding| finding.role == filters::Role::Hardware).count());
                    assert!(findings.iter().filter(|finding| finding.role == filters::Role::Hardware).all(|finding| matches!(finding.finding,filters::Finding::Known(_) | filters::Finding::NotApplicable { .. })));
                }
                serde_json::json!({"component":component,"hardware":hardware,"filters":findings,
                    "as_is":current.as_ref().map(|i|format!("{:016x}",i.as_is.fingerprint())),
                    "candidate":current.as_ref().map(|i|format!("{:016x}",i.candidate.fingerprint()))})
            }).collect::<Vec<_>>())
        }).collect();
        for handle in handles {
            output.extend(handle.join().unwrap());
        }
    });
    output.sort_by(|a, b| a["component"].as_str().cmp(&b["component"].as_str()));
    let known = output
        .iter()
        .filter(|row| row["candidate"].is_string())
        .count();
    let report = serde_json::json!({"images":output.len(),"known":known,"unresolved":output.len()-known,"owner_ids":owner_ids,"rows":output});
    if let Ok(path) = std::env::var("PIONEER_REGISTRY_REPORT") {
        std::fs::write(path, serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    }
    println!(
        "Registry parity: {} images, {known} complete identities, {} unresolved",
        rows.len(),
        rows.len() - known
    );
}
