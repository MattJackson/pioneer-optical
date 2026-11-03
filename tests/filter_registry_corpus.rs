//! Optional native registry parity replay; firmware remains outside the crate.
#![cfg(feature = "envelope")]
use pioneer_optical::{compatibility::Firmware, filters, image::matrix};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
};

#[test]
#[ignore = "requires PIONEER_REGISTRY_STARTUP_AUDIT and PIONEER_STARTUP_CORPUS"]
fn every_platform_reports_every_owner_and_group_changes_have_native_causes() {
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
                let previous = matrix::legacy_discover(hardware, &normal, kernel.as_deref());
                if let Some(identity) = &current {
                    assert_eq!(identity.as_is.entries().len(), findings.iter().filter(|finding| finding.role == filters::Role::Hardware).count());
                    assert!(findings.iter().filter(|finding| finding.role == filters::Role::Hardware).all(|finding| matches!(finding.finding,filters::Finding::Known(_) | filters::Finding::NotApplicable { .. })));
                }
                serde_json::json!({"component":component,"hardware":hardware,"filters":findings,
                    "legacy_as_is":previous.as_ref().and_then(|i|i.as_is.family()).map(|f|f.to_string()),
                    "legacy_candidate":previous.as_ref().and_then(|i|i.candidate.family()).map(|f|f.to_string()),
                    "as_is":current.as_ref().map(|i|format!("{:016x}",i.as_is.fingerprint())),
                    "candidate":current.as_ref().map(|i|format!("{:016x}",i.candidate.fingerprint()))})
            }).collect::<Vec<_>>())
        }).collect();
        for handle in handles {
            output.extend(handle.join().unwrap());
        }
    });
    output.sort_by(|a, b| a["component"].as_str().cmp(&b["component"].as_str()));
    let mut new_to_old = BTreeMap::<String, BTreeSet<String>>::new();
    let mut old_to_new = BTreeMap::<String, BTreeSet<String>>::new();
    for row in &output {
        if let (Some(old), Some(new)) =
            (row["legacy_candidate"].as_str(), row["candidate"].as_str())
        {
            new_to_old.entry(new.into()).or_default().insert(old.into());
            old_to_new.entry(old.into()).or_default().insert(new.into());
        }
    }
    // Retaining additional native facts must never merge old distinct contracts.
    assert!(
        new_to_old.values().all(|previous| previous.len() == 1),
        "new registry merged old hardware contracts"
    );
    let splits: BTreeMap<_, _> = old_to_new
        .into_iter()
        .filter(|(_, values)| values.len() > 1)
        .collect();
    let known = output
        .iter()
        .filter(|row| row["candidate"].is_string())
        .count();
    let report = serde_json::json!({"images":output.len(),"known":known,"unresolved":output.len()-known,"owner_ids":owner_ids,"candidate_splits":splits,"rows":output});
    if let Ok(path) = std::env::var("PIONEER_REGISTRY_REPORT") {
        std::fs::write(path, serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    }
    println!("Registry parity: {} images, {known} complete identities, {} unresolved; {} old groups split with additional native facts",rows.len(),rows.len()-known,report["candidate_splits"].as_object().unwrap().len());
}
