//! Optional replay of every held image in the existing startup/init audit.
use super::*;
use crate::compatibility::Firmware;
use alloc::collections::BTreeMap;

#[test]
#[ignore = "requires PIONEER_REGISTRY_STARTUP_AUDIT and PIONEER_STARTUP_CORPUS"]
fn all_722_existing_native_startup_and_initialization_facts_are_reported() {
    let audit = std::path::PathBuf::from(std::env::var("PIONEER_REGISTRY_STARTUP_AUDIT").unwrap());
    let corpus = std::path::PathBuf::from(std::env::var("PIONEER_STARTUP_CORPUS").unwrap());
    let data: serde_json::Value = serde_json::from_slice(&std::fs::read(audit).unwrap()).unwrap();
    let rows = data["components"].as_array().unwrap();
    let mut init_counts = [0usize; 3];
    let mut startup_counts = [0usize; 3];
    let mut sat8 = BTreeMap::<Vec<u8>, usize>::new();
    let mut m32c_init = BTreeMap::<Vec<u8>, usize>::new();
    let mut known_startup_tags = BTreeMap::<u16, usize>::new();
    for row in rows {
        let sha = row["component"].as_str().unwrap();
        let hardware = row["hardware"].as_str().unwrap();
        let normal = std::fs::read(corpus.join("normal").join(format!("{sha}.bin"))).unwrap();
        let kernel = row["kernel_component"]
            .as_str()
            .and_then(|k| std::fs::read(corpus.join("kernel").join(format!("{k}.bin"))).ok());
        let context = Context::new(Firmware {
            hardware,
            normal: &normal,
            kernel: kernel.as_deref(),
        });
        let initialization = crate::filters::initialization::inspect(&context);
        match &initialization.finding {
            Finding::Known(value) => {
                init_counts[0] += 1;
                if hardware.starts_with("SAT 8") {
                    *sat8.entry(value.canonical_bytes()).or_default() += 1;
                }
                if row["architecture"] == "M32C" {
                    *m32c_init.entry(value.canonical_bytes()).or_default() += 1;
                }
            }
            Finding::Unresolved(_) => init_counts[1] += 1,
            _ => {
                panic!(
                    "{sha}: unexpected initialization {:?}",
                    initialization.finding
                );
            }
        }
        let prerequisite = inspect(&context);
        match &prerequisite.finding {
            Finding::Known(Value::Variant(tag, fields)) => {
                startup_counts[0] += 1;
                *known_startup_tags.entry(*tag).or_default() += 1;
                if *tag == 10 {
                    assert_eq!(fields, &vec![Value::U16(0xd9), Value::U16(0xffff)], "{sha}");
                }
                if *tag == 1 || *tag == 2 {
                    assert_ne!(
                        fields.get(1),
                        Some(&Value::U16(0xffff)),
                        "{sha}: detector miss became native FFFF"
                    );
                }
            }
            Finding::Unresolved(_) => startup_counts[1] += 1,
            _ => {
                panic!("{sha}: unexpected prerequisite {:?}", prerequisite.finding);
            }
        }
        if !hardware.starts_with("SAT ") {
            assert!(
                selection(&context).unwrap().is_none(),
                "{sha}: non-H8 context acquired H8 A0 action"
            );
        }
    }
    assert_eq!(rows.len(), 722);
    assert_eq!(init_counts, [638, 84, 0]);
    assert_eq!(startup_counts, [218, 504, 0]);
    assert_eq!(
        known_startup_tags,
        BTreeMap::from([(1, 60), (2, 1), (10, 85), (11, 71), (20, 1)])
    );
    let mut sizes: Vec<_> = sat8.values().copied().collect();
    sizes.sort_unstable();
    assert_eq!(sizes, vec![11, 18, 20, 63, 279]);
    let mut sizes: Vec<_> = m32c_init.values().copied().collect();
    sizes.sort_unstable();
    assert_eq!(sizes, vec![1, 13, 85]);
}
