//! Exact held-image phase mapping, separate from cross-interface or flash admission.
#![cfg(feature = "envelope")]

use pioneer_optical::{
    compatibility::{Correction, Error, Firmware},
    envelope::Envelope,
    filters::{
        self,
        phase::{
            self,
            native::{self, Assignment},
        },
        Filter,
    },
    image::layout::Observation,
};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, path::Path};

#[derive(Deserialize)]
struct Inventory {
    schema: u32,
    domains: Vec<Domain>,
}
#[derive(Deserialize)]
struct Domain {
    id: String,
    image_count: usize,
    records: Vec<Record>,
}
#[derive(Deserialize)]
struct Record {
    normal: String,
    kernel: Option<String>,
    hardware: String,
    phase: serde_json::Value,
}
struct Original {
    normal: Envelope,
    kernel: Option<Envelope>,
}
struct Proof {
    image: Vec<u8>,
}
const REGISTRY: &[&dyn Filter] = &[&phase::FILTER];

fn inventory() -> Inventory {
    serde_json::from_str(include_str!("fixtures/phase-domain-inventory.json")).unwrap()
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn component(root: &Path, hash: &str) -> Vec<u8> {
    let bytes = std::fs::read(root.join(format!("{hash}.enc")))
        .unwrap_or_else(|e| panic!("missing exact corpus component {hash}: {e}"));
    assert_eq!(digest(&bytes), hash, "corpus component integrity");
    bytes
}
fn load(root: &Path, record: &Record) -> Result<Original, String> {
    let kernel = record
        .kernel
        .as_ref()
        .map(|hash| {
            Envelope::load(&component(root, hash)).map_err(|e| format!("Kernel {hash}: {e:?}"))
        })
        .transpose()?;
    let bytes = component(root, &record.normal);
    let normal = match &kernel {
        Some(kernel) => Envelope::load_with_kernel(&bytes, kernel),
        None => Envelope::load(&bytes),
    }
    .map_err(|e| format!("Normal decode: {e:?}"))?;
    assert_eq!(normal.info().hardware_version, record.hardware);
    Ok(Original { normal, kernel })
}
fn firmware<'a>(record: &'a Record, original: &'a Original) -> Firmware<'a> {
    Firmware {
        hardware: &record.hardware,
        normal: &original.normal.image,
        kernel: original.kernel.as_ref().map(|k| k.image.as_slice()),
    }
}
fn known(context: &filters::Context<'_>) -> phase::NativePhase {
    match context.native_phase {
        Observation::Known(p) => p,
        ref p => panic!("native phase: {p:?}"),
    }
}
fn mapping(normal: &[u8], assignment: Assignment) -> Result<Vec<u8>, String> {
    if matches!(native::discover_pair(normal), Observation::Known(_)) {
        native::correct_pair(normal, assignment)
    } else {
        native::sat1::phase_only::correct(normal, assignment)
    }
    .map_err(|e| format!("native target-only mapping: {e:?}"))
}
fn unchanged_outside_mapping(original: &[u8], mapped: &[u8], prepared: &[u8]) {
    assert_eq!(original.len(), mapped.len());
    assert_eq!(original.len(), prepared.len());
    for at in 0..original.len() {
        if !(16..20).contains(&at) {
            assert_eq!(
                prepared[at], mapped[at],
                "non-phase byte changed at {at:#x}"
            );
        }
    }
    // Mapping itself cannot edit integrity metadata; only the authentic codec
    // and shared integrity owner may compensate it during preparation.
    assert_eq!(&original[..24], &mapped[..24]);
}
fn describe(plan: &filters::runner::Plan<'_>, before: Assignment, required: Assignment) {
    assert!(
        plan.required_words().unwrap().is_empty(),
        "phase cannot require donor parameters"
    );
    let descriptions: Vec<_> = plan.operations().map(|op| op.description()).collect();
    if before == required {
        assert!(descriptions.is_empty());
    } else {
        assert_eq!(
            descriptions,
            [Some(Correction::Phase {
                from: before,
                to: required
            })]
        );
    }
}

#[test]
fn inventory_covers_every_held_image_and_kernel_variant() {
    let inventory = inventory();
    assert_eq!(inventory.schema, 1);
    assert_eq!(inventory.domains.len(), 2);
    for (domain, (name, images, variants)) in inventory
        .domains
        .iter()
        .zip([("sat1", 73, 73), ("h8sat", 460, 461)])
    {
        assert_eq!(domain.id, name);
        assert_eq!(domain.image_count, images);
        assert_eq!(domain.records.len(), variants);
        assert_eq!(
            domain
                .records
                .iter()
                .map(|r| &r.normal)
                .collect::<BTreeSet<_>>()
                .len(),
            images
        );
        assert_eq!(
            domain
                .records
                .iter()
                .map(|r| (&r.normal, &r.kernel))
                .collect::<BTreeSet<_>>()
                .len(),
            variants
        );
        for record in &domain.records {
            for hash in std::iter::once(&record.normal).chain(record.kernel.iter()) {
                assert_eq!(hash.len(), 64);
                assert!(hash.bytes().all(|b| b.is_ascii_hexdigit()));
            }
        }
    }
}

/// One complete target/fact effect is independent of donor waveforms. The witness
/// is explicitly target-derived, not an invented original image or resident Kernel.
fn prove_target(
    record: &Record,
    original: &Original,
    assignment: Assignment,
    native_proofs: &mut usize,
) -> Result<Proof, String> {
    let target = firmware(record, original);
    let destination = filters::Context::new(target);
    let before = known(&destination);
    let mapped = mapping(target.normal, assignment)?;
    let witness = filters::Context::new(Firmware {
        normal: &mapped,
        ..target
    });
    let required = known(&witness);
    assert_eq!(required.assignment, assignment);
    assert_eq!(required.interface, before.interface);
    assert_eq!(required.architecture, before.architecture);
    assert_eq!(
        mapping(&mapped, before.assignment)?,
        target.normal,
        "native mapping round trip"
    );
    *native_proofs += 1;
    println!(
        "{}",
        json!({"event":"native-mapping-proof", "normal":record.normal,
        "kernel":record.kernel, "assignment":format!("{assignment:?}"),
        "image_sha256":digest(&mapped), "byte_exact_round_trip":true,
        "codec_and_receiver_admission":"separate; not established by this native proof"})
    );
    let plan = filters::runner::plan_with(
        &witness,
        &destination,
        filters::runner::Policy::Strict,
        REGISTRY,
    )
    .map_err(|e| format!("phase plan: {e:?}"))?;
    describe(&plan, before.assignment, assignment);
    let preparation = filters::Preparation {
        target,
        normal: Some(&original.normal),
        kernel: original.kernel.as_ref(),
    };
    assert!(plan.matches_components(&preparation));
    let changed = plan
        .prepare_with(&preparation, REGISTRY)
        .map_err(|e| format!("phase prepare: {e:?}"))?;
    assert_eq!(changed.is_none(), before.assignment == assignment);
    let image = changed.unwrap_or_else(|| target.normal.to_vec());
    unchanged_outside_mapping(target.normal, &mapped, &image);
    plan.verify_with(&preparation, &image, REGISTRY)
        .map_err(|e| format!("phase verify: {e:?}"))?;
    assert!(matches!(
        phase::observe(Firmware {
            normal: &image,
            ..target
        }),
        Observation::Known(actual) if actual == required
    ));
    let encoded = original
        .normal
        .repack(&image)
        .ok_or("original codec refused encode")?;
    if assignment == before.assignment {
        assert_eq!(
            digest(&encoded),
            record.normal,
            "unchanged original codec bytes"
        );
    }
    let decoded = match &original.kernel {
        Some(kernel) => Envelope::load_with_kernel(&encoded, kernel),
        None => Envelope::load(&encoded),
    }
    .map_err(|e| format!("original codec decode: {e:?}"))?;
    assert_eq!(decoded.image, image, "original codec plaintext changed");
    assert_eq!(
        decoded.repack(&decoded.image).as_deref(),
        Some(encoded.as_slice()),
        "original codec nondeterminism"
    );
    println!(
        "{}",
        json!({"event":"target-proof", "normal":record.normal, "kernel":record.kernel,
        "assignment":format!("{assignment:?}"), "interface":format!("{:?}",required.interface),
        "installed_witness":"target-derived native assignment; not a new OEM original",
        "image_sha256":digest(&image), "encoded_sha256":digest(&encoded),
        "receiver_policy_bound":original.normal.info().receiver_xor_policy.is_some(),
        "receiver_context":if original.kernel.is_some() {"retained Kernel"} else {"unavailable; no resident Kernel inferred"},
        "scope":"native phase and original codec only; other flash gates not evaluated"})
    );
    Ok(Proof { image })
}

#[test]
#[ignore = "exact private corpus; exhaustive ordered planner coverage runs only in CI"]
fn every_target_mapping_and_ordered_planner_pair() {
    let root = std::env::var_os("PIONEER_PHASE_CORPUS").expect("PIONEER_PHASE_CORPUS");
    let domain_id = std::env::var("PIONEER_PHASE_DOMAIN").expect("PIONEER_PHASE_DOMAIN");
    let shard: usize = std::env::var("PIONEER_PHASE_SHARD")
        .unwrap_or_else(|_| "0".into())
        .parse()
        .unwrap();
    let shards: usize = std::env::var("PIONEER_PHASE_SHARDS")
        .unwrap_or_else(|_| "1".into())
        .parse()
        .unwrap();
    assert!(shards > 0 && shard < shards);
    let source = std::env::var("PIONEER_PHASE_SOURCE").ok();
    let selected = std::env::var("PIONEER_PHASE_TARGET").ok();
    let focused = source.is_some() && selected.is_some();
    assert_eq!(source.is_some(), selected.is_some());
    assert!(
        focused || std::env::var("CI").as_deref() == Ok("true"),
        "local execution requires one explicit source/target pair"
    );
    let mut domain = inventory()
        .domains
        .into_iter()
        .find(|d| d.id == domain_id)
        .unwrap();
    if focused {
        assert_eq!(shards, 1);
        domain
            .records
            .retain(|r| Some(&r.normal) == source.as_ref() || Some(&r.normal) == selected.as_ref());
        assert!(domain
            .records
            .iter()
            .any(|r| Some(&r.normal) == source.as_ref()));
        assert!(domain
            .records
            .iter()
            .any(|r| Some(&r.normal) == selected.as_ref()));
    }
    assert!(shards <= domain.records.len());
    let originals: Vec<_> = domain
        .records
        .iter()
        .map(|r| load(Path::new(&root), r))
        .collect();
    let contexts: Vec<_> = originals
        .iter()
        .zip(&domain.records)
        .map(|(o, r)| {
            o.as_ref()
                .ok()
                .map(|o| filters::Context::new(firmware(r, o)))
        })
        .collect();
    for (record, context) in domain.records.iter().zip(&contexts) {
        if let Some(context) = context {
            assert_eq!(
                serde_json::to_value(known(context).value()).unwrap(),
                record.phase,
                "held-image native phase changed for {}",
                record.normal
            );
        }
    }
    let mut failures = Vec::new();
    let (
        mut targets,
        mut mappings,
        mut pairs,
        mut same_interface,
        mut cross_interface,
        mut unavailable_pairs,
    ) = (0, 0, 0, 0, 0, 0);
    let mut receiver_unavailable = 0;
    let mut native_proofs = 0;
    for (b, record) in domain.records.iter().enumerate() {
        if b % shards != shard || selected.as_ref().is_some_and(|h| h != &record.normal) {
            continue;
        }
        targets += 1;
        if record.kernel.is_none() {
            receiver_unavailable += 1;
        }
        let proofs: Vec<_> = [Assignment::Direct, Assignment::Swapped].into_iter().map(|assignment| {
            let proof = originals[b].as_ref().map_err(Clone::clone)
                .and_then(|o| prove_target(record, o, assignment, &mut native_proofs));
            match &proof {
                Ok(_) => mappings += 1,
                Err(reason) => {
                    println!("{}", json!({"event":"target-unavailable", "normal":record.normal,
                        "kernel":record.kernel, "assignment":format!("{assignment:?}"), "reason":reason,
                        "receiver_context":if record.kernel.is_none() {"missing retained Kernel; no substitution"} else {"retained Kernel supplied"},
                        "complete":false}));
                    failures.push(format!("{} {assignment:?}: {reason}",record.normal));
                }
            }
            proof
        }).collect();
        for (a, source_record) in domain.records.iter().enumerate() {
            if source.as_ref().is_some_and(|h| h != &source_record.normal) {
                continue;
            }
            pairs += 1;
            let pair_started = std::time::Instant::now();
            let (Some(installed), Some(destination)) = (&contexts[a], &contexts[b]) else {
                unavailable_pairs += 1;
                println!(
                    "{}",
                    json!({"event":"pair-unavailable", "source":source_record.normal,
                    "target":record.normal,"reason":"authentic input decode unavailable",
                    "source_error":originals[a].as_ref().err(),"target_error":originals[b].as_ref().err()})
                );
                failures.push(format!(
                    "{} -> {}: decode unavailable",
                    source_record.normal, record.normal
                ));
                continue;
            };
            let required = known(installed);
            let before = known(destination);
            let plan = filters::runner::plan_with(
                installed,
                destination,
                filters::runner::Policy::Strict,
                REGISTRY,
            );
            if required.architecture != before.architecture
                || required.interface != before.interface
            {
                cross_interface += 1;
                assert!(
                    matches!(plan, Err(Error::Incompatible)),
                    "cross-interface must remain an explicit refusal"
                );
                println!(
                    "{}",
                    json!({"event":"pair-cross-interface-unresolved", "source":source_record.normal,
                    "target":record.normal,"source_kernel":source_record.kernel,"target_kernel":record.kernel,
                    "complete":false})
                );
                continue;
            }
            same_interface += 1;
            let result = (|| -> Result<(), String> {
                let plan = plan.map_err(|e| format!("plan: {e:?}"))?;
                describe(&plan, before.assignment, required.assignment);
                let original = originals[b].as_ref().unwrap();
                let preparation = filters::Preparation {
                    target: destination.firmware,
                    normal: Some(&original.normal),
                    kernel: original.kernel.as_ref(),
                };
                assert!(
                    plan.matches_components(&preparation),
                    "pair plan binds exact target components"
                );
                let index = usize::from(required.assignment == Assignment::Swapped);
                let proof = proofs[index]
                    .as_ref()
                    .map_err(|e| format!("target proof unavailable: {e}"))?;
                // Every ordered pair verifies its own component-bound operation.
                // Only identical target/assignment preparation and compression
                // are memoized, never native pair admission or operation binding.
                plan.verify_with(&preparation, &proof.image, REGISTRY)
                    .map_err(|e| format!("pair verify: {e:?}"))?;
                Ok(())
            })();
            println!(
                "{}",
                json!({"event":"pair-proof", "source":source_record.normal,
                "target":record.normal,"source_kernel":source_record.kernel,"target_kernel":record.kernel,
                "assignment":format!("{:?}",required.assignment),"verified":result.is_ok(),"error":result.as_ref().err(),
                "elapsed_ms":pair_started.elapsed().as_millis()})
            );
            if let Err(reason) = result {
                failures.push(format!(
                    "{} -> {}: {reason}",
                    source_record.normal, record.normal
                ));
            }
        }
    }
    let expected_targets = domain
        .records
        .iter()
        .enumerate()
        .filter(|(b, r)| b % shards == shard && selected.as_ref().map_or(true, |h| h == &r.normal))
        .count();
    let expected_sources = domain
        .records
        .iter()
        .filter(|r| source.as_ref().map_or(true, |h| h == &r.normal))
        .count();
    assert!(expected_targets > 0 && expected_sources > 0);
    assert_eq!(targets, expected_targets);
    assert_eq!(pairs, expected_targets * expected_sources);
    assert_eq!(pairs, same_interface + cross_interface + unavailable_pairs);
    println!(
        "{}",
        json!({"event":"coverage-summary","domain":domain.id,"shard":shard,"shards":shards,
        "unique_images_in_domain":domain.image_count,"retained_input_records":domain.records.len(),
        "execution":if focused {"one explicitly selected local direction"} else {"exhaustive CI target shard"},
        "target_records":targets,"native_mapping_proofs":native_proofs,
        "native_assignment_and_codec_proofs":mappings,"expected_mapping_proofs":targets*2,
        "ordered_pairs":pairs,"same_interface_pairs":same_interface,"cross_interface_unresolved_pairs":cross_interface,
        "decode_unavailable_pairs":unavailable_pairs,"records_without_resident_kernel":receiver_unavailable,
        "failed_obligations":failures.len(),"overall_phase_domain_complete":false,
        "scope":"same-interface native phase only; cross-interface and other flash gates are separate unresolved obligations"})
    );
    assert!(
        failures.is_empty(),
        "{} incomplete phase/codec obligations; first20: {:#?}; every failure is in the JSON rows",
        failures.len(),
        &failures[..failures.len().min(20)]
    );
    assert_eq!(mappings, targets * 2);
}
