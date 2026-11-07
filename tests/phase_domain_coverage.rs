//! Exact held-image phase mapping, separate from cross-interface or flash admission.
#![cfg(feature = "envelope")]

use pioneer_optical::{
    compatibility::{Correction, Error, Firmware},
    envelope::{Envelope, KernelXorPolicy, Update},
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
#[derive(Clone)]
struct Original {
    normal: Envelope,
    kernel: Option<Envelope>,
    receiver: Option<String>,
    conditional: bool,
}
#[derive(Deserialize)]
struct ConditionalManifest {
    schema: u32,
    records: Vec<ConditionalRecord>,
}
#[derive(Deserialize)]
struct ConditionalRecord {
    normal: String,
    packaged_kernel: Option<String>,
    receivers: Vec<Receiver>,
}
#[derive(Deserialize)]
struct Receiver {
    kernel: String,
    association: String,
    decoded_normal_sha256: String,
    native_xor_policy: serde_json::Value,
    provenance: Vec<serde_json::Value>,
    checks: Vec<String>,
}
fn conditional_manifest() -> ConditionalManifest {
    serde_json::from_str(include_str!("fixtures/phase-conditional-receivers.json")).unwrap()
}
#[derive(Deserialize)]
struct UnavailableManifest {
    schema: u32,
    records: Vec<UnavailableReceiver>,
}
#[derive(Deserialize)]
struct UnavailableReceiver {
    normal: String,
    hardware: String,
    standalone_decoded_sha256: String,
    standalone_be32_sum: u32,
    refusal: String,
    reason: String,
}
fn unavailable_manifest() -> UnavailableManifest {
    serde_json::from_str(include_str!("fixtures/phase-unavailable-receivers.json")).unwrap()
}
struct Proof {
    delivery: bool,
    image: Vec<u8>,
    native_phase: phase::NativePhase,
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
    Ok(Original {
        normal,
        kernel,
        receiver: record.kernel.clone(),
        conditional: false,
    })
}
fn load_conditional(root: &Path, record: &Record, receiver: &Receiver) -> Result<Original, String> {
    assert!(
        record.kernel.is_none(),
        "conditional context never replaces packaged context"
    );
    assert_eq!(receiver.association, "conditional-receiver-context");
    let kernel_bytes = component(root, &receiver.kernel);
    let normal_bytes = component(root, &record.normal);
    let update = Update::load(&kernel_bytes, &normal_bytes)
        .map_err(|e| format!("conditional Update::load {}: {e:?}", receiver.kernel))?;
    let kernel = update.kernel().clone();
    let normal = update.normal().clone();
    let k = kernel.header_info();
    let n = normal.header_info();
    for (a, b) in [
        (&k.hardware_version, &n.hardware_version),
        (&k.destination, &n.destination),
        (&k.kernel_version, &n.kernel_version),
        (&k.kernel_version2, &n.kernel_version2),
    ] {
        assert!(!a.is_empty());
        assert_eq!(a, b, "conditional header identity");
    }
    let policy = KernelXorPolicy::from_kernel(&kernel)
        .ok_or("conditional native receiver policy missing")?;
    assert_eq!(
        serde_json::to_value(policy).unwrap(),
        receiver.native_xor_policy
    );
    assert_eq!(digest(&normal.image), receiver.decoded_normal_sha256);
    assert_eq!(normal.image.len() % 4, 0);
    assert_eq!(
        normal.image.chunks_exact(4).fold(0u32, |sum, w| sum
            .wrapping_add(u32::from_be_bytes(w.try_into().unwrap()))),
        0
    );
    let original = Original {
        normal,
        kernel: Some(kernel),
        receiver: Some(receiver.kernel.clone()),
        conditional: true,
    };
    let context = filters::Context::new(firmware(record, &original));
    assert_eq!(
        serde_json::to_value(known(&context).value()).unwrap(),
        record.phase,
        "conditional receiver must preserve the native fact"
    );
    println!(
        "{}",
        json!({"event":"conditional-receiver-authenticated","normal":record.normal,
        "packaged_kernel":record.kernel,"selected_receiver":receiver.kernel,
        "actual_installed_kernel":"unknown","association":receiver.association,
        "decoded_normal_sha256":receiver.decoded_normal_sha256,
        "checks":"four headers + Update::load + native policy + zero checksum + native phase fact"})
    );
    Ok(original)
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

#[test]
fn conditional_receivers_are_supplemental_not_packaged_or_installed() {
    let base = inventory();
    let manifest = conditional_manifest();
    assert_eq!(manifest.schema, 1);
    assert_eq!(manifest.records.len(), 12);
    assert_eq!(
        manifest
            .records
            .iter()
            .map(|r| r.receivers.len())
            .sum::<usize>(),
        19
    );
    let mut normals = BTreeSet::new();
    for row in manifest.records {
        assert!(normals.insert(row.normal.clone()));
        assert!(row.packaged_kernel.is_none());
        let records: Vec<_> = base
            .domains
            .iter()
            .flat_map(|d| &d.records)
            .filter(|r| r.normal == row.normal)
            .collect();
        assert_eq!(records.len(), 1);
        assert!(records[0].kernel.is_none());
        let mut kernels = BTreeSet::new();
        assert!(!row.receivers.is_empty());
        for receiver in row.receivers {
            assert!(kernels.insert(receiver.kernel));
            assert_eq!(receiver.association, "conditional-receiver-context");
            assert!(!receiver.provenance.is_empty());
            assert_eq!(
                receiver.checks,
                [
                    "four-header-fields-equal",
                    "native-xor-policy",
                    "decoded-checksum-zero",
                    "original-update-load-accepted"
                ]
            );
        }
    }
}

#[test]
fn unavailable_receiver_fixture_is_exact_and_disjoint() {
    let missing = unavailable_manifest();
    let conditional = conditional_manifest();
    let inventory = inventory();
    assert_eq!(missing.schema, 1);
    assert_eq!(missing.records.len(), 114);
    let mut hashes = BTreeSet::new();
    for row in &missing.records {
        assert!(hashes.insert(&row.normal));
        assert_eq!(row.normal.len(), 64);
        assert_eq!(row.standalone_decoded_sha256.len(), 64);
        assert_ne!(row.standalone_be32_sum, 0);
        assert_eq!(row.refusal, "Representation");
        assert!(!row.reason.is_empty());
        assert!(!conditional.records.iter().any(|r| r.normal == row.normal));
        let records: Vec<_> = inventory
            .domains
            .iter()
            .flat_map(|d| &d.records)
            .filter(|r| r.normal == row.normal)
            .collect();
        assert_eq!(records.len(), 1);
        assert!(records[0].kernel.is_none());
        assert_eq!(records[0].hardware, row.hardware);
    }
}

/// One complete target/fact effect is independent of donor waveforms. The witness
/// is explicitly target-derived, not an invented original image or resident Kernel.
fn prove_target(
    record: &Record,
    original: &Original,
    assignment: Assignment,
    native_proofs: &mut usize,
    unavailable: Option<&UnavailableReceiver>,
) -> Result<Proof, String> {
    let target = firmware(record, original);
    let destination = filters::Context::new(target);
    let before = known(&destination);
    assert_eq!(serde_json::to_value(before.value()).unwrap(), record.phase);
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
        "packaged_kernel":record.kernel, "selected_receiver":original.receiver,
        "conditional_receiver":original.conditional, "actual_installed_kernel":"unknown",
        "assignment":format!("{assignment:?}"),
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
    if let Some(expected) = unavailable {
        assert_eq!(expected.normal, record.normal);
        assert_eq!(expected.hardware, record.hardware);
        assert!(record.kernel.is_none() && original.kernel.is_none());
        assert!(original.receiver.is_none() && !original.conditional);
        assert!(original.normal.info().receiver_xor_policy.is_none());
        assert_eq!(digest(target.normal), expected.standalone_decoded_sha256);
        let sum = target.normal.chunks_exact(4).fold(0u32, |sum, word| {
            sum.wrapping_add(u32::from_be_bytes(word.try_into().unwrap()))
        });
        assert_eq!(target.normal.len() % 4, 0);
        assert_eq!(sum, expected.standalone_be32_sum);
        assert_ne!(
            sum, 0,
            "resolved checksum authority must retire this negative fixture"
        );
        assert_eq!(expected.refusal, "Representation");
        // Native semantics remain mandatory even when delivery cannot be proven.
        // This verifies the actual selected operation against the reversible,
        // target-derived mapping before asserting the precise integrity refusal.
        plan.verify_with(&preparation, &mapped, REGISTRY)
            .map_err(|e| format!("native phase verify: {e:?}"))?;
        let prepared = plan.prepare_with(&preparation, REGISTRY);
        if before.assignment == assignment {
            assert_eq!(prepared, Ok(None), "unchanged native plan remains a no-op");
        } else {
            assert_eq!(
                prepared,
                Err(Error::Representation),
                "only the pinned representation refusal is expected"
            );
        }
        assert_eq!(
            (filters::be32_normal_integrity().repair)(&preparation, target.normal),
            Err(Error::Representation),
            "original codec integrity authority remains unavailable"
        );
        assert!(original.normal.repack_with_checksum(&mapped).is_none());
        assert_eq!(
            digest(
                &original
                    .normal
                    .repack(target.normal)
                    .expect("unchanged original representation remains lossless")
            ),
            record.normal
        );
        println!(
            "{}",
            json!({"event":"expected-receiver-context-refusal",
            "normal":record.normal,"packaged_kernel":null,"selected_receiver":null,
            "assignment":format!("{assignment:?}"),"native_mapping_verified":true,
            "byte_exact_native_round_trip":true,"refusal":"Representation",
            "standalone_be32_sum":sum,"reason":expected.reason,
            "complete_delivery_proof":false,"actual_installed_kernel":"unknown"})
        );
        return Ok(Proof {
            image: mapped,
            native_phase: required,
            delivery: false,
        });
    }
    let changed = plan
        .prepare_with(&preparation, REGISTRY)
        .map_err(|e| format!("phase prepare: {e:?}"))?;
    assert_eq!(changed.is_none(), before.assignment == assignment);
    let image = changed.unwrap_or_else(|| target.normal.to_vec());
    // A no-op plan does not invoke the integrity owner. Explicitly establish
    // original codec/checksum authority even then: lossless repacking of invalid
    // plaintext is only byte preservation, not a valid delivery proof.
    match (filters::be32_normal_integrity().repair)(&preparation, target.normal) {
        Ok(unchanged) => assert_eq!(unchanged, target.normal),
        Err(error) => {
            if before.assignment == assignment {
                let preserved = original
                    .normal
                    .repack(target.normal)
                    .is_some_and(|encoded| digest(&encoded) == record.normal);
                println!(
                    "{}",
                    json!({"event":"original-codec-preservation-only","normal":record.normal,
                    "packaged_kernel":record.kernel,"selected_receiver":original.receiver,
                    "byte_exact_original_repack":preserved,"original_integrity_authority":false,
                    "complete_delivery_proof":false,"reason":format!("{error:?}")})
                );
            }
            return Err(format!("original integrity: {error:?}"));
        }
    }
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
        json!({"event":"target-proof", "normal":record.normal, "packaged_kernel":record.kernel,
        "selected_receiver":original.receiver,"conditional_receiver":original.conditional,"actual_installed_kernel":"unknown",
        "assignment":format!("{assignment:?}"), "interface":format!("{:?}",required.interface),
        "installed_witness":"target-derived native assignment; not a new OEM original",
        "image_sha256":digest(&image), "encoded_sha256":digest(&encoded),
        "original_integrity_authority":true,
        "receiver_policy_bound":original.normal.info().receiver_xor_policy.is_some(),
        "receiver_context":if original.conditional {"conditional receiver only; not original package or installed identity"} else if original.kernel.is_some() {"packaged Kernel"} else {"unavailable; no resident Kernel inferred"},
        "scope":"native phase and original codec only; other flash gates not evaluated"})
    );
    Ok(Proof {
        delivery: true,
        image,
        native_phase: required,
    })
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
    let standalone: Vec<_> = domain
        .records
        .iter()
        .map(|r| load(Path::new(&root), r))
        .collect();
    let supplemental = conditional_manifest();
    let unavailable = unavailable_manifest();
    let originals: Vec<_> = domain
        .records
        .iter()
        .zip(&standalone)
        .map(|(record, base)| {
            match supplemental
                .records
                .iter()
                .find(|r| r.normal == record.normal)
            {
                Some(row) => load_conditional(Path::new(&root), record, &row.receivers[0]),
                None => base.clone(),
            }
        })
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
    let mut supplemental_native_proofs = 0;
    let mut supplemental_codec_proofs = 0;
    let mut original_context_refusals = 0;
    let mut original_context_codec_proofs = 0;
    let mut conditional_records = 0;
    let mut conditional_variants = 0;
    let mut expected_refusals = 0;
    let mut native_only_pairs = 0;
    let strict_delivery = std::env::var("PIONEER_PHASE_REQUIRE_DELIVERY").as_deref() == Ok("1");
    for (b, record) in domain.records.iter().enumerate() {
        if b % shards != shard || selected.as_ref().is_some_and(|h| h != &record.normal) {
            continue;
        }
        targets += 1;
        if record.kernel.is_none() {
            receiver_unavailable += 1;
        }
        let mut proofs = Vec::new();
        if let Some(row) = supplemental
            .records
            .iter()
            .find(|r| r.normal == record.normal)
        {
            conditional_records += 1;
            // Always exercise the original absent-context input before introducing
            // any explicit conditional receiver. Only Representation refusal is
            // a missing-context result; mapping/verification failures stay fatal.
            for assignment in [Assignment::Direct, Assignment::Swapped] {
                let base = standalone[b]
                    .as_ref()
                    .map_err(Clone::clone)
                    .and_then(|o| prove_target(record, o, assignment, &mut native_proofs, None));
                println!(
                    "{}",
                    json!({"event":"original-standalone-outcome","normal":record.normal,
                    "packaged_kernel":record.kernel,"selected_receiver":null,
                    "assignment":format!("{assignment:?}"),"success":base.is_ok(),"error":base.as_ref().err()})
                );
                if base.is_ok() {
                    original_context_codec_proofs += 1;
                }
                if let Err(reason) = base {
                    if matches!(
                        reason.as_str(),
                        "phase prepare: Representation" | "original integrity: Representation"
                    ) {
                        original_context_refusals += 1;
                    } else {
                        failures.push(format!(
                            "{} standalone {assignment:?}: {reason}",
                            record.normal
                        ));
                    }
                }
            }
            // Every supplemental alternative receives full two-assignment proof.
            // The first listed receiver alone binds this record's ordered-pair
            // lane; no success-driven substitution or invented package is used.
            for (index, receiver) in row.receivers.iter().enumerate() {
                conditional_variants += 1;
                let candidate = if index == 0 {
                    originals[b].clone()
                } else {
                    load_conditional(Path::new(&root), record, receiver)
                };
                let mut effects = Vec::new();
                for assignment in [Assignment::Direct, Assignment::Swapped] {
                    let effect = candidate.as_ref().map_err(Clone::clone).and_then(|o| {
                        prove_target(record, o, assignment, &mut supplemental_native_proofs, None)
                    });
                    println!(
                        "{}",
                        json!({"event":"conditional-target-outcome","normal":record.normal,
                        "packaged_kernel":record.kernel,"selected_receiver":receiver.kernel,
                        "actual_installed_kernel":"unknown","assignment":format!("{assignment:?}"),
                        "ordered_pair_receiver":index==0,"success":effect.is_ok(),"error":effect.as_ref().err()})
                    );
                    match &effect {
                        Ok(_) => supplemental_codec_proofs += 1,
                        Err(reason) => failures.push(format!(
                            "{} conditional {} {assignment:?}: {reason}",
                            record.normal, receiver.kernel
                        )),
                    }
                    effects.push(effect);
                }
                if index == 0 {
                    proofs = effects;
                }
            }
        } else {
            for assignment in [Assignment::Direct, Assignment::Swapped] {
                let proof = originals[b].as_ref().map_err(Clone::clone).and_then(|o| {
                    prove_target(
                        record,
                        o,
                        assignment,
                        &mut native_proofs,
                        unavailable
                            .records
                            .iter()
                            .find(|r| r.normal == record.normal),
                    )
                });
                if let Ok(proof) = &proof {
                    if proof.delivery {
                        original_context_codec_proofs += 1;
                    } else {
                        expected_refusals += 1;
                    }
                }
                if let Err(reason) = &proof {
                    println!(
                        "{}",
                        json!({"event":"target-unavailable","normal":record.normal,
                        "packaged_kernel":record.kernel,"selected_receiver":record.kernel,
                        "assignment":format!("{assignment:?}"),"reason":reason,"complete":false})
                    );
                    failures.push(format!("{} {assignment:?}: {reason}", record.normal));
                }
                proofs.push(proof);
            }
        }
        mappings += proofs
            .iter()
            .filter(|p| p.as_ref().is_ok_and(|p| p.delivery))
            .count();
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
                    "target":record.normal,"source_packaged_kernel":source_record.kernel,"target_packaged_kernel":record.kernel,
                    "source_selected_receiver":originals[a].as_ref().ok().and_then(|o|o.receiver.as_ref()),
                    "target_selected_receiver":originals[b].as_ref().ok().and_then(|o|o.receiver.as_ref()),
                    "source_conditional":originals[a].as_ref().is_ok_and(|o|o.conditional),
                    "target_conditional":originals[b].as_ref().is_ok_and(|o|o.conditional),"actual_installed_kernel":"unknown",
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
                // The shared runner already verified this exact immutable output
                // in prove_target, including re-inspection of its native fact.
                // Each pair still plans, binds and verifies its own operations;
                // avoid rebuilding unrelated hardware observations for the same
                // target/assignment output thousands of times.
                assert_eq!(proof.native_phase, required);
                if before == required {
                    assert_eq!(proof.image, destination.firmware.normal);
                }
                for operation in plan.operations() {
                    operation
                        .verify(&preparation, &proof.image)
                        .map_err(|e| format!("pair operation verify: {e:?}"))?;
                }
                Ok(())
            })();
            let delivery = proofs[usize::from(required.assignment == Assignment::Swapped)]
                .as_ref()
                .is_ok_and(|p| p.delivery);
            if result.is_ok() && !delivery {
                native_only_pairs += 1;
            }
            println!(
                "{}",
                json!({"event":"pair-proof", "source":source_record.normal,
                "target":record.normal,"source_packaged_kernel":source_record.kernel,"target_packaged_kernel":record.kernel,
                    "source_selected_receiver":originals[a].as_ref().ok().and_then(|o|o.receiver.as_ref()),
                    "target_selected_receiver":originals[b].as_ref().ok().and_then(|o|o.receiver.as_ref()),
                    "source_conditional":originals[a].as_ref().is_ok_and(|o|o.conditional),
                    "target_conditional":originals[b].as_ref().is_ok_and(|o|o.conditional),"actual_installed_kernel":"unknown",
                "assignment":format!("{:?}",required.assignment),"verified":result.is_ok() && delivery,
                "native_verified":result.is_ok(),"delivery_verified":result.is_ok() && delivery,
                "expected_representation_refusal":result.is_ok() && !delivery,
                "error":result.as_ref().err(),
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
        "decode_unavailable_pairs":unavailable_pairs,"records_without_packaged_kernel":receiver_unavailable,
        "original_standalone_representation_refusals":original_context_refusals,
        "original_context_codec_proofs":original_context_codec_proofs,
        "conditionally_tested_records":conditional_records,"conditional_native_mapping_proofs":supplemental_native_proofs,
        "conditional_receiver_variants":conditional_variants,"expected_conditional_codec_proofs":conditional_variants*2,
        "conditional_codec_proofs":supplemental_codec_proofs,"conditional_receivers_do_not_identify_installed_kernel":true,
        "primary_codec_proofs_include_conditional_receivers":conditional_records>0,
        "records_without_listed_receiver_context":receiver_unavailable-conditional_records,
        "expected_representation_refusals":expected_refusals,
        "native_only_same_interface_pairs":native_only_pairs,
        "codec_delivery_complete":expected_refusals==0 && failures.is_empty(),
        "strict_delivery_required":strict_delivery,
        "failed_obligations":failures.len(),"overall_phase_domain_complete":false,
        "scope":"same-interface native phase only; cross-interface and other flash gates are separate unresolved obligations"})
    );
    assert!(
        failures.is_empty(),
        "{} incomplete phase/codec obligations; first20: {:#?}; every failure is in the JSON rows",
        failures.len(),
        &failures[..failures.len().min(20)]
    );
    assert_eq!(mappings + expected_refusals, targets * 2);
    assert_eq!(
        native_proofs,
        targets * 2,
        "every original input retains both native proofs"
    );
    if strict_delivery {
        assert_eq!(
            expected_refusals, 0,
            "strict delivery completeness: authentic receiver contexts remain unavailable"
        );
    }
    assert_eq!(supplemental_codec_proofs, conditional_variants * 2);
}
