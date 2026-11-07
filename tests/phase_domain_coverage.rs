//! Complete, image-specific phase coverage, independent of other filter owners.
#![cfg(feature = "envelope")]

use pioneer_optical::{
    compatibility::Firmware,
    envelope::Envelope,
    filters::{self, phase, Filter},
    image::layout::Observation,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

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
}
struct Original {
    normal: Envelope,
    kernel: Option<Envelope>,
}

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
fn load(root: &Path, record: &Record) -> Original {
    let kernel = record.kernel.as_ref().map(|hash| {
        Envelope::load(&component(root, hash))
            .unwrap_or_else(|e| panic!("Kernel {hash} decode: {e:?}"))
    });
    let raw = component(root, &record.normal);
    let normal = match &kernel {
        Some(kernel) => Envelope::load_with_kernel(&raw, kernel),
        None => Envelope::load(&raw),
    }
    .unwrap_or_else(|e| panic!("Normal {} decode: {e:?}", record.normal));
    assert_eq!(normal.info().hardware_version, record.hardware);
    Original { normal, kernel }
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
        let normals: BTreeSet<_> = domain.records.iter().map(|r| &r.normal).collect();
        assert_eq!(normals.len(), images);
        let pairs: BTreeSet<_> = domain
            .records
            .iter()
            .map(|r| (&r.normal, &r.kernel))
            .collect();
        assert_eq!(pairs.len(), variants, "duplicate input variant");
        for record in &domain.records {
            for hash in std::iter::once(&record.normal).chain(record.kernel.iter()) {
                assert_eq!(hash.len(), 64);
                assert!(hash.bytes().all(|b| b.is_ascii_hexdigit()));
            }
        }
    }
}

/// CI partitions by installed-image index. No unsupported pair, missing input,
/// absent Kernel, equal label or other owner's refusal can skip a direction.
#[test]
#[ignore = "requires exact phase corpus; exhaustive domain coverage runs in CI"]
fn every_direction_prepares_verifies_and_round_trips_original_codec() {
    let root = std::env::var_os("PIONEER_PHASE_CORPUS").expect("PIONEER_PHASE_CORPUS");
    let domain_id = std::env::var("PIONEER_PHASE_DOMAIN").expect("PIONEER_PHASE_DOMAIN");
    let shard = std::env::var("PIONEER_PHASE_SHARD")
        .unwrap_or_else(|_| "0".into())
        .parse::<usize>()
        .unwrap();
    let shards = std::env::var("PIONEER_PHASE_SHARDS")
        .unwrap_or_else(|_| "1".into())
        .parse::<usize>()
        .unwrap();
    assert!(shards > 0 && shard < shards);
    // A local developer may select one exact direction; never accidentally run
    // the exhaustive matrix outside CI through an ignored-test invocation.
    let source = std::env::var("PIONEER_PHASE_SOURCE").ok();
    let target = std::env::var("PIONEER_PHASE_TARGET").ok();
    let focused = source.is_some() && target.is_some();
    assert!(focused || std::env::var("CI").as_deref() == Ok("true"));
    assert_eq!(source.is_some(), target.is_some());
    let inventory = inventory();
    let mut domain = inventory
        .domains
        .into_iter()
        .find(|d| d.id == domain_id)
        .expect("unknown phase domain");
    if focused {
        assert_eq!(
            shards, 1,
            "focused local proof selects a direction, not a shard"
        );
        domain
            .records
            .retain(|r| Some(&r.normal) == source.as_ref() || Some(&r.normal) == target.as_ref());
    }
    assert!(shards <= domain.records.len());
    let originals: Vec<_> = domain
        .records
        .iter()
        .map(|record| load(Path::new(&root), record))
        .collect();
    let contexts: Vec<_> = originals
        .iter()
        .zip(&domain.records)
        .map(|(original, record)| {
            filters::Context::new(Firmware {
                hardware: &record.hardware,
                normal: &original.normal.image,
                kernel: original.kernel.as_ref().map(|k| k.image.as_slice()),
            })
        })
        .collect();
    let registry: &[&dyn Filter] = &[&phase::FILTER];
    let mut checked = 0;
    // A certificate is scoped to the exact target envelope/Kernel and emitted
    // image digest. Every pair still plans, prepares and verifies independently;
    // identical output bytes need not repeat deterministic codec compression.
    let mut codec_proofs: BTreeMap<(usize, String), String> = BTreeMap::new();
    for (a, installed) in contexts.iter().enumerate() {
        if a % shards != shard
            || source
                .as_ref()
                .is_some_and(|s| s != &domain.records[a].normal)
        {
            continue;
        }
        for (b, destination) in contexts.iter().enumerate() {
            if target
                .as_ref()
                .is_some_and(|s| s != &domain.records[b].normal)
            {
                continue;
            }
            let pair = format!(
                "{} -> {}",
                domain.records[a].normal, domain.records[b].normal
            );
            let plan = filters::runner::plan_with(
                installed,
                destination,
                filters::runner::Policy::Strict,
                registry,
            )
            .unwrap_or_else(|e| panic!("{pair}: phase plan {e:?}"));
            let words = plan.required_words().unwrap();
            filters::prerequisites::check::<()>(&words, |index| {
                Ok(words
                    .iter()
                    .find(|w| w.word.parameter == index)
                    .unwrap()
                    .word
                    .value)
            })
            .unwrap();
            for wrong in &words {
                assert!(
                    filters::prerequisites::check::<()>(&words, |index| {
                        let value = words
                            .iter()
                            .find(|w| w.word.parameter == index)
                            .unwrap()
                            .word
                            .value;
                        Ok(if index == wrong.word.parameter {
                            value ^ 1
                        } else {
                            value
                        })
                    })
                    .is_err(),
                    "{pair}: missing prerequisite enforcement"
                );
            }
            let original = &originals[b];
            let preparation = filters::Preparation {
                target: destination.firmware,
                normal: Some(&original.normal),
                kernel: original.kernel.as_ref(),
            };
            let changed = plan
                .prepare_with(&preparation, registry)
                .unwrap_or_else(|e| panic!("{pair}: phase prepare {e:?}"));
            let image = changed.as_deref().unwrap_or(&original.normal.image);
            plan.verify_with(&preparation, image, registry)
                .unwrap_or_else(|e| panic!("{pair}: phase verify {e:?}"));
            let observed = phase::observe(Firmware {
                normal: image,
                ..destination.firmware
            });
            assert!(
                matches!((&observed, &installed.native_phase),
                    (Observation::Known(actual), Observation::Known(required)) if actual == required),
                "{pair}: output does not implement the installed phase contract"
            );
            let image_hash = digest(image);
            let encoded_hash = codec_proofs
                .entry((b, image_hash.clone()))
                .or_insert_with(|| {
                    let encoded = original
                        .normal
                        .repack(image)
                        .unwrap_or_else(|| panic!("{pair}: original-codec encode failed"));
                    let decoded = match &original.kernel {
                        Some(kernel) => Envelope::load_with_kernel(&encoded, kernel),
                        None => Envelope::load(&encoded),
                    }
                    .unwrap_or_else(|e| panic!("{pair}: original-codec decode {e:?}"));
                    assert_eq!(decoded.image, image, "{pair}: codec image mismatch");
                    assert_eq!(
                        decoded.repack(&decoded.image).unwrap(),
                        encoded,
                        "{pair}: nondeterministic codec"
                    );
                    digest(&encoded)
                });
            checked += 1;
            println!(
                "phase-proof {} {a} {b} {} {}",
                domain.id, image_hash, encoded_hash
            );
        }
    }
    let expected = if focused {
        domain
            .records
            .iter()
            .enumerate()
            .filter(|(i, r)| i % shards == shard && Some(&r.normal) == source.as_ref())
            .count()
            * domain
                .records
                .iter()
                .filter(|r| Some(&r.normal) == target.as_ref())
                .count()
    } else {
        (0..domain.records.len())
            .filter(|i| i % shards == shard)
            .count()
            * domain.records.len()
    };
    assert!(expected > 0, "empty selection cannot prove coverage");
    assert_eq!(checked, expected);
    println!(
        "phase-coverage {} shard {shard}/{shards}: {checked}/{expected}",
        domain.id
    );
}
