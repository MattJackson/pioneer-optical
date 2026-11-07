//! Exact-component evidence for the guarded mapped-channel correction.
//! The independent V5C/input gate deliberately prevents whole-pair admission.
#![cfg(feature = "envelope")]
use pioneer_optical::{
    compatibility::{Error, Firmware},
    envelope::Envelope,
    filters::{
        self, loading, loading_channel,
        runner::{self, Policy},
        Context, Filter, Preparation, Transition,
    },
    image::{irq::channel::Mapping, layout::Observation},
};
use sha2::{Digest, Sha256};
const FIVE: &str = "0a3954c01e54510eea5c870fe633fd0532d2415744e5a860962acfd06bb7430c";
const SEVEN: &str = "00eeb09ba68c05db205d40efdcb7aac5c120439d39ba564e5b4c7d3061043a59";
struct Pair {
    normal: Envelope,
    kernel: Option<Envelope>,
}
fn inventory() -> serde_json::Value {
    serde_json::from_str(include_str!("fixtures/phase-domain-inventory.json")).unwrap()
}
fn load_pair(hash: &str, kernel: Option<&str>) -> Result<Pair, String> {
    let root = std::env::var("PIONEER_PHASE_CORPUS").expect("PIONEER_PHASE_CORPUS");
    let read = |hash: &str| -> Result<Vec<u8>, String> {
        let bytes = std::fs::read(std::path::Path::new(&root).join(format!("{hash}.enc")))
            .map_err(|e| format!("read {hash}: {e}"))?;
        if format!("{:x}", Sha256::digest(&bytes)) != hash {
            return Err(format!("SHA256 mismatch: {hash}"));
        }
        Ok(bytes)
    };
    let bytes = read(hash)?;
    let kernel = kernel
        .map(|hash| Envelope::load(&read(hash)?).map_err(|e| format!("Kernel decode: {e:?}")))
        .transpose()?;
    let normal = match &kernel {
        Some(k) => Envelope::load_with_kernel(&bytes, k),
        None => Envelope::load(&bytes),
    }
    .map_err(|e| format!("Normal decode: {e:?}"))?;
    Ok(Pair { normal, kernel })
}
fn load(hash: &str) -> Pair {
    let inv = inventory();
    let record = inv["domains"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|d| d["records"].as_array().unwrap())
        .find(|r| r["normal"] == hash)
        .unwrap();
    load_pair(hash, record["kernel"].as_str()).unwrap()
}
fn context(pair: &Pair) -> Context<'_> {
    Context::new(Firmware {
        hardware: &pair.normal.info().hardware_version,
        normal: &pair.normal.image,
        kernel: pair.kernel.as_ref().map(|k| k.image.as_slice()),
    })
}
fn exercise(source: &Pair, target: &Pair) -> Result<(), String> {
    let a = context(source);
    let b = context(target);
    let before_y = loading::FILTER.inspect(&b);
    let x = loading_channel::FILTER.inspect(&a);
    let y = loading_channel::FILTER.inspect(&b);
    for (index, mut forged) in [y.clone(), y.clone(), y.clone()].into_iter().enumerate() {
        if index == 0 {
            forged.id = "other-owner";
        } else if index == 1 {
            forged.role = filters::Role::Operational;
        } else {
            forged.finding = filters::Finding::Known(filters::Value::U8(99));
        }
        assert!(matches!(
            loading_channel::FILTER.candidate(&b, &forged),
            filters::Finding::Unresolved(_)
        ));
        assert!(matches!(
            loading_channel::FILTER.plan(
                &Transition {
                    installed: &a,
                    target: &b
                },
                &x,
                &forged
            ),
            Err(Error::UnresolvedIdentity)
        ));
    }
    let operation = loading_channel::FILTER
        .plan(
            &Transition {
                installed: &a,
                target: &b,
            },
            &x,
            &y,
        )
        .map_err(|e| format!("plan: {e:?}"))?
        .ok_or("missing correction operation")?;
    assert!(operation.required_words().is_empty());
    let preparation = Preparation {
        target: b.firmware,
        normal: Some(&target.normal),
        kernel: target.kernel.as_ref(),
    };
    let patched = operation
        .prepare(&preparation)
        .map_err(|e| format!("prepare: {e:?}"))?
        .ok_or("missing prepared image")?;
    operation
        .verify(&preparation, &patched)
        .map_err(|e| format!("verify: {e:?}"))?;
    let repaired = (operation.integrity().unwrap().repair)(&preparation, &patched)
        .map_err(|e| format!("integrity: {e:?}"))?;
    let registry: &[&dyn Filter] = &[&loading_channel::FILTER];
    let selected = runner::plan_with(&a, &b, Policy::Strict, registry)
        .map_err(|e| format!("runner plan: {e:?}"))?;
    let composed = selected
        .prepare_with(&preparation, registry)
        .map_err(|e| format!("plan: {e:?}"))?
        .ok_or("missing correction operation")?;
    assert_eq!(
        composed, repaired,
        "shared composer must emit the same corrected image"
    );
    selected
        .verify_with(&preparation, &composed, registry)
        .map_err(|e| format!("runner verify: {e:?}"))?;
    let encoded = target
        .normal
        .repack(&repaired)
        .ok_or("codec encode refused")?;
    let decoded = match &target.kernel {
        Some(k) => Envelope::load_with_kernel(&encoded, k),
        None => Envelope::load(&encoded),
    }
    .map_err(|e| format!("codec decode: {e:?}"))?;
    assert_eq!(decoded.image, repaired);
    operation
        .verify(&preparation, &decoded.image)
        .map_err(|e| format!("decoded verify: {e:?}"))?;
    selected
        .verify_with(&preparation, &decoded.image, registry)
        .map_err(|e| format!("decoded runner verify: {e:?}"))?;
    let after = Context::new(Firmware {
        normal: &decoded.image,
        ..b.firmware
    });
    assert_eq!(loading_channel::FILTER.inspect(&after).finding, x.finding);
    assert_eq!(loading::FILTER.inspect(&after).finding, before_y.finding);
    assert_eq!(
        loading_channel::FILTER.candidate(&b, &y),
        loading_channel::FILTER.candidate(&after, &loading_channel::FILTER.inspect(&after))
    );
    let back = loading_channel::FILTER
        .plan(
            &Transition {
                installed: &b,
                target: &after,
            },
            &y,
            &loading_channel::FILTER.inspect(&after),
        )
        .map_err(|e| format!("plan: {e:?}"))?
        .ok_or("missing correction operation")?;
    let reverse = Preparation {
        target: after.firmware,
        normal: Some(&decoded),
        kernel: target.kernel.as_ref(),
    };
    let back_bytes = back
        .prepare(&reverse)
        .map_err(|e| format!("reverse prepare: {e:?}"))?
        .ok_or("missing reverse image")?;
    let restored = (back.integrity().unwrap().repair)(&reverse, &back_bytes)
        .map_err(|e| format!("reverse integrity: {e:?}"))?;
    assert_eq!(restored, target.normal.image);
    for at in patched
        .iter()
        .zip(&target.normal.image)
        .enumerate()
        .filter_map(|(at, (a, b))| (a != b).then_some(at))
    {
        let mut damaged = patched.clone();
        damaged[at] = target.normal.image[at];
        assert!(
            operation.verify(&preparation, &damaged).is_err(),
            "lost mapped operand at {at:x}"
        );
    }
    let mut stale = target.normal.image.clone();
    stale[24] ^= 1;
    let stale = Preparation {
        target: Firmware {
            normal: &stale,
            ..b.firmware
        },
        normal: None,
        kernel: None,
    };
    assert_eq!(
        operation.prepare(&stale).unwrap_err(),
        Error::ComponentMismatch
    );
    Ok(())
}
#[test]
#[ignore = "requires exact encoded PIONEER_PHASE_CORPUS components"]
fn real_channel_correction_preserves_independent_requirements_and_roundtrips() {
    let five = load(FIVE);
    let seven = load(SEVEN);
    for (source, target) in [(&five, &seven), (&seven, &five)] {
        exercise(source, target).unwrap();
        let a = context(source);
        let b = context(target);
        assert_ne!(
            loading::FILTER.inspect(&a).finding,
            loading::FILTER.inspect(&b).finding
        );
        let plan = runner::evaluate(&a, &b, Policy::Strict).unwrap();
        assert_eq!(plan.admit(), Err(Error::Incompatible));
        let x = plan
            .decisions()
            .iter()
            .find(|d| d.id == loading_channel::FILTER.id())
            .unwrap();
        assert!(x.operation().is_some());
        assert!(x.blocked().is_none());
        let y = plan
            .decisions()
            .iter()
            .find(|d| d.id == loading::FILTER.id())
            .unwrap();
        assert_eq!(y.blocked(), Some(Error::Incompatible));
    }
}
#[test]
fn unbound_patterns_are_not_correction_proof() {
    let direct = [0xf8, 0x20, 0x6a, 0x88, 0xff, 0xc5];
    let bit = [0x6a, 0x18, 0xff, 0xc5, 0x72, 0x50];
    let a = Context::new(Firmware {
        hardware: "SAT 8600",
        normal: &direct,
        kernel: None,
    });
    let b = Context::new(Firmware {
        hardware: "SAT 8801",
        normal: &bit,
        kernel: None,
    });
    let x = loading_channel::FILTER.inspect(&a);
    let y = loading_channel::FILTER.inspect(&b);
    assert!(matches!(
        loading_channel::FILTER.plan(
            &Transition {
                installed: &a,
                target: &b
            },
            &x,
            &y
        ),
        Err(Error::Incompatible)
    ));
    assert_eq!(loading_channel::FILTER.candidate(&b, &y), y.finding);
    assert!(filters::filters()
        .iter()
        .any(|f| f.id() == loading_channel::FILTER.id()));
}
/// CI alone exercises every complete binding in the held corpus; local work
/// runs the exact two-component test above rather than the entire inventory.
#[test]
#[ignore = "CI corpus coverage; requires exact PIONEER_PHASE_CORPUS components"]
fn every_bound_channel_image_roundtrips_in_ci() {
    assert_eq!(std::env::var("CI").as_deref(), Ok("true"));
    let five = load(FIVE);
    let seven = load(SEVEN);
    let inventory = inventory();
    let domain = inventory["domains"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["id"] == "h8sat")
        .unwrap();
    let shard: usize = std::env::var("PIONEER_PHASE_SHARD")
        .unwrap_or_else(|_| "0".into())
        .parse()
        .unwrap();
    let shards: usize = std::env::var("PIONEER_PHASE_SHARDS")
        .unwrap_or_else(|_| "1".into())
        .parse()
        .unwrap();
    assert!(shards > 0 && shard < shards && shards <= domain["records"].as_array().unwrap().len());
    let mut count = [0usize; 2];
    let mut unbound = [0usize; 2];
    let mut native = 0usize;
    let mut codec = 0usize;
    let mut failures = Vec::new();
    let mut records = 0usize;
    for (index, record) in domain["records"].as_array().unwrap().iter().enumerate() {
        if index % shards != shard {
            continue;
        }
        records += 1;
        let hash = record["normal"].as_str().unwrap();
        let pair = match load_pair(hash, record["kernel"].as_str()) {
            Ok(pair) => pair,
            Err(error) => {
                println!(
                    "{}",
                    serde_json::json!({"event":"loading-channel-record","normal":hash,"kernel":record["kernel"],"classification":"decode-unavailable","native":false,"codec":false,"error":error})
                );
                failures.push(format!("{hash}: {error}"));
                continue;
            }
        };
        let observed = context(&pair);
        let evidence = &observed.sat.as_ref().unwrap().irq;
        let Observation::Known(channel) = &evidence.channel else {
            if let Observation::Known(pioneer_optical::image::irq::Value::Controller {
                and_mask,
                or_mask: 0,
            }) = evidence.selected
            {
                if and_mask == 0xdf {
                    unbound[0] += 1;
                } else if and_mask == 0x7f {
                    unbound[1] += 1;
                }
            }
            println!(
                "{}",
                serde_json::json!({"event":"loading-channel-record","normal":hash,"kernel":record["kernel"],"classification":"outside-bound-domain","controller":format!("{:?}",evidence.selected),"binding":format!("{:?}",evidence.channel),"claim":"binding miss is not physical incompatibility"})
            );
            continue;
        };
        let (source, index, required) = if channel.mapping == Mapping::Five {
            (&seven, 0, Mapping::Seven)
        } else {
            (&five, 1, Mapping::Five)
        };
        count[index] += 1;
        let native_result = (|| -> Result<(), String> {
            let changed = channel
                .correct(&pair.normal.image, required)
                .ok_or("native correction refused")?;
            if !channel.verify(&pair.normal.image, &changed, required) {
                return Err("native verification failed".into());
            }
            let Observation::Known(back) = pioneer_optical::image::irq::discover(&changed).channel
            else {
                return Err("native rediscovery failed".into());
            };
            if back.correct(&changed, channel.mapping).as_deref()
                != Some(pair.normal.image.as_slice())
            {
                return Err("native reversal failed".into());
            }
            Ok(())
        })();
        if native_result.is_ok() {
            native += 1;
        }
        let native_ok = native_result.is_ok();
        let result = native_result.and_then(|_| exercise(source, &pair));
        if result.is_ok() {
            codec += 1;
        }
        println!(
            "{}",
            serde_json::json!({"event":"loading-channel-record","normal":hash,"kernel":record["kernel"],"classification":"bound-channel","mapping":format!("{:?}",channel.mapping),"auxiliary":format!("{:?}",channel.auxiliary),"native_mapping_proof":native_ok,"codec_and_runner_proof":result.is_ok(),"error":result.as_ref().err(),"scope":"channel facet only; independent requirements and full-pair admission remain separate"})
        );
        if let Err(error) = result {
            failures.push(format!("{hash}: {error}"));
        }
    }
    println!(
        "{}",
        serde_json::json!({"event":"loading-channel-summary","shard":shard,"shards":shards,"records":records,"bound_clear5_clear7":count,"recognized_but_unbound_clear5_clear7":unbound,"native_mapping_proofs":native,"codec_and_runner_proofs":codec,"failures":failures.len(),"universal_loading_correctability":false})
    );
    let expected_records = domain["records"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
        .filter(|(index, _)| index % shards == shard)
        .count();
    assert_eq!(
        records, expected_records,
        "every assigned record was examined"
    );
    // A shard may contain only unbound programs. The exact witness test proves
    // both mapped channels independently; don't infer a per-shard population.
    if shards == 1 {
        assert!(count.iter().all(|n| *n > 0), "no bound domain coverage");
    }
    assert!(
        failures.is_empty(),
        "{} unavailable obligations; first20={:?}",
        failures.len(),
        &failures[..failures.len().min(20)]
    );
}
