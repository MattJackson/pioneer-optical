//! Exact-component evidence for the guarded mapped-channel correction.
//! The independent V5C/input gate deliberately prevents whole-pair admission.
#![cfg(feature = "envelope")]
use pioneer_optical::{
    compatibility::{Error, Firmware},
    envelope::{Envelope, KernelXorPolicy, Update},
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
fn component(hash: &str) -> Result<Vec<u8>, String> {
    let root = std::env::var("PIONEER_PHASE_CORPUS").expect("PIONEER_PHASE_CORPUS");
    let bytes = std::fs::read(std::path::Path::new(&root).join(format!("{hash}.enc")))
        .map_err(|e| format!("read {hash}: {e}"))?;
    if format!("{:x}", Sha256::digest(&bytes)) != hash {
        return Err(format!("SHA256 mismatch: {hash}"));
    }
    Ok(bytes)
}
fn load_pair(hash: &str, kernel: Option<&str>) -> Result<Pair, String> {
    let bytes = component(hash)?;
    let kernel = kernel
        .map(|hash| Envelope::load(&component(hash)?).map_err(|e| format!("Kernel decode: {e:?}")))
        .transpose()?;
    let normal = match &kernel {
        Some(k) => Envelope::load_with_kernel(&bytes, k),
        None => Envelope::load(&bytes),
    }
    .map_err(|e| format!("Normal decode: {e:?}"))?;
    Ok(Pair { normal, kernel })
}
fn conditional_manifest() -> serde_json::Value {
    serde_json::from_str(include_str!("fixtures/phase-conditional-receivers.json")).unwrap()
}
fn unavailable_manifest() -> serde_json::Value {
    serde_json::from_str(include_str!("fixtures/phase-unavailable-receivers.json")).unwrap()
}
fn checksum(bytes: &[u8]) -> u32 {
    assert_eq!(bytes.len() % 4, 0);
    bytes.chunks_exact(4).fold(0u32, |sum, w| {
        sum.wrapping_add(u32::from_be_bytes(w.try_into().unwrap()))
    })
}
fn load_conditional(
    record: &serde_json::Value,
    receiver: &serde_json::Value,
) -> Result<Pair, String> {
    assert!(
        record["kernel"].is_null(),
        "conditional receiver never replaces packaged Kernel"
    );
    assert_eq!(receiver["association"], "conditional-receiver-context");
    assert!(!receiver["provenance"].as_array().unwrap().is_empty());
    let hash = record["normal"].as_str().unwrap();
    let kernel_hash = receiver["kernel"].as_str().unwrap();
    let update = Update::load(&component(kernel_hash)?, &component(hash)?)
        .map_err(|e| format!("conditional Update::load {kernel_hash}: {e:?}"))?;
    let pair = Pair {
        normal: update.normal().clone(),
        kernel: Some(update.kernel().clone()),
    };
    let n = pair.normal.header_info();
    let k = pair.kernel.as_ref().unwrap().header_info();
    for (a, b) in [
        (&n.hardware_version, &k.hardware_version),
        (&n.destination, &k.destination),
        (&n.kernel_version, &k.kernel_version),
        (&n.kernel_version2, &k.kernel_version2),
    ] {
        assert!(!a.is_empty());
        assert_eq!(a, b, "conditional header identity");
    }
    assert_eq!(
        pair.normal.info().hardware_version,
        record["hardware"].as_str().unwrap()
    );
    let policy = KernelXorPolicy::from_kernel(pair.kernel.as_ref().unwrap())
        .ok_or("conditional receiver policy unavailable")?;
    assert_eq!(
        serde_json::to_value(policy).unwrap(),
        receiver["native_xor_policy"]
    );
    assert_eq!(
        format!("{:x}", Sha256::digest(&pair.normal.image)),
        receiver["decoded_normal_sha256"].as_str().unwrap()
    );
    assert_eq!(checksum(&pair.normal.image), 0);
    println!(
        "{}",
        serde_json::json!({"event":"loading-conditional-receiver-authenticated","normal":hash,"packaged_kernel":null,"selected_receiver":kernel_hash,"association":"conditional-receiver-context","actual_installed_kernel":"unknown","checks":"Update::load + four headers + pinned native policy + pinned decoded digest + zero checksum"})
    );
    Ok(pair)
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
fn prove_native(pair: &Pair, required: Mapping) -> Result<(), String> {
    let observed = context(pair);
    let Observation::Known(channel) = &observed.sat.as_ref().unwrap().irq.channel else {
        return Err("native channel unavailable".into());
    };
    let changed = channel
        .correct(&pair.normal.image, required)
        .ok_or("native correction refused")?;
    if !channel.verify(&pair.normal.image, &changed, required) {
        return Err("native verification failed".into());
    }
    let Observation::Known(back) = pioneer_optical::image::irq::discover(&changed).channel else {
        return Err("native rediscovery failed".into());
    };
    if back.correct(&changed, channel.mapping).as_deref() != Some(pair.normal.image.as_slice()) {
        return Err("native reversal failed".into());
    }
    Ok(())
}
fn prove_missing_context_refusal(source: &Pair, target: &Pair) -> Result<(), String> {
    if target.kernel.is_some() || checksum(&target.normal.image) == 0 {
        return Err("missing-context refusal lacks standalone invalid-checksum evidence".into());
    }
    let a = context(source);
    let b = context(target);
    let Observation::Known(channel) = &b.sat.as_ref().unwrap().irq.channel else {
        return Err("missing-context native channel unavailable".into());
    };
    let required = if channel.mapping == Mapping::Five {
        Mapping::Seven
    } else {
        Mapping::Five
    };
    let mapped = channel
        .correct(&target.normal.image, required)
        .ok_or("missing-context native correction failed")?;
    let registry: &[&dyn Filter] = &[&loading_channel::FILTER];
    let plan = runner::plan_with(&a, &b, Policy::Strict, registry)
        .map_err(|e| format!("missing-context plan: {e:?}"))?;
    let preparation = Preparation {
        target: b.firmware,
        normal: Some(&target.normal),
        kernel: None,
    };
    plan.verify_with(&preparation, &mapped, registry)
        .map_err(|e| format!("missing-context native runner verify: {e:?}"))?;
    match plan.prepare_with(&preparation, registry) {
        Err(Error::Representation) => {}
        Err(e) => return Err(format!("unexpected missing-context refusal: {e:?}")),
        Ok(_) => return Err("missing-context preparation unexpectedly accepted".into()),
    }
    let integrity = plan.decisions()[0]
        .operation()
        .ok_or("missing-context operation absent")?
        .integrity()
        .ok_or("missing-context integrity absent")?;
    match (integrity.repair)(&preparation, &mapped) {
        Err(Error::Representation) => Ok(()),
        Err(e) => Err(format!(
            "unexpected missing-context integrity refusal: {e:?}"
        )),
        Ok(_) => Err("missing-context integrity unexpectedly accepted".into()),
    }
}
fn validate_unavailable(record: &serde_json::Value, pair: &Pair, pin: &serde_json::Value) {
    assert_eq!(record["normal"], pin["normal"]);
    assert_eq!(record["hardware"], pin["hardware"]);
    assert!(record["kernel"].is_null() && pair.kernel.is_none());
    assert_eq!(pin["refusal"], "Representation");
    assert_eq!(
        format!("{:x}", Sha256::digest(&pair.normal.image)),
        pin["standalone_decoded_sha256"].as_str().unwrap()
    );
    assert_eq!(
        u64::from(checksum(&pair.normal.image)),
        pin["standalone_be32_sum"].as_u64().unwrap()
    );
    assert_ne!(checksum(&pair.normal.image), 0);
    let observed = context(pair);
    let preparation = Preparation {
        target: observed.firmware,
        normal: Some(&pair.normal),
        kernel: None,
    };
    assert_eq!(
        (filters::be32_normal_integrity().repair)(&preparation, &pair.normal.image),
        Err(Error::Representation),
        "pinned original has no checksum authority even outside the mapped-channel domain"
    );
}
#[test]
#[ignore = "requires one exact conditional receiver and original corpus components"]
fn conditional_loading_receiver_is_authenticated_and_not_packaged() {
    let hash = "10074482e4e69b0ecaae472a89b17072e817dc3c6df43e1f6ce35afaf7bab325";
    let inv = inventory();
    let record = inv["domains"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|d| d["records"].as_array().unwrap())
        .find(|r| r["normal"] == hash)
        .unwrap();
    let manifest = conditional_manifest();
    let row = manifest["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["normal"] == hash)
        .unwrap();
    assert!(row["packaged_kernel"].is_null());
    let standalone = load_pair(hash, None).unwrap();
    let conditional = load_conditional(record, &row["receivers"][0]).unwrap();
    let before = context(&standalone);
    let after = context(&conditional);
    assert!(
        matches!(
            after.sat.as_ref().unwrap().irq.channel,
            Observation::Unresolved(_)
        ),
        "this authentication witness does not establish a supported correction domain"
    );
    assert_eq!(
        loading_channel::FILTER.inspect(&before).finding,
        loading_channel::FILTER.inspect(&after).finding
    );
    let installed = load(SEVEN);
    let installed = context(&installed);
    assert!(matches!(
        loading_channel::FILTER.plan(
            &Transition {
                installed: &installed,
                target: &after
            },
            &loading_channel::FILTER.inspect(&installed),
            &loading_channel::FILTER.inspect(&after)
        ),
        Err(Error::Incompatible)
    ));
    assert!(
        record["kernel"].is_null(),
        "package inventory remains unchanged"
    );
}
#[test]
#[ignore = "requires one exact pinned unavailable receiver context"]
fn known_unavailable_loading_receiver_retains_native_and_integrity_refusals() {
    let hash = "5f8438bf528b55bbf778e64d743ad5e93835e1d43b0ff04fd1107b84103a019a";
    let inv = inventory();
    let record = inv["domains"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|d| d["records"].as_array().unwrap())
        .find(|r| r["normal"] == hash)
        .unwrap();
    let manifest = unavailable_manifest();
    let pin = manifest["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["normal"] == hash)
        .unwrap();
    assert!(conditional_manifest()["records"]
        .as_array()
        .unwrap()
        .iter()
        .all(|r| r["normal"] != hash));
    let standalone = load_pair(hash, None).unwrap();
    validate_unavailable(record, &standalone, pin);
    let source = load(FIVE);
    let a = context(&source);
    let b = context(&standalone);
    assert!(matches!(
        b.sat.as_ref().unwrap().irq.channel,
        Observation::Unresolved(_)
    ));
    assert!(
        matches!(
            loading_channel::FILTER.plan(
                &Transition {
                    installed: &a,
                    target: &b
                },
                &loading_channel::FILTER.inspect(&a),
                &loading_channel::FILTER.inspect(&b)
            ),
            Err(Error::Incompatible)
        ),
        "native binding is unavailable independently of checksum authority"
    );
}
#[test]
#[ignore = "requires exact packaged Seven component with deliberately omitted Kernel"]
fn omitted_packaged_kernel_is_an_explicit_negative_control() {
    // This is a controlled context omission, not a newly discovered missing
    // receiver record, and it never enters the corpus exception fixture.
    let standalone = load_pair(SEVEN, None).unwrap();
    prove_native(&standalone, Mapping::Five).unwrap();
    prove_missing_context_refusal(&load(FIVE), &standalone).unwrap();
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
    let supplemental = conditional_manifest();
    let unavailable = unavailable_manifest();
    let mut count = [0usize; 2];
    let mut conditional_bound = [0usize; 2];
    let mut unbound = [0usize; 2];
    let mut native = 0usize;
    let mut codec = 0usize;
    let mut conditional_native = 0usize;
    let mut conditional_codec = 0usize;
    let mut conditional_variants = 0usize;
    let mut safe_refusals = 0usize;
    let mut missing_receiver_records = 0usize;
    let mut failures = Vec::new();
    let mut records = 0usize;
    for (index, record) in domain["records"].as_array().unwrap().iter().enumerate() {
        if index % shards != shard {
            continue;
        }
        records += 1;
        let hash = record["normal"].as_str().unwrap();
        let packaged = record["kernel"].as_str();
        let conditional = supplemental["records"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["normal"] == hash);
        let negative = unavailable["records"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["normal"] == hash);
        assert!(
            !(conditional.is_some() && negative.is_some()),
            "receiver-positive and unavailable fixtures overlap"
        );
        if negative.is_some() {
            assert!(packaged.is_none());
            missing_receiver_records += 1;
        }
        let mut contexts = vec![(None, load_pair(hash, packaged))];
        if let Some(row) = conditional {
            assert!(packaged.is_none() && row["packaged_kernel"].is_null());
            assert!(!row["receivers"].as_array().unwrap().is_empty());
            for receiver in row["receivers"].as_array().unwrap() {
                conditional_variants += 1;
                contexts.push((Some(receiver), load_conditional(record, receiver)));
            }
        }
        for (receiver, pair) in contexts {
            let conditional_context = receiver.is_some();
            let selected_receiver = receiver.and_then(|r| r["kernel"].as_str()).or(packaged);
            let association = if conditional_context {
                "conditional-receiver-context"
            } else if packaged.is_some() {
                "packaged-kernel"
            } else {
                "standalone-no-receiver"
            };
            let pair = match pair {
                Ok(pair) => pair,
                Err(error) => {
                    println!(
                        "{}",
                        serde_json::json!({"event":"loading-channel-record","normal":hash,"packaged_kernel":packaged,"selected_receiver":selected_receiver,"association":association,"actual_installed_kernel":"unknown","classification":"decode-unavailable","native":false,"codec":false,"error":error})
                    );
                    failures.push(format!(
                        "{hash} {association} {selected_receiver:?}: {error}"
                    ));
                    continue;
                }
            };
            if !conditional_context {
                if let Some(pin) = negative {
                    validate_unavailable(record, &pair, pin);
                }
            }
            let observed = context(&pair);
            let evidence = &observed.sat.as_ref().unwrap().irq;
            let Observation::Known(channel) = &evidence.channel else {
                if !conditional_context {
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
                }
                println!(
                    "{}",
                    serde_json::json!({"event":"loading-channel-record","normal":hash,"packaged_kernel":packaged,"selected_receiver":selected_receiver,"association":association,"actual_installed_kernel":"unknown","classification":"outside-bound-domain","controller":format!("{:?}",evidence.selected),"binding":format!("{:?}",evidence.channel),"claim":"binding miss is not physical incompatibility","pinned_original_integrity_refusal":if !conditional_context && negative.is_some(){Some("Representation")}else{None},"delivery_coverage_complete":false})
                );
                continue;
            };
            let (source, index, required) = if channel.mapping == Mapping::Five {
                (&seven, 0, Mapping::Seven)
            } else {
                (&five, 1, Mapping::Five)
            };
            if conditional_context {
                conditional_bound[index] += 1;
            } else {
                count[index] += 1;
            }
            let native_result = prove_native(&pair, required);
            let native_ok = native_result.is_ok();
            if native_ok {
                if conditional_context {
                    conditional_native += 1;
                } else {
                    native += 1;
                }
            }
            let result = native_result.and_then(|_| exercise(source, &pair));
            let mut expected_safe_refusal = false;
            let mut unexpected = result.as_ref().err().cloned();
            // Only a pinned original absent-context input may use this exact
            // negative contract. Native/plan/verification failures never qualify.
            if !conditional_context
                && packaged.is_none()
                && (conditional.is_some() || negative.is_some())
                && native_ok
                && result.as_ref().err().map(String::as_str) == Some("prepare: Representation")
            {
                match prove_missing_context_refusal(source, &pair) {
                    Ok(()) => {
                        expected_safe_refusal = true;
                        safe_refusals += 1;
                        unexpected = None;
                    }
                    Err(error) => unexpected = Some(error),
                }
            }
            if result.is_ok() {
                if conditional_context {
                    conditional_codec += 1;
                } else {
                    codec += 1;
                }
            }
            println!(
                "{}",
                serde_json::json!({"event":"loading-channel-record","normal":hash,"packaged_kernel":packaged,"selected_receiver":selected_receiver,"association":association,"actual_installed_kernel":"unknown","classification":"bound-channel","mapping":format!("{:?}",channel.mapping),"auxiliary":format!("{:?}",channel.auxiliary),"native_mapping_proof":native_ok,"codec_and_runner_proof":result.is_ok(),"expected_safe_missing_context_refusal":expected_safe_refusal,"error":result.as_ref().err(),"unexpected_error":unexpected,"delivery_coverage_complete":false,"scope":"channel facet only; conditional receivers are not package/installed identity; independent requirements and full-pair admission remain separate"})
            );
            if let Some(error) = unexpected {
                failures.push(format!(
                    "{hash} {association} {selected_receiver:?}: {error}"
                ));
            }
        }
    }
    println!(
        "{}",
        serde_json::json!({"event":"loading-channel-summary","shard":shard,"shards":shards,"records":records,"original_context_bound_clear5_clear7":count,"recognized_but_unbound_clear5_clear7":unbound,"original_native_mapping_proofs":native,"original_codec_and_runner_proofs":codec,"conditional_variants":conditional_variants,"conditional_bound_clear5_clear7":conditional_bound,"conditional_native_mapping_proofs":conditional_native,"conditional_codec_and_runner_proofs":conditional_codec,"expected_safe_missing_context_refusals":safe_refusals,"records_without_listed_receiver_context":missing_receiver_records,"failures":failures.len(),"universal_loading_correctability":false,"delivery_coverage_complete":false})
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
    if std::env::var("PIONEER_PHASE_REQUIRE_DELIVERY").as_deref() == Ok("1") {
        assert_eq!(
            missing_receiver_records, 0,
            "delivery remains incomplete without authentic receiver contexts"
        );
    }
    assert!(
        failures.is_empty(),
        "{} unavailable obligations; first20={:?}",
        failures.len(),
        &failures[..failures.len().min(20)]
    );
}

#[test]
#[ignore = "requires the exact private corpus components"]
fn relocated_diagnostic_identifiers_preserve_channel_binding() {
    const WX1: &str = "9b44cfbe5134d4f992b4f1b6e4cdea930c61f83cdbd6808f858f87ba27eedb23";
    let target = load(WX1);
    let source = load(SEVEN);
    Update::load(
        &component("100ebef645a65f7e1ac99b5558fd20885f9ac2db8c3f649df0a11bc48e2ef0fc").unwrap(),
        &component(WX1).unwrap(),
    )
    .unwrap();
    prove_native(&target, Mapping::Seven).unwrap();
    exercise(&source, &target).unwrap();
    exercise(&target, &source).unwrap();
    let original = load(FIVE);
    assert_eq!(
        loading::FILTER.inspect(&context(&original)).finding,
        loading::FILTER.inspect(&context(&target)).finding
    );
    // Original BDE codec roundtrip is distinct from original package authentication.
    assert!(matches!(
        Update::load(
            &component("05fc3aaa7f86ecb69107b75d5c1ec4ea5dbd23b6671673327ccb4c6b9cf1448b").unwrap(),
            &component(FIVE).unwrap()
        ),
        Err(pioneer_optical::envelope::UpdateError::Authentication)
    ));
    // The relocated operands may only feed the positively bound in-range
    // identifier branch. Wrong role, out-of-range tag, or dereference reject.
    for (offset, value) in [
        (0x16b4cc + 90, 0xff),
        (0x13c4fc + 0x184, 0x46),
        (0x13bc4c + 56, 0x5a),
    ] {
        let mut changed = target.normal.image.clone();
        changed[offset] = value;
        assert!(
            !matches!(
                pioneer_optical::image::irq::discover(&changed).channel,
                Observation::Known(_)
            ),
            "mutation at {offset:x}"
        );
    }
}
