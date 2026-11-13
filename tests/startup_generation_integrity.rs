//! Final paired generation checks are distinct from structural sink discovery.
#![cfg(feature = "envelope")]
#![cfg(feature = "internals")]

use pioneer_optical::{
    compatibility::{Error, Firmware},
    envelope::{
        builder::{normal_authentication_from_kernel, NormalAuthentication},
        Update,
    },
    filters::{self, runner, Context, Filter, Preparation},
    startup::coverage::{
        preservation::{self, Kind},
        sinks,
    },
};
use sha2::{Digest, Sha256};

fn compact_normal() -> Vec<u8> {
    let fixtures: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/startup-native-sinks.json")).unwrap();
    let fixture = &fixtures[0];
    let mut normal = vec![0xff; fixture["size"].as_u64().unwrap() as usize];
    for span in fixture["spans"].as_array().unwrap() {
        let at = span[0].as_u64().unwrap() as usize;
        let hex = span[1].as_str().unwrap();
        for i in (0..hex.len()).step_by(2) {
            normal[at + i / 2] = u8::from_str_radix(&hex[i..i + 2], 16).unwrap();
        }
    }
    normal
}

fn repair_checksum(normal: &mut [u8]) {
    let sum = normal.chunks_exact(4).fold(0u32, |sum, word| {
        sum.wrapping_add(u32::from_be_bytes(word.try_into().unwrap()))
    });
    let old = u32::from_be_bytes(normal[16..20].try_into().unwrap());
    normal[16..20].copy_from_slice(&old.wrapping_sub(sum).to_be_bytes());
}

fn context<'a>(normal: &'a [u8], kernel: Option<&'a [u8]>) -> Context<'a> {
    Context::new(Firmware {
        hardware: "SAT 8000",
        normal,
        kernel,
    })
}

fn firmware(update: &Update) -> Firmware<'_> {
    Firmware {
        hardware: &update.normal().info().hardware_version,
        normal: &update.normal().image,
        kernel: Some(&update.kernel().image),
    }
}

#[test]
fn generation_requires_matching_present_bytes_only_after_positive_recognition() {
    let mut normal = compact_normal();
    let kernel = [0xff; 0x100];
    let local = preservation::discover_pair(&normal, None).unwrap();
    assert!(sinks::discover(&normal).is_some());
    assert!(!local.final_integrity(&normal, None));
    let paired = preservation::discover_pair(&normal, Some(&kernel)).unwrap();
    assert!(paired.final_integrity(&normal, Some(&kernel)));
    assert!(!paired.final_integrity(&normal[..0x28], Some(&kernel)));
    let truncated = &kernel[..0xfe];
    let paired = preservation::discover_pair(&normal, Some(truncated)).unwrap();
    assert!(!paired.final_integrity(&normal, Some(truncated)));
    normal[0x28] ^= 1;
    let paired = preservation::discover_pair(&normal, Some(&kernel)).unwrap();
    assert!(!paired.final_integrity(&normal, Some(&kernel)));

    // Remove the recognized predicate and its calls, preserving the unrelated
    // checksum and host predicates. An absent pattern creates no byte relation.
    let prefix = [0x6a, 0x28, 0, 0x40, 0, 0xfe, 0x6a, 0x29, 0, 0x41, 0, 0x28];
    let at = normal
        .windows(prefix.len())
        .position(|b| b == prefix)
        .unwrap();
    normal[at..at + 28].fill(0xff);
    let local = preservation::discover_pair(&normal, None).unwrap();
    assert!(local.final_integrity(&normal, None));
    let paired = preservation::discover_pair(&normal, Some(&kernel)).unwrap();
    assert!(paired.final_integrity(&normal, Some(&kernel)));
    let paired = preservation::discover_pair(&normal, Some(truncated)).unwrap();
    assert!(paired.final_integrity(&normal, Some(truncated)));
}

#[test]
fn preservation_refuses_source_or_target_generation_failures_and_missing_kernel() {
    let source = compact_normal();
    let mut target = source.clone();
    target[0x2200] ^= 1;
    let kernel = [0xff; 0x100];
    let mut bad_source = source.clone();
    bad_source[0x28] ^= 1;
    repair_checksum(&mut bad_source);
    let mut bad_target = target.clone();
    bad_target[0x28] ^= 1;
    repair_checksum(&mut bad_target);
    let registry: &[&dyn Filter] = &[&filters::startup::FILTER];
    for (source, target, kernel) in [
        (
            bad_source.as_slice(),
            target.as_slice(),
            Some(kernel.as_slice()),
        ),
        (
            source.as_slice(),
            bad_target.as_slice(),
            Some(kernel.as_slice()),
        ),
        (source.as_slice(), target.as_slice(), None),
        (source.as_slice(), target.as_slice(), Some(&kernel[..0xfe])),
    ] {
        let installed = context(source, kernel);
        let requested = context(target, kernel);
        let plan = runner::evaluate_with(&installed, &requested, runner::Policy::Strict, registry)
            .unwrap();
        assert!(plan.decisions()[0].operation().is_none());
        assert!(plan.admit().is_err());
    }
}

#[test]
fn exact_normal_cannot_bypass_recognized_generation_integrity() {
    let normal = compact_normal();
    let kernel = [0xff; 0x100];
    let mut wrong_kernel = kernel;
    wrong_kernel[0xfe] ^= 1;
    let mut aliased_kernel = kernel;
    aliased_kernel[0x80..0x84]
        .copy_from_slice(&sinks::discover(&normal).unwrap().entries[0].to_be_bytes());
    let registry: &[&dyn Filter] = &[&filters::startup::FILTER];
    let outcomes: Vec<_> = [
        (Some(kernel.as_slice()), Some(wrong_kernel.as_slice())),
        (Some(wrong_kernel.as_slice()), Some(wrong_kernel.as_slice())),
        (Some(wrong_kernel.as_slice()), Some(kernel.as_slice())),
        (
            Some(wrong_kernel.as_slice()),
            Some(aliased_kernel.as_slice()),
        ),
        (
            Some(aliased_kernel.as_slice()),
            Some(wrong_kernel.as_slice()),
        ),
        (None, None),
        (Some(&kernel[..0xfe]), Some(&kernel[..0xfe])),
    ]
    .into_iter()
    .map(|(source_kernel, target_kernel)| {
        let installed = context(&normal, source_kernel);
        let requested = context(&normal, target_kernel);
        let plan = runner::evaluate_with(&installed, &requested, runner::Policy::Strict, registry)
            .unwrap();
        assert!(plan.decisions()[0].operation().is_none());
        plan.admit()
    })
    .collect();
    assert_eq!(
        outcomes,
        vec![Err(Error::VerificationFailed); outcomes.len()]
    );
}

#[test]
fn unknown_exact_pair_remains_noop_but_changed_unbound_kernel_refuses() {
    let mut normal = compact_normal();
    // Break checksum-predicate eligibility while retaining the Normal reader.
    normal[0x2000] ^= 1;
    assert!(preservation::discover_pair(&normal, None).is_none());
    let kernel = [0xff; 0x100];
    let mut changed_kernel = kernel;
    changed_kernel[0x80] ^= 1;
    let registry: &[&dyn Filter] = &[&filters::startup::FILTER];
    let installed = context(&normal, Some(&kernel));
    let same = context(&normal, Some(&kernel));
    let plan = runner::plan_with(&installed, &same, runner::Policy::Strict, registry).unwrap();
    assert!(plan.operations().next().is_none());
    let changed = context(&normal, Some(&changed_kernel));
    assert!(runner::plan_with(&installed, &changed, runner::Policy::Strict, registry).is_err());

    // An otherwise recognized inventory cannot assign an unbound Kernel alias
    // to a known Normal predicate and fall through as an exact-pair no-op.
    let normal = compact_normal();
    let certificate = sinks::discover(&normal).unwrap();
    let mut aliased_kernel = kernel;
    aliased_kernel[0x80..0x84].copy_from_slice(&certificate.entries[0].to_be_bytes());
    assert!(preservation::discover_pair(&normal, Some(&aliased_kernel)).is_none());
    let installed = context(&normal, Some(&kernel));
    let changed = context(&normal, Some(&aliased_kernel));
    assert!(runner::plan_with(&installed, &changed, runner::Policy::Strict, registry).is_err());
    let supported = context(&normal, Some(&changed_kernel));
    let plan = runner::plan_with(&installed, &supported, runner::Policy::Strict, registry).unwrap();
    assert_eq!(plan.operations().count(), 1);
}

#[test]
fn composed_normal_header_change_refuses_even_with_compensated_checksum() {
    let source = compact_normal();
    let mut target = source.clone();
    target[0x2200] ^= 1;
    let kernel = [0xff; 0x100];
    let installed = context(&source, Some(&kernel));
    let requested = context(&target, Some(&kernel));
    let registry: &[&dyn Filter] = &[&filters::startup::FILTER];
    let plan = runner::plan_with(&installed, &requested, runner::Policy::Strict, registry).unwrap();
    let preparation = Preparation {
        target: requested.firmware,
        normal: None,
        kernel: None,
    };
    assert!(plan.prepare_with(&preparation, registry).unwrap().is_none());
    let mut changed = target.clone();
    changed[0x28] ^= 1;
    repair_checksum(&mut changed);
    let certificate = preservation::discover_pair(&target, Some(&kernel)).unwrap();
    assert!(certificate.preserves(&target, &changed, Some(&kernel)));
    assert_eq!(
        plan.verify_with(&preparation, &changed, registry),
        Err(Error::VerificationFailed)
    );
}

#[test]
#[ignore = "requires the four exact authenticated BDR-211M components"]
fn exact_w1_generation_checks_survive_authentication_and_full_composition() {
    let root = std::path::PathBuf::from(std::env::var("PIONEER_PHASE_CORPUS").unwrap());
    let read = |hash: &str| {
        let bytes = std::fs::read(root.join(format!("{hash}.enc"))).unwrap();
        assert_eq!(format!("{:x}", Sha256::digest(&bytes)), hash);
        bytes
    };
    let a_kernel = read("34086ec0b5fbaf14802ffd307c1a74b519dcc21dc5bf8f89bfb93c9966ca3662");
    let b_kernel = read("437f8a0fa28f326f1432b5c127951faed207dfdb9646462bc59bd9008f0296cf");
    let a = Update::load(
        &a_kernel,
        &read("0a486f059bcaf5f9e0b5ad21ca94b5a3da6f1b583cd24f09cdf653ec235321aa"),
    )
    .unwrap();
    let b = Update::load(
        &b_kernel,
        &read("12183b7e321946cab7911cf5573d0198d928b4b4d5982721c15e6bb238086ee6"),
    )
    .unwrap();
    for (source, target, kernel_bytes, kind) in [
        (&a, &b, &b_kernel, Kind::InstructionOwnedPredicates),
        (&b, &a, &a_kernel, Kind::NormalPredicates),
    ] {
        let installed = Context::new(firmware(source));
        let requested = Context::new(firmware(target));
        assert_eq!(target.normal().image[0x28], target.kernel().image[0xfe]);
        let plan = runner::plan(&installed, &requested, runner::Policy::Strict).unwrap();
        let preparation = Preparation {
            target: requested.firmware,
            normal: Some(target.normal()),
            kernel: Some(target.kernel()),
        };
        assert!(plan.prepare(&preparation).unwrap().is_none());
        let certificate =
            preservation::discover_pair(&target.normal().image, Some(&target.kernel().image))
                .unwrap();
        assert_eq!(certificate.kind(), kind);
        let mut changed = target.normal().image.clone();
        changed[0x28] ^= 1;
        // This exact InstructionOwned target has no recognized generation
        // predicate; its header is not assigned one by this local guard.
        if kind == Kind::InstructionOwnedPredicates {
            assert!(certificate.final_integrity(&changed, Some(&target.kernel().image)));
            continue;
        }
        let mut encoded = target.normal().repack_with_checksum(&changed).unwrap();
        // A caller-owned key exercises Update's mathematical authentication;
        // it makes no claim that a physical drive trusts this signing key.
        let signer = pioneer_optical::envelope::signature::SigningKey::from_bytes([7; 20]).unwrap();
        match normal_authentication_from_kernel(&target.kernel().image).unwrap() {
            NormalAuthentication::KeyAndCiphertext => signer.sign_normal(&mut encoded).unwrap(),
            NormalAuthentication::CiphertextOnly => {
                signer.sign_normal_ciphertext_only(&mut encoded).unwrap()
            }
            _ => panic!("expected a signed W1 Normal"),
        }
        let mismatched = Update::load(kernel_bytes, &encoded).unwrap();
        let certificate = preservation::discover_pair(
            &mismatched.normal().image,
            Some(&mismatched.kernel().image),
        )
        .unwrap();
        assert!(!certificate
            .final_integrity(&mismatched.normal().image, Some(&mismatched.kernel().image)));
        assert_eq!(
            plan.verify(&preparation, &mismatched.normal().image),
            Err(Error::VerificationFailed)
        );
        let bad = Context::new(firmware(&mismatched));
        for (source, target) in [(&installed, &bad), (&bad, &installed)] {
            let plan = runner::evaluate(source, target, runner::Policy::Strict).unwrap();
            let startup = plan
                .decisions()
                .iter()
                .find(|d| d.id == "startup-prerequisite")
                .unwrap();
            assert!(startup.operation().is_none());
            assert!(plan.admit().is_err());
        }
    }
}
