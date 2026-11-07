//! Focused typed evidence checks; private native inputs stay outside the repository.
#![cfg(feature = "envelope")]
use pioneer_optical::startup::{
    self,
    coverage::sinks,
    inspection::{
        self, PreservationScope, ReaderEvidenceState, RequirementObservation, RootedObligation,
    },
};

fn compact_certificate() -> Vec<u8> {
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

#[test]
fn scoped_preservation_retains_rooted_obligations_and_legacy_discovery() {
    let normal = compact_certificate();
    let before = sinks::discover(&normal).unwrap();
    let result = inspection::inspect(&normal, None);
    assert!(matches!(result.reader(), ReaderEvidenceState::Normal(_)));
    assert!(matches!(
        result.requirement(),
        RequirementObservation::NoSupportedComparison
    ));
    let witness = result.preservation().unwrap();
    assert_eq!(witness.scope(), PreservationScope::LocalPredicates);
    assert_eq!(witness.certificate().normal_predicates(), &before);
    assert!(result.sink_failure().is_none());
    assert!(result
        .rooted_obligations()
        .contains(&RootedObligation::Native(
            startup::coverage::assessment::Obligation::StartupPath
        )));
    let alias = before.entries[0].to_be_bytes();
    let paired = inspection::inspect(&normal, Some(&alias));
    assert!(paired.preservation().is_none());
    assert_eq!(
        paired.sink_failure(),
        Some(&sinks::Failure::Unsupported {
            stage: sinks::Stage::KernelAliases
        })
    );
    assert_eq!(sinks::discover(&normal), Some(before));
}

#[test]
#[ignore = "requires STARTUP_NATIVE_INPUTS exact encoded native fixtures"]
fn named_native_inspection_preserves_readers_and_exact_reference_failures() {
    use pioneer_optical::envelope::{Envelope, Update};
    use sha2::{Digest, Sha256};
    let root = std::path::PathBuf::from(std::env::var("STARTUP_NATIVE_INPUTS").unwrap());
    let read = |hash: &str| {
        let bytes = std::fs::read(root.join(format!("{hash}.enc"))).unwrap();
        assert_eq!(format!("{:x}", Sha256::digest(&bytes)), hash);
        bytes
    };
    let pair = |normal: &str, kernel: &str| {
        let normal_bytes = read(normal);
        let kernel_bytes = read(kernel);
        let update = Update::load(&kernel_bytes, &normal_bytes).unwrap();
        for (hash, encoded, authenticated) in [
            (normal, &normal_bytes, update.normal()),
            (kernel, &kernel_bytes, update.kernel()),
        ] {
            let standalone = Envelope::load(encoded).unwrap();
            let recovered = standalone
                .image
                .iter()
                .zip(&authenticated.image)
                .filter(|(a, b)| a != b)
                .count();
            println!("encoded={hash} decoded={:x} standalone_decoded={:x} recovered_byte_count={recovered}", Sha256::digest(&authenticated.image), Sha256::digest(&standalone.image));
        }
        update
    };
    let resident = pair(
        "62b5761dff779bf89765c8de7dec3b470ade42f15c25f31bb244035bd9069f08",
        "8cb61be9c341d749e61cd125b8259a36441fc129efa59fe11d64a80c69f7b2e9",
    );
    let r = inspection::inspect(&resident.normal().image, Some(&resident.kernel().image));
    let ReaderEvidenceState::Resident { kernel_id, .. } = r.reader() else {
        panic!("{:?}", r.reader())
    };
    assert_eq!(
        *kernel_id,
        <[u8; 32]>::from(Sha256::digest(&resident.kernel().image))
    );
    assert!(matches!(
        r.requirement(),
        RequirementObservation::NoSupportedComparison
    ));
    assert!(r
        .rooted_obligations()
        .iter()
        .any(|o| matches!(o, RootedObligation::ResidentConsumers { .. })));
    assert!(!r.rooted_obligations().iter().any(|o| matches!(
        o,
        RootedObligation::Native(startup::coverage::assessment::Obligation::Reader(_))
    )));

    let missing = Envelope::load(&read(
        "01db920b995420d8fa5c1d1a0927d1480ef2b7df11a6941a12ee3878617fa156",
    ))
    .unwrap();
    assert!(matches!(
        inspection::inspect(&missing.image, None).reader(),
        ReaderEvidenceState::MissingResident { entry: 4212258 }
    ));
    let sat1 = pair(
        "2fbd27764be34ebb9a95e898d4e53afa5f67435b7fd324adbfde7411a386466c",
        "c834e7b2b7281121eceda84d67f00f73fe2b3036a58ebeae547b4a0a10b1a3a0",
    );
    assert!(matches!(
        inspection::inspect(&sat1.normal().image, Some(&sat1.kernel().image)).reader(),
        ReaderEvidenceState::Normal(_)
    ));

    // The unchanged existing source certificate and W1's pre-extension refusal.
    let source = pair(
        "0a486f059bcaf5f9e0b5ad21ca94b5a3da6f1b583cd24f09cdf653ec235321aa",
        "34086ec0b5fbaf14802ffd307c1a74b519dcc21dc5bf8f89bfb93c9966ca3662",
    );
    assert!(
        inspection::inspect(&source.normal().image, Some(&source.kernel().image))
            .preservation()
            .is_some()
    );
    let target = pair(
        "12183b7e321946cab7911cf5573d0198d928b4b4d5982721c15e6bb238086ee6",
        "437f8a0fa28f326f1432b5c127951faed207dfdb9646462bc59bd9008f0296cf",
    );
    assert_eq!(
        sinks::diagnose(&target.normal().image),
        Err(sinks::Failure::UnclassifiedAddressReference {
            stage: sinks::Stage::ClosedEntries,
            at: 0xdc430,
            target: 0x456eb8
        })
    );
    for (hash, stage, at, target) in [
        (
            "19ee9b3468677a2fcc1fa633cb8767a49e87f68481fa2b20299e6f5221b3ed1a",
            sinks::Stage::RejectCalls,
            0x1874ac,
            0x4b1016,
        ),
        (
            "1d669f937d6d453b37d1be3ea0161556da287216cc024796ab69575ec6b022bc",
            sinks::Stage::ValidatorCalls,
            0x16471c,
            0x550000,
        ),
    ] {
        // Source records have no Kernel; do not substitute one.
        let normal = Envelope::load(&read(hash)).unwrap();
        assert_eq!(
            sinks::diagnose(&normal.image),
            Err(sinks::Failure::UnclassifiedAddressReference { stage, at, target })
        );
        assert!(sinks::discover(&normal.image).is_none());
    }
}
