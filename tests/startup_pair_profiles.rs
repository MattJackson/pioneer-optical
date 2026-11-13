//! Exact pair profiles through the full filter composition path.
#![cfg(feature = "envelope")]
#![cfg(feature = "internals")]

use pioneer_optical::{
    compatibility::{Error, Firmware},
    envelope::Update,
    filters::{runner, Context, Preparation},
    startup::coverage::preservation::{self, Kind},
};
use sha2::{Digest, Sha256};

fn pair(normal: &str, kernel: &str) -> Update {
    let root = std::path::PathBuf::from(std::env::var("PIONEER_PHASE_CORPUS").unwrap());
    let read = |hash: &str| {
        let bytes = std::fs::read(root.join(format!("{hash}.enc"))).unwrap();
        assert_eq!(format!("{:x}", Sha256::digest(&bytes)), hash);
        bytes
    };
    Update::load(&read(kernel), &read(normal)).unwrap()
}

fn firmware(update: &Update) -> Firmware<'_> {
    Firmware {
        hardware: &update.normal().info().hardware_version,
        normal: &update.normal().image,
        kernel: Some(&update.kernel().image),
    }
}

fn unchanged_directions(a: &Update, b: &Update) {
    for (source, target) in [(a, b), (b, a)] {
        let source_context = Context::new(firmware(source));
        let target_context = Context::new(firmware(target));
        let plan = runner::plan(&source_context, &target_context, runner::Policy::Strict).unwrap();
        assert!(plan.required_words().unwrap().is_empty());
        assert!(plan.decisions().iter().all(|decision| !decision.waived));
        let context = Preparation {
            target: firmware(target),
            normal: Some(target.normal()),
            kernel: Some(target.kernel()),
        };
        assert_eq!(plan.prepare(&context).unwrap(), None);
        plan.verify(&context, &target.normal().image).unwrap();
        let certificate =
            preservation::discover_pair(&target.normal().image, Some(&target.kernel().image))
                .unwrap();
        let mut changed = target.normal().image.clone();
        changed[certificate.protected_spans()[0].start] ^= 1;
        assert_eq!(
            plan.verify(&context, &changed),
            Err(Error::VerificationFailed)
        );
        let mut wrong_kernel = target.kernel().image.clone();
        wrong_kernel[0x100] ^= 1;
        let wrong_context = Preparation {
            target: Firmware {
                kernel: Some(&wrong_kernel),
                ..firmware(target)
            },
            normal: None,
            kernel: None,
        };
        assert_eq!(
            plan.verify(&wrong_context, &target.normal().image),
            Err(Error::ComponentMismatch)
        );
    }
}

#[test]
#[ignore = "requires the four exact authenticated BDR-211M components"]
fn bdr211m_pair_profile_composes_without_editing_firmware_or_parameters() {
    let a = pair(
        "0a486f059bcaf5f9e0b5ad21ca94b5a3da6f1b583cd24f09cdf653ec235321aa",
        "34086ec0b5fbaf14802ffd307c1a74b519dcc21dc5bf8f89bfb93c9966ca3662",
    );
    let b = pair(
        "12183b7e321946cab7911cf5573d0198d928b4b4d5982721c15e6bb238086ee6",
        "437f8a0fa28f326f1432b5c127951faed207dfdb9646462bc59bd9008f0296cf",
    );
    assert_eq!(
        preservation::discover_pair(&b.normal().image, Some(&b.kernel().image))
            .unwrap()
            .kind(),
        Kind::InstructionOwnedPredicates
    );
    assert!(preservation::discover_pair(&b.normal().image, None).is_none());
    use pioneer_optical::startup::checks::{Checks, Error as StartupError, Policy};
    for (source, target, query) in [(&a, &b, 0x57ba40usize), (&b, &a, 0x57c4ee)] {
        let installed = Checks::discover(&source.normal().image, Some(&source.kernel().image));
        for policy in [Policy::CompatibleBanks, Policy::ExplicitCrossflash] {
            installed
                .plan_to_with_policy(
                    Checks::discover(&target.normal().image, Some(&target.kernel().image)),
                    policy,
                )
                .unwrap();
            let mut changed = target.normal().image.clone();
            changed[query - 0x410000] ^= 1;
            assert_eq!(
                installed.plan_to_with_policy(
                    Checks::discover(&changed, Some(&target.kernel().image)),
                    policy,
                ),
                Err(StartupError::CapacityRelationUnproved)
            );
            // Resident services are an external OEM interface: the relation
            // keeps the discriminator's call target, not the Kernel's bytes.
            let mut changed_kernel = target.kernel().image.clone();
            changed_kernel[0xb6f4] ^= 1;
            assert!(installed
                .plan_to_with_policy(
                    Checks::discover(&target.normal().image, Some(&changed_kernel)),
                    policy,
                )
                .is_ok());
            let start = query - 0x410000;
            let resident = start
                + target.normal().image[start..start + 0x80]
                    .windows(4)
                    .position(|w| w == [0x5e, 0x10, 0x7c, 0x72])
                    .unwrap();
            let mut retargeted = target.normal().image.clone();
            retargeted[resident + 3] ^= 0x02;
            assert_eq!(
                installed.plan_to_with_policy(
                    Checks::discover(&retargeted, Some(&target.kernel().image)),
                    policy,
                ),
                Err(StartupError::CapacityRelationUnproved)
            );
        }
    }
    unchanged_directions(&a, &b);
}

#[test]
#[ignore = "requires the four exact authenticated SAT8000 components"]
fn sat8000_pair_profile_retains_resident_validation_without_edits() {
    let a = pair(
        "1b9a41c497072a289fff80e7b4d825c058b3ec57c8d053f901d23995376cf78e",
        "7b1596b7f6fb99ac070d478c7dd597ff89d6badc854142cf098ef84fc4e1cfcf",
    );
    let b = pair(
        "0b5249168360d02375a5cd8a792934ef59e9e5ae86f12b45de76beeb071d346d",
        "904625ace77ee60c6d64fbc5ef0906c94cf196559a67bc79aa83d4b46fa93217",
    );
    for update in [&a, &b] {
        assert_eq!(
            preservation::discover_pair(&update.normal().image, Some(&update.kernel().image))
                .unwrap()
                .kind(),
            Kind::FixedBankResident
        );
        assert!(preservation::discover_pair(&update.normal().image, None).is_none());
    }
    unchanged_directions(&a, &b);
}

#[test]
#[ignore = "requires the four exact authenticated SAT1 W26/US01 components"]
fn sat1_pair_profile_composes_phase_without_persistent_edits() {
    let w26 = pair(
        "2fbd27764be34ebb9a95e898d4e53afa5f67435b7fd324adbfde7411a386466c",
        "c834e7b2b7281121eceda84d67f00f73fe2b3036a58ebeae547b4a0a10b1a3a0",
    );
    let us01 = pair(
        "ab9ff1487bb2551064c59a53a659676833e0096c183bafb8e7715f49806a51a3",
        "de05d4a7c58e13b20f62c896d9db05d6b13f3bc8e0d3ebe4a4cad31781145573",
    );
    for (source, target, operands) in [
        (
            &w26,
            &us01,
            [1540733, 1540757, 1540793, 1540807, 1540823, 1540831],
        ),
        (
            &us01,
            &w26,
            [1532915, 1532941, 1532973, 1532989, 1533003, 1533013],
        ),
    ] {
        let installed = Context::new(firmware(source));
        let requested = Context::new(firmware(target));
        let certificate =
            preservation::discover_pair(&target.normal().image, Some(&target.kernel().image))
                .unwrap();
        assert_eq!(certificate.kind(), Kind::LegacyPredicates);
        assert!(preservation::discover_pair(&target.normal().image, None).is_none());
        let plan = runner::plan(&installed, &requested, runner::Policy::Strict).unwrap();
        assert!(plan.required_words().unwrap().is_empty());
        assert!(plan.decisions().iter().all(|decision| !decision.waived));
        let context = Preparation {
            target: firmware(target),
            normal: Some(target.normal()),
            kernel: Some(target.kernel()),
        };
        let output = plan
            .prepare(&context)
            .unwrap()
            .expect("Phase edits required");
        plan.verify(&context, &output).unwrap();
        let changed: Vec<_> = output
            .iter()
            .zip(&target.normal().image)
            .enumerate()
            .filter_map(|(at, (a, b))| (a != b && !(16..20).contains(&at)).then_some(at))
            .collect();
        assert_eq!(changed, operands);
        assert!(certificate.preserves(
            &target.normal().image,
            &output,
            Some(&target.kernel().image)
        ));
        assert!(certificate.final_integrity(&output, Some(&target.kernel().image)));
        let encoded = target.normal().repack(&output).unwrap();
        let decoded =
            pioneer_optical::envelope::Envelope::load_with_kernel(&encoded, target.kernel())
                .unwrap();
        assert_eq!(decoded.image, output);
        let mut corrupt = output.clone();
        corrupt[certificate.protected_spans()[0].start] ^= 1;
        assert_eq!(
            plan.verify(&context, &corrupt),
            Err(Error::VerificationFailed)
        );
        let mut wrong_kernel = target.kernel().image.clone();
        wrong_kernel[0x100] ^= 1;
        let wrong_context = Preparation {
            target: Firmware {
                kernel: Some(&wrong_kernel),
                ..firmware(target)
            },
            normal: None,
            kernel: None,
        };
        assert_eq!(
            plan.verify(&wrong_context, &output),
            Err(Error::ComponentMismatch)
        );
    }
}
