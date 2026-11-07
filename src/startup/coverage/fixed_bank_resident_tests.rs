use super::*;

fn kernel_fixture() -> Vec<u8> {
    let mut image = vec![0xff; 0x10000];
    for shape in shapes::KERNEL {
        image[shape.span()].copy_from_slice(shape.bytes);
    }
    image
}

#[test]
fn complete_forms_and_copy_arithmetic_have_no_wildcards() {
    let k = kernel_fixture();
    assert_eq!(copy_contract(&k), Some(()));
    assert_eq!(kernel_census(&k), Some(()));
    for (name, at) in [
        ("cold clear", 0x57),
        ("cold final jump", 0x5b),
        ("copy source", 0x183),
        ("copy end", 0x189),
        ("copy destination", 0x18f),
        ("conditional flag", 0x21c),
        ("checksum add", 0x10f3),
        ("normal entry", 0x4f53),
        ("restart", 0x52d4),
        ("programmer flag clear", 0x14e2),
        ("memcpy tail", 0x6f4d),
    ] {
        let mut changed = k.clone();
        changed[at] ^= 1;
        assert_eq!(copy_contract(&changed), None, "{name}");
    }
    for f in FORMS {
        let mut n = vec![0xff; 0x220000];
        for shape in f.shapes {
            n[shape.span()].copy_from_slice(shape.bytes);
        }
        assert_eq!(form(&n).unwrap().wrapper, f.wrapper);
        for shape in f.shapes {
            let at = shape.span().end - 1;
            n[at] ^= 1;
            assert!(form(&n).is_none(), "complete body ending {at:x}");
            n[at] ^= 1;
        }
    }
}

#[test]
fn resident_census_refuses_new_absolute_relative_and_literal_aliases() {
    let k = kernel_fixture();
    for bytes in [
        vec![0x5e, 0x40, 0x04, 0x78],
        vec![0x5a, 0x40, 0x04, 0x78],
        vec![0, 0x40, 0x04, 0x78],
        // BSR16 at 0x800 -> resident loader setter 0x478.
        vec![0x5c, 0, 0xfc, 0x74],
    ] {
        let mut changed = k.clone();
        changed[0x800..0x800 + bytes.len()].copy_from_slice(&bytes);
        assert_eq!(kernel_census(&changed), None, "{bytes:x?}");
    }
    let mut changed = k.clone();
    changed[0xa1a..0xa1e].fill(0xff);
    assert_eq!(kernel_census(&changed), None);
}

#[test]
fn metadata_and_final_integrity_are_distinct_from_composition() {
    let mut n = vec![0; 0x100];
    let mut k = vec![0; 0x10000];
    n[0x14..0x18].copy_from_slice(&0x100u32.to_be_bytes());
    assert_eq!(paired_header(&n, &k), Some(()));
    let validation = ResidentValidation {
        kernel_spans: vec![0..0x10000],
        identity_spans: vec![0x6ae4..0x6af4, 0x1008..0x1010],
        normal_spans: vec![0..0x10, 0x14..0x20],
        image_length_field: 0x14,
        checksum_entry: 0x23e,
        reject_entry: 0x400252,
        conditional_state: (0x144, 5),
    };
    assert!(!validation.final_integrity(&n, &k));
    n[0x10..0x14].copy_from_slice(&0u32.wrapping_sub(0x100).to_be_bytes());
    assert!(validation.final_integrity(&n, &k));
    n[0x18] ^= 1;
    assert_eq!(paired_header(&n, &k), None);
    assert!(!validation.final_integrity(&n, &k));
    k[0x1008] ^= 1;
    assert_eq!(paired_header(&n, &k), Some(()));
    n[0x14..0x18].copy_from_slice(&0x101u32.to_be_bytes());
    assert_eq!(paired_header(&n, &k), None);
    assert!(discover(&[], &[]).is_none());
    assert!(discover(&n, &k[..0xffff]).is_none());
}

#[cfg(feature = "envelope")]
#[test]
#[ignore = "requires PIONEER_NORMAL_CORPUS; only the two exact authenticated SAT8000 pairs"]
fn authenticated_sat8000_pairs_bind_and_reject_native_mutations() {
    use crate::envelope::Update;
    use sha2::{Digest, Sha256};
    let root = std::path::PathBuf::from(std::env::var("PIONEER_NORMAL_CORPUS").unwrap());
    let read = |hash: &str| {
        let bytes = std::fs::read(root.join(format!("{hash}.enc"))).unwrap();
        assert_eq!(format!("{:x}", Sha256::digest(&bytes)), hash);
        bytes
    };
    let mut layouts = Vec::new();
    for (normal_hash, kernel_hash) in [
        (
            "1b9a41c497072a289fff80e7b4d825c058b3ec57c8d053f901d23995376cf78e",
            "7b1596b7f6fb99ac070d478c7dd597ff89d6badc854142cf098ef84fc4e1cfcf",
        ),
        (
            "0b5249168360d02375a5cd8a792934ef59e9e5ae86f12b45de76beeb071d346d",
            "904625ace77ee60c6d64fbc5ef0906c94cf196559a67bc79aa83d4b46fa93217",
        ),
    ] {
        let update = Update::load(&read(kernel_hash), &read(normal_hash)).unwrap();
        let (n, k) = (&update.normal().image, &update.kernel().image);
        let standalone = crate::envelope::Envelope::load(&read(normal_hash)).unwrap();
        let recovered: Vec<_> = standalone
            .image
            .iter()
            .zip(n)
            .enumerate()
            .filter_map(|(at, (before, after))| (before != after).then_some(at))
            .collect();
        eprintln!("authenticated decoded normal={:x} kernel={:x}; recovered Normal byte offsets={recovered:x?}", Sha256::digest(n), Sha256::digest(k));
        let (certificate, resident) = discover(n, k).expect("authenticated exact native form");
        assert!(resident.final_integrity(n, k));
        assert!(certificate.accepts_kernel(k));
        assert!(certificate.protected.contains(&(0..0x10)));
        assert!(certificate.protected.contains(&(0x14..0x20)));
        assert!(!certificate
            .protected
            .iter()
            .any(|r| overlap(r, &(0x10..0x14))));
        assert!(resident.kernel_spans.contains(&(0..0x10000)));
        assert!(sinks::discover(n).is_none(), "modern sink is not weakened");
        assert!(discover(n, &[]).is_none());
        assert!(discover(n, &k[..0xffff]).is_none());
        let f = form(n).unwrap();
        for (name, component, at, patch) in [
            (
                "extra loader call",
                false,
                0x1000,
                vec![
                    0x5e,
                    (NORMAL_BASE + f.wrapper as u32).to_be_bytes()[1],
                    (NORMAL_BASE + f.wrapper as u32).to_be_bytes()[2],
                    (NORMAL_BASE + f.wrapper as u32).to_be_bytes()[3],
                ],
            ),
            (
                "new Normal literal alias",
                false,
                0x1000,
                (NORMAL_BASE + f.helper as u32).to_be_bytes().to_vec(),
            ),
            (
                "new Normal relative alias",
                false,
                f.helper - 0x100,
                vec![0x5c, 0, 0, 0xfc],
            ),
            ("bank writer", false, f.initializer + 75, vec![0xd2]),
            ("cold clear", true, 0x57, vec![0x4e]),
            ("cold final jump", true, 0x5b, vec![0]),
            ("conditional b5", true, 0x21c, vec![0x77, 0x60]),
            ("checksum add", true, 0x10f3, vec![0x83]),
            ("copy target", true, 0x18f, vec![0x94]),
            ("copy source", true, 0x183, vec![0x28]),
            ("copy length", true, 0x189, vec![0x4e]),
            ("Normal entry call", true, 0x4f53, vec![0x04]),
            ("paired descriptor", true, 0x6ae4, vec![0x58]),
            ("paired destination", true, 0x1008, vec![0x58]),
            ("misaligned length", false, 0x17, vec![1]),
            ("excessive length", false, 0x14, vec![1]),
            ("KL return", false, f.helper + 16, vec![0, 0]),
            ("restart", true, 0x5334, vec![0x5a, 0x40, 0x01, 0x08]),
            (
                "Normal dispatcher",
                false,
                f.shapes[2].start + 30,
                vec![0, 0],
            ),
            (
                "resident literal alias",
                true,
                0x800,
                vec![0, 0x40, 4, 0x78],
            ),
        ] {
            let (mut nn, mut kk) = (n.clone(), k.clone());
            let image = if component { &mut kk } else { &mut nn };
            assert_ne!(
                &image[at..at + patch.len()],
                patch.as_slice(),
                "{name} must mutate"
            );
            image[at..at + patch.len()].copy_from_slice(&patch);
            // Compensate native checksum: refusal must bind the owning predicate.
            let sum = kk
                .chunks_exact(4)
                .chain(nn.chunks_exact(4))
                .fold(0u32, |s, b| {
                    s.wrapping_add(u32::from_be_bytes(b.try_into().unwrap()))
                });
            let checksum = word(&nn, 0x10).unwrap().wrapping_sub(sum);
            nn[0x10..0x14].copy_from_slice(&checksum.to_be_bytes());
            assert!(discover(&nn, &kk).is_none(), "{normal_hash}: {name}");
            eprintln!("refused {normal_hash}: {name}");
        }
        // A stale checksum is allowed during composition; final validation owns it.
        let mut stale = n.clone();
        stale[0x10] ^= 1;
        assert!(discover(&stale, k).is_some());
        assert!(!resident.final_integrity(&stale, k));
        let Observation::Known(reader) = layout::discover_h8_reader(n, None) else {
            panic!("reader")
        };
        for function in &reader.functions {
            let mut changed = n.clone();
            changed[(function.address - NORMAL_BASE) as usize] ^= 1;
            assert!(discover(&changed, k).is_none(), "reader mutation");
        }
        layouts.push(reader.layout);
        eprintln!(
            "bound {normal_hash}: normal_spans={} kernel_spans={} sum=0",
            certificate.protected.len(),
            resident.kernel_spans.len()
        );
    }
    assert_eq!(layouts[0], layouts[1]);
}
