use super::*;

fn private_pair(profile: &Profile) -> (Vec<u8>, Vec<u8>) {
    use sha2::{Digest, Sha256};
    let root = std::path::PathBuf::from(
        std::env::var_os("PIONEER_PHASE_CORPUS")
            .expect("PIONEER_PHASE_CORPUS must point to the exact private encoded corpus"),
    );
    let (normal, kernel) = if profile.name == "w26" {
        (
            "2fbd27764be34ebb9a95e898d4e53afa5f67435b7fd324adbfde7411a386466c",
            "c834e7b2b7281121eceda84d67f00f73fe2b3036a58ebeae547b4a0a10b1a3a0",
        )
    } else {
        (
            "ab9ff1487bb2551064c59a53a659676833e0096c183bafb8e7715f49806a51a3",
            "de05d4a7c58e13b20f62c896d9db05d6b13f3bc8e0d3ebe4a4cad31781145573",
        )
    };
    let component = |hash: &str| {
        let path = root.join(format!("{hash}.enc"));
        let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        assert_eq!(format!("{:x}", Sha256::digest(&bytes)), hash);
        bytes
    };
    let pair = crate::envelope::Update::load(&component(kernel), &component(normal))
        .expect("the exact private Kernel/Normal pair must authenticate");
    (pair.normal().image.clone(), pair.kernel().image.clone())
}

fn fixture(profile: &Profile) -> (Vec<u8>, Vec<u8>) {
    let compressed: &[u8] = if profile.name == "w26" {
        include_bytes!("legacy_w26_test.zlib")
    } else {
        include_bytes!("legacy_us01_test.zlib")
    };
    // Public test blobs contain sparse Normal fragments only. Complete exact
    // Kernels remain private and are authenticated with their paired Normal.
    let normal = miniz_oxide::inflate::decompress_to_vec_zlib(compressed).unwrap();
    assert_eq!(
        normal.len(),
        profile.length,
        "no trailing private component"
    );
    let (_, kernel) = private_pair(profile);
    (normal, kernel)
}

#[test]
#[ignore = "requires PIONEER_PHASE_CORPUS exact private encoded SAT1 pairs; run in SAT1 CI"]
fn exact_native_forms_bind_complete_local_contracts() {
    for p in legacy_shapes::PROFILES {
        let (n, k) = fixture(p);
        assert!(
            p.shapes
                .iter()
                .all(|s| n.get(s.offset..s.offset + s.packed.len())
                    == Some(&legacy_shapes::BYTES[s.packed.clone()])),
            "{} shapes",
            p.name
        );
        assert!(
            KernelBoundary::bind(&n, &k, p).is_some(),
            "{} Kernel",
            p.name
        );
        assert!(
            matches!(layout::discover_h8_reader(&n, None), Observation::Known(_)),
            "{} reader",
            p.name
        );
        let (a, z) = p.predicates[0];
        assert!(
            crate::startup::bank::legacy_predicate_witness(&n, a, z).is_some(),
            "{} bank",
            p.name
        );
        for owner in p.owners {
            assert!(
                legacy_aliases::complete_owner(&n, owner, p),
                "{} owner {:x}",
                p.name,
                owner.entry
            );
        }
        assert!(
            legacy_aliases::closed(&n, &k, p),
            "{} alias closure",
            p.name
        );
        assert!(legacy_aliases::flags(&n, p), "{} flags", p.name);
        assert!(legacy_aliases::no_wide_flags(&k));
        let c = discover(&n, &k).expect(p.name);
        assert!(c.final_integrity(&n, &k));
        assert!(c.preserves(&n, &n, &k));
        assert_eq!(c.exclusions().len(), if p.name == "w26" { 6 } else { 10 });
    }
}

#[test]
#[ignore = "requires PIONEER_PHASE_CORPUS exact private encoded SAT1 pairs; run in SAT1 CI"]
fn every_held_native_byte_is_mandatory() {
    // Exhaust the held bank branches/writer arguments/epilogues, rejection
    // stores/CCR, root/copy arguments, console count/scaling/key/pointer/return,
    // host registry/initializer/CFG, switch bound/table/base, diagnostic NUL
    // objects/stack arguments, and each complete operand owner instruction.
    for p in legacy_shapes::PROFILES {
        let (mut n, k) = fixture(p);
        for shape in p.shapes {
            for at in shape.offset..shape.offset + shape.packed.len() {
                n[at] ^= 1;
                assert!(discover(&n, &k).is_none(), "{} held byte {at:x}", p.name);
                n[at] ^= 1;
            }
        }
    }
}

#[test]
#[ignore = "requires PIONEER_PHASE_CORPUS exact private encoded SAT1 pairs; run in SAT1 CI"]
fn new_normal_and_kernel_entries_cannot_inherit_operand_ownership() {
    for p in legacy_shapes::PROFILES {
        let (n, k) = fixture(p);
        for owner in p.owners {
            let target = 0x410000 + owner.entry as u32 + 2;
            for opcode in [0, 0x5a, 0x5e] {
                let mut changed = n.clone();
                let mut reference = target.to_be_bytes();
                reference[0] = opcode;
                changed[0x8000..0x8004].copy_from_slice(&reference);
                assert!(!legacy_aliases::closed(&changed, &k, p));
                assert!(discover(&changed, &k).is_none());
                let mut resident = k.clone();
                resident[0x8000..0x8004].copy_from_slice(&reference);
                // Check cross-component closure itself, independently of hash.
                assert!(!legacy_aliases::closed(&n, &resident, p));
                assert!(discover(&n, &resident).is_none());
            }
        }
        for &(entry, _) in p.predicates {
            let mut changed = n.clone();
            changed[0x8000..0x8004].copy_from_slice(&(0x5e410000 + entry as u32 + 2).to_be_bytes());
            assert!(discover(&changed, &k).is_none());
        }
        for &(at, target, _, _) in p.exclusions {
            let mut changed = n.clone();
            let mut call = target.to_be_bytes();
            call[0] = 0x5e;
            changed[at..at + 4].copy_from_slice(&call);
            assert!(
                discover(&changed, &k).is_none(),
                "{} exclusion {at:x}",
                p.name
            );
        }
        // Both short and wide signed PC-relative forms are in the census.
        let entry = p.owners[0].entry;
        for op in [0x40, 0x55] {
            let mut changed = n.clone();
            changed[entry - 8..entry - 6].copy_from_slice(&[op, 8]);
            assert!(!legacy_aliases::closed(&changed, &k, p));
        }
        for op in [0x58, 0x5c] {
            let mut changed = n.clone();
            let entry = p.predicates[0].0;
            let delta = (entry as i32 + 2 - 0x60004) as i16;
            changed[0x60000..0x60004].copy_from_slice(&[
                op,
                0,
                delta.to_be_bytes()[0],
                delta.to_be_bytes()[1],
            ]);
            assert!(!legacy_aliases::closed(&changed, &k, p));
        }
    }
}

#[test]
#[ignore = "requires PIONEER_PHASE_CORPUS exact private encoded SAT1 pairs; run in SAT1 CI"]
fn new_byte_and_overlapping_wide_flag_accesses_refuse() {
    for p in legacy_shapes::PROFILES {
        let (n, k) = fixture(p);
        for code in [
            &[0x6a, 0xa8, 0, 0, 1, 0x40][..],
            &[0x6b, 0xa0, 0, 0, 1, 0x40],
            &[1, 0, 0x6b, 0xa0, 0, 0, 1, 0x3e],
        ] {
            let mut changed = n.clone();
            changed[0x8000..0x8000 + code.len()].copy_from_slice(code);
            assert!(!legacy_aliases::flags(&changed, p));
            assert!(discover(&changed, &k).is_none());
            if code[0] != 0x6a {
                let mut resident = k.clone();
                resident[0x8000..0x8000 + code.len()].copy_from_slice(code);
                assert!(!legacy_aliases::no_wide_flags(&resident));
            }
        }
    }
}

#[test]
#[ignore = "requires PIONEER_PHASE_CORPUS exact private encoded SAT1 pairs; run in SAT1 CI"]
fn paired_native_header_copy_boundary_and_final_sums_are_enforced() {
    for p in legacy_shapes::PROFILES {
        let (n, k) = fixture(p);
        let cert = discover(&n, &k).unwrap();
        assert!(discover(&n, &[]).is_none());
        let other = legacy_shapes::PROFILES
            .iter()
            .find(|x| x.name != p.name)
            .unwrap();
        let (_, foreign) = fixture(other);
        assert!(discover(&n, &foreign).is_none());
        for at in [0, 15, 0x14, 0x17, 0x18, 0x1f] {
            let mut changed = n.clone();
            changed[at] ^= 0x80;
            assert!(!cert.accepts_kernel(&changed, &k));
            assert!(!cert.final_integrity(&changed, &k));
        }
        for length in [0x3c0004u32, p.length as u32 - 1] {
            let mut changed = n.clone();
            changed[0x14..0x18].copy_from_slice(&length.to_be_bytes());
            assert!(discover(&changed, &k).is_none());
        }
        // Native gate/reset/Normal-root call, copy wrapper and its complete
        // resident implementation, clear leaf, copied checksum and formatter.
        for at in [
            0x10e, 0x11a, 0x142, 0x174, 0x1a4, 0x1b4, 0x1c2, 0x1d8, 0x489c, 0x48b4, 0x5f2a, 0x621a,
            0x555a, 0x3f9e, 0x4132,
        ] {
            let mut changed = k.clone();
            changed[at] ^= 1;
            assert!(discover(&n, &changed).is_none(), "{} Kernel {at:x}", p.name);
        }
        // A transient ordinary data edit has structural preservation, but the
        // final native sum must be repaired through the integrity owner.
        let mut changed = n.clone();
        changed[0x8000] = 0xfe;
        assert!(cert.preserves(&n, &changed, &k));
        assert!(!cert.final_integrity(&changed, &k));
        changed[0x10..0x14].fill(0);
        let sum = changed.chunks_exact(4).fold(0u32, |a, w| {
            a.wrapping_add(u32::from_be_bytes(w.try_into().unwrap()))
        });
        changed[0x10..0x14].copy_from_slice(&sum.wrapping_neg().to_be_bytes());
        assert!(cert.final_integrity(&changed, &k));
    }
}

#[test]
#[ignore = "requires PIONEER_PHASE_CORPUS exact private encoded SAT1 pairs; run in SAT1 CI"]
fn duplicate_opcode_registry_is_not_a_new_host_owner() {
    for p in legacy_shapes::PROFILES {
        let (mut n, k) = fixture(p);
        let at = if p.name == "w26" { 0x21c922 } else { 0x22042e };
        let table = n[at..at + 256].to_vec();
        n[0x8000..0x8100].copy_from_slice(&table);
        assert!(!write_buffer(&n, p));
        assert!(discover(&n, &k).is_none());
    }
}

#[test]
#[ignore = "requires PIONEER_PHASE_CORPUS exact private encoded SAT1 pairs; run in SAT1 CI"]
fn authenticated_private_pairs_bind_legacy_contracts() {
    for profile in legacy_shapes::PROFILES {
        let (normal, kernel) = private_pair(profile);
        let certificate = discover(&normal, &kernel).expect(profile.name);
        assert!(certificate.final_integrity(&normal, &kernel));
    }
}
