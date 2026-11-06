#![cfg(feature = "envelope")]
// Sparse native controller/profile/coil witnesses from the emitted UD04 image.
// Waveform tables occupy explicit synthetic fixture slots 0x1000..0x1400;
// this tests consumer/data authority and does not establish deployable storage.
// Kernel evidence is reused verbatim from phase-trajectory-bridge.json.
use pioneer_optical::filters::phase::bundle::waveforms::resources::{
    profile_ownership, software, trajectory_bridge as bridge, trajectory_profile as profile,
};
use std::ops::Range;
const BASE: usize = 0x410000;
fn span(a: usize, z: usize) -> Range<usize> {
    a - BASE..z - BASE
}
fn fixture(role: &str) -> Vec<u8> {
    let text = if role == "normal" {
        include_str!("fixtures/phase-software-data-authority.json")
    } else {
        include_str!("fixtures/phase-trajectory-bridge.json")
    };
    let records: serde_json::Value = serde_json::from_str(text).unwrap();
    let r = records
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["role"] == role)
        .unwrap();
    let mut n = vec![255; r["size"].as_u64().unwrap() as usize];
    for s in r["spans"].as_array().unwrap() {
        let a = s[0].as_u64().unwrap() as usize;
        for (i, b) in s[1]
            .as_str()
            .unwrap()
            .as_bytes()
            .chunks_exact(2)
            .enumerate()
        {
            n[a + i] = u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap();
        }
    }
    n
}
fn observed(n: &[u8], k: &[u8]) -> Option<profile::ObservedShared> {
    let call =
        |a: usize| u32::from_be_bytes(n[a - BASE..a - BASE + 4].try_into().unwrap()) & 0xffffff;
    profile::observe_shared(
        n,
        k,
        profile::SharedEntries {
            init: call(0x53996c),
            update: call(0x539aaa),
            ctor: call(0x5398d8),
            prepare: call(0x5398c4),
        },
        bridge::services(),
        0xa05ddd,
    )
}
struct ClosureRanges {
    retired: Vec<Range<usize>>,
    replaced: Vec<Range<usize>>,
    bodies: Vec<Range<usize>>,
}
fn ranges(p: &profile::ObservedShared) -> ClosureRanges {
    let mut retired = p.placements.code.to_vec();
    retired.extend(p.placements.data.clone());
    retired.extend(
        [
            (0x5398a6, 0x539ad8),
            (0x53956c, 0x53957e),
            (0x5395e8, 0x539620),
            (0x539620, 0x53962e),
            (0x538351, 0x53836e),
            (0x5388a5, 0x5388c4),
            (0x539406, 0x539407),
        ]
        .map(|(a, z)| span(a, z)),
    );
    let mut replaced = retired.clone();
    replaced.extend(p.ranges.clone());
    replaced.extend(
        [
            (0x538350, 0x53836e),
            (0x5388a4, 0x5388c4),
            (0x5398a6, 0x539b2c),
            (0x5392d2, 0x539406),
            (0x539406, 0x539550),
        ]
        .map(|(a, z)| span(a, z)),
    );
    let mut bodies = p.placements.code.to_vec();
    bodies.extend(
        [
            (0x5398a6, 0x53990e),
            (0x53990e, 0x539a1e),
            (0x539a1e, 0x539abe),
            (0x539abe, 0x539ac4),
            (0x5392d2, 0x539406),
            (0x539406, 0x539550),
        ]
        .map(|(a, z)| span(a, z)),
    );
    ClosureRanges {
        retired,
        replaced,
        bodies,
    }
}
fn prove(n: &[u8], k: &[u8], p: &profile::ObservedShared) -> Option<Vec<Range<usize>>> {
    let r = ranges(p);
    profile_ownership::prove_with_software_tables(
        n,
        k,
        &r.retired,
        &r.replaced,
        &r.bodies,
        &p.data_authority,
    )
}
#[test]
#[ignore = "captures bounded native witnesses from the locally composed image"]
fn capture_sparse_native_witnesses() {
    let root = std::path::Path::new("/Users/matthew/Developer/tmp/release-0180");
    let mut n = std::fs::read(root.join("reverse-composed.bin")).unwrap();
    // Explicit synthetic fixture storage, never a production allocation claim.
    // Keep native selector operands and complete 256-byte table extents bound.
    let selector = software::observe(&n).unwrap().selector;
    for (i, old) in waveforms(&n).into_iter().enumerate() {
        let new = 0x1000 + i * 256;
        let bytes = n[old.clone()].to_vec();
        n[old.clone()].fill(255);
        n[new..new + 256].copy_from_slice(&bytes);
        let old_address = ((BASE + old.start) as u32).to_be_bytes();
        let field = selector.start
            + n[selector.clone()]
                .windows(4)
                .position(|b| b == old_address)
                .unwrap();
        n[field..field + 4].copy_from_slice(&((BASE + new) as u32).to_be_bytes());
    }
    let k = fixture("kernel");
    let p = observed(&n, &k).expect("profile graph");
    let mut kept = ranges(&p).replaced;
    use pioneer_optical::filters::phase::{
        bundle::waveforms::resources::{dispatch_bridge, profile_code},
        native::encoders,
    };
    kept.extend(profile_code::observe(&n).unwrap().protected_normal());
    let g = dispatch_bridge::observe(&n).unwrap();
    kept.extend([g.dispatch, g.selector]);
    kept.extend(g.callers.into_iter().flatten());
    let c = encoders::observe(&n).unwrap();
    kept.extend(c.programs.into_iter().flatten());
    kept.push(c.leaf);
    kept.extend(waveforms(&n));
    kept.extend(p.ranges.clone());
    kept.extend(p.invariants.clone());
    let old: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/phase-trajectory-bridge.json")).unwrap();
    for r in old
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["role"] == "target")
    {
        for s in r["spans"].as_array().unwrap() {
            let a = s[0].as_u64().unwrap() as usize;
            kept.push(a..a + s[1].as_str().unwrap().len() / 2);
        }
    }
    kept.sort_by_key(|r| r.start);
    let mut merged: Vec<Range<usize>> = vec![];
    for r in kept {
        if let Some(last) = merged.last_mut().filter(|last| r.start <= last.end) {
            last.end = last.end.max(r.end);
        } else {
            merged.push(r);
        }
    }
    let records: Vec<_> = merged
        .iter()
        .map(|r| {
            serde_json::json!([
                r.start,
                n[r.clone()]
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            ])
        })
        .collect();
    std::fs::write(
        "tests/fixtures/phase-software-data-authority.json",
        serde_json::to_vec(&serde_json::json!([{"role":"normal","size":n.len(),"spans":records}]))
            .unwrap(),
    )
    .unwrap();
}
#[test]
fn sparse_joint_authority_closes_all_eight_arrays() {
    let n = fixture("normal");
    let k = fixture("kernel");
    let p = observed(&n, &k).expect("sparse native graph");
    assert_eq!(waveforms(&n).len(), 4);
    assert!(prove(&n, &k, &p).is_some());
}

fn waveforms(n: &[u8]) -> Vec<Range<usize>> {
    software::observe(n)
        .unwrap()
        .choices
        .into_iter()
        .map(|(_, s)| match s {
            software::Source::Image(r) => r,
            _ => panic!("image table required"),
        })
        .collect()
}
#[test]
fn external_control_and_data_references_are_not_array_authority() {
    let n = fixture("normal");
    let k = fixture("kernel");
    let p = observed(&n, &k).unwrap();
    let mut arrays = waveforms(&n);
    arrays.extend(p.data_authority.scalar_ranges().iter().cloned());
    assert_eq!(arrays.len(), 8);
    assert_eq!(waveforms(&n).len(), 4);
    assert!(prove(&n, &k, &p).is_some());
    for r in arrays {
        let address = ((BASE + r.start) as u32).to_be_bytes();
        // Native JSR absolute24, JMP absolute24, and MOV.W absolute32 reader.
        for instruction in [
            vec![0x5e, address[1], address[2], address[3]],
            vec![0x5a, address[1], address[2], address[3]],
            vec![0x6b, 0x20, address[0], address[1], address[2], address[3]],
        ] {
            let decoded = h8_asm::isa::decode_insn(
                &instruction,
                h8_asm::Target::H8S2000,
                h8_asm::Mode::Advanced,
            )
            .unwrap();
            assert_eq!(decoded.len, instruction.len());
            assert!(matches!(decoded.insn.mnemonic, "JSR" | "JMP" | "MOV"));
            let mut changed = n.clone();
            assert!(changed[0x800..0x808].iter().all(|b| *b == 255));
            changed[0x800..0x800 + instruction.len()].copy_from_slice(&instruction);
            let refreshed = observed(&changed, &k)
                .expect("unrelated reader must not invalidate canonical profile recognition");
            assert!(
                prove(&changed, &k, &refreshed).is_none(),
                "external instruction {instruction:x?} to {r:x?}"
            );
        }
    }
}
#[test]
fn array_bytes_do_not_hide_raw_code_pointers() {
    let n = fixture("normal");
    let k = fixture("kernel");
    let p = observed(&n, &k).unwrap();
    let code = ((BASE + p.placements.code[0].start) as u32).to_be_bytes();
    for r in waveforms(&n) {
        let mut changed = n.clone();
        changed[r.start + 1..r.start + 5].copy_from_slice(&code);
        let refreshed = observed(&changed, &k).unwrap();
        assert!(
            prove(&changed, &k, &refreshed).is_none(),
            "unaligned code pointer in {r:x?}"
        );
    }
    for r in p.data_authority.scalar_ranges() {
        let mut changed = n.clone();
        changed[r.start + 1..r.start + 5].copy_from_slice(&code);
        assert!(
            observed(&changed, &k).is_none(),
            "canonical scalar payload {r:x?}"
        );
    }
}
#[test]
fn profile_payloads_and_diagnostics_remain_native_witnesses() {
    let n = fixture("normal");
    let k = fixture("kernel");
    let p = observed(&n, &k).unwrap();
    for r in p.data_authority.ranges() {
        let mut changed = n.clone();
        changed[r.start] ^= 1;
        assert!(!p.data_authority.is_bound_to(&changed));
        assert!(observed(&changed, &k).is_none(), "payload mutation {r:x?}");
    }
}

#[test]
fn diagnostic_strings_do_not_authorize_executable_looking_bytes() {
    let mut n = fixture("normal");
    let k = fixture("kernel");
    let p = observed(&n, &k).unwrap();
    assert!(prove(&n, &k, &p).is_some());
    let selector = software::observe(&n).unwrap().selector;
    let old = waveforms(&n).pop().unwrap();
    // Restore the observed collision: a BCS-looking pair in the logger's
    // diagnostic text addresses the nearby table. Strings are opaque, not
    // scalar-array authority, even though their canonical digest is bound.
    let new = p.data_authority.diagnostic_range().end + 7;
    assert_eq!(new, 0x5b5b04 - BASE);
    assert!(n[new..new + 256].iter().all(|b| *b == 255));
    let data = n[old.clone()].to_vec();
    n[old.clone()].fill(255);
    n[new..new + 256].copy_from_slice(&data);
    let address = ((BASE + old.start) as u32).to_be_bytes();
    let at = selector.start
        + n[selector.clone()]
            .windows(4)
            .position(|b| b == address)
            .unwrap();
    n[at..at + 4].copy_from_slice(&((BASE + new) as u32).to_be_bytes());
    let refreshed = observed(&n, &k).unwrap();
    assert!(prove(&n, &k, &refreshed).is_none());
}
#[test]
fn native_fingerprint_includes_waveform_data() {
    let n = fixture("normal");
    let k = fixture("kernel");
    let baseline = bridge::observe_detailed(&n, &k).expect("sparse native controller");
    assert!(baseline.verify(&n, &k));
    for r in waveforms(&n) {
        let mut changed = n.clone();
        changed[r.start] ^= 1;
        assert!(!baseline.verify(&changed, &k), "waveform {r:x?}");
    }
}
