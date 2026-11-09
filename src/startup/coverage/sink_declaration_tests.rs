use super::super::sink_declarations;
use super::*;

struct Fixture {
    normal: Vec<u8>,
    kernel: Vec<u8>,
    owner: usize,
    caller: usize,
    child: usize,
    getter: usize,
    parent: usize,
    base: usize,
    invoker: usize,
    child_table: usize,
    worker_table: usize,
    adjacent: usize,
    seed: usize,
}
fn imm(v: u32, r: u8) -> Vec<u8> {
    let mut b = alloc::vec![0x7a, r];
    b.extend(v.to_be_bytes());
    b
}
fn jsr(at: usize) -> Vec<u8> {
    let a = NORMAL_BASE + at as u32;
    alloc::vec![0x5e, (a >> 16) as u8, (a >> 8) as u8, a as u8]
}
fn mov(a: u8, b: u8) -> Vec<u8> {
    alloc::vec![0x0f, 0x80 | (a << 4) | b]
}
fn load(a: u8, d: u16, b: u8) -> Vec<u8> {
    let mut x = alloc::vec![1, 0, 0x6f, (a << 4) | b];
    x.extend(d.to_be_bytes());
    x
}
fn store(a: u8, b: u8, d: u16) -> Vec<u8> {
    let mut x = alloc::vec![1, 0, 0x6f, 0x80 | (b << 4) | a];
    x.extend(d.to_be_bytes());
    x
}
fn put(n: &mut [u8], at: usize, parts: &[Vec<u8>]) {
    let mut p = at;
    for b in parts {
        n[p..p + b.len()].copy_from_slice(b);
        p += b.len();
    }
}
fn raw(x: &[u8]) -> Vec<u8> {
    x.to_vec()
}
fn fixture(delta: usize) -> Fixture {
    let owner = delta + 0x200;
    let caller = delta + 0x400;
    let child = delta + 0x600;
    let getter = delta + 0x800;
    let parent = delta + 0xa00;
    let base = delta + 0xc00;
    let trampoline = delta + 0xe00;
    let worker = delta + 0x1000;
    let invoker = delta + 0x1200;
    let adjacent = delta + 0x1400;
    let child_table = delta + 0x1600;
    let worker_table = delta + 0x1700;
    let descriptor = delta + 0x1800;
    let mut n = alloc::vec![0xff;delta+0x2000];
    let frame = raw(&[1, 0, 0x6d, 0xf3, 1, 0x20, 0x6d, 0xf4]);
    let finish = raw(&[1, 0x20, 0x6d, 0x76, 1, 0, 0x6d, 0x73, 0x54, 0x70]);
    put(
        &mut n,
        owner,
        &[
            frame.clone(),
            raw(&[0; 6]),
            raw(&[0x5e, 0x10, 0x55, 0x88]),
            raw(&[0x79, 0x37, 0, 0x46, 0x79, 0x17, 0, 0x46]),
            finish.clone(),
        ],
    );
    let seed = owner + 8 + 6 + 4 + 4 + 2;
    put(
        &mut n,
        caller,
        &[frame.clone(), raw(&[0; 4]), jsr(owner), finish.clone()],
    );
    put(
        &mut n,
        child,
        &[
            raw(&[1, 0x10, 0x6d, 0xf4]),
            mov(0, 4),
            raw(&[0; 6]),
            raw(&[0x1a, 0x80, 0xf8, 0x10]),
            raw(&[0x5e, 0x10, 0x50, 0]),
            mov(0, 1),
            imm(NORMAL_BASE + child_table as u32, 0),
            store(0, 1, 12),
            store(1, 4, 32),
            raw(&[1, 0x10, 0x6d, 0x75, 0x54, 0x70]),
        ],
    );
    put(
        &mut n,
        getter,
        &[
            raw(&[1, 0, 0x6d, 0xf3]),
            imm(0x2000, 3),
            mov(3, 0),
            jsr(parent),
            mov(3, 0),
            raw(&[1, 0, 0x6d, 0x73, 0x54, 0x70]),
        ],
    );
    put(
        &mut n,
        parent,
        &[
            raw(&[1, 0x20, 0x6d, 0xf4]),
            mov(0, 4),
            imm(NORMAL_BASE + descriptor as u32, 1),
            raw(&[0x18, 0xaa]),
            mov(4, 0),
            jsr(base),
            imm(NORMAL_BASE + worker_table as u32, 1),
            store(1, 4, 4),
            mov(4, 0),
            raw(&[1, 0x20, 0x6d, 0x76, 0x54, 0x70]),
        ],
    );
    put(
        &mut n,
        base,
        &[
            raw(&[1, 0x20, 0x6d, 0xf4]),
            mov(1, 5),
            mov(0, 4),
            imm(NORMAL_BASE + trampoline as u32, 0),
            store(0, 7, 10),
            raw(&[0x6f, 0x56, 0, 2]),
            raw(&[0x6f, 0xf6, 0, 14]),
            load(5, 4, 6),
            store(6, 7, 16),
            raw(&[0x69, 0x50]),
            mov(7, 1),
            raw(&[0x0b, 0x91]),
            raw(&[0x5e, 0x10, 0x50, 0]),
            raw(&[1, 0x20, 0x6d, 0x76, 0x54, 0x70]),
        ],
    );
    put(
        &mut n,
        trampoline,
        &[
            raw(&[1, 0, 0x6d, 0xf3]),
            mov(0, 3),
            raw(&[0x5e, 0x10, 0x60, 0]),
            load(3, 4, 1),
            load(1, 26, 2),
            load(1, 20, 0),
            raw(&[0x0a, 0xb0, 0x5d, 0x20, 1, 0, 0x6d, 0x73, 0x54, 0x70]),
        ],
    );
    put(
        &mut n,
        worker,
        &[
            raw(&[0x79, 0x37, 0, 0x10]),
            mov(0, 4),
            raw(&[0x5e, 0x10, 0x50, 0]),
            mov(4, 0),
            jsr(invoker),
            raw(&[0x79, 0x17, 0, 0x10, 0x54, 0x70]),
        ],
    );
    put(
        &mut n,
        invoker,
        &[
            frame,
            raw(&[0x1b, 0x97]),
            mov(0, 5),
            raw(&[0x5e, 0x10, 0x50, 0]),
            raw(&[0; 6]),
            load(5, 32, 4),
            load(4, 12, 1),
            load(1, 16, 6),
            load(1, 10, 3),
            raw(&[0x0a, 0xc3]),
            mov(3, 0),
            raw(&[0x5d, 0x60, 0x0b, 0x97]),
            finish,
        ],
    );
    put(&mut n, adjacent, &[jsr(getter), jsr(child)]);
    n[child_table + 16..child_table + 20]
        .copy_from_slice(&(NORMAL_BASE + caller as u32).to_be_bytes());
    n[child_table + 10..child_table + 14].fill(0);
    n[worker_table + 26..worker_table + 30]
        .copy_from_slice(&(NORMAL_BASE + worker as u32).to_be_bytes());
    n[worker_table + 20..worker_table + 24].fill(0);
    n[descriptor..descriptor + 8].fill(0);
    Fixture {
        normal: n,
        kernel: alloc::vec![0xff;0x10000],
        owner,
        caller,
        child,
        getter,
        parent,
        base,
        invoker,
        child_table,
        worker_table,
        adjacent,
        seed,
    }
}
fn certificate(f: &Fixture) -> BoundaryCertificate {
    let bodies =
        sink_declarations::bind(&f.normal, &f.kernel, f.seed).expect("connected declaration");
    declared_certificate(&f.normal, &f.kernel, bodies).unwrap()
}
#[test]
fn connected_declaration_relocates_without_specimen_coordinates() {
    for delta in [0, 0x2600] {
        let f = fixture(delta);
        let c = certificate(&f);
        assert_eq!(c.bodies.len(), 2);
        assert!(c.is_cross_instruction_literal(f.seed, 4));
        assert!(c.accepts_kernel(&f.kernel));
        for span in c.protected() {
            assert!(!span.is_empty());
            assert!(span.end <= f.normal.len());
        }
        for (at, len) in [
            (f.seed, 2),
            (f.owner, 4),
            (f.owner + 10, 4),
            (f.adjacent, 4),
            (f.owner + 34, 4),
        ] {
            assert!(!c.is_cross_instruction_literal(at, len));
        }
        assert!(sink_declarations::bind(&f.normal, &[], f.seed).is_none());
        assert!(!c.accepts_kernel(&f.kernel[..100]));
    }
}
#[test]
fn disconnected_parent_table_field_and_method_links_refuse() {
    for kind in 0..6 {
        let mut f = fixture(0);
        match kind {
            0 => {
                let site = f.getter + 12;
                f.normal[site..site + 4].copy_from_slice(&jsr(f.owner));
            }
            1 => f.normal[f.parent + 22..f.parent + 26]
                .copy_from_slice(&(NORMAL_BASE + f.child_table as u32).to_be_bytes()),
            2 => f.normal[f.child + 24..f.child + 28]
                .copy_from_slice(&(NORMAL_BASE + f.worker_table as u32).to_be_bytes()),
            3 => {
                let at = f.child + 38;
                f.normal[at..at + 2].copy_from_slice(&34u16.to_be_bytes());
            }
            4 => {
                let at = f.child + 32;
                f.normal[at..at + 2].copy_from_slice(&14u16.to_be_bytes());
            }
            _ => f.normal[f.child_table + 16..f.child_table + 20]
                .copy_from_slice(&(NORMAL_BASE + f.owner as u32).to_be_bytes()),
        }
        assert!(
            sink_declarations::bind(&f.normal, &f.kernel, f.seed).is_none(),
            "mutation {kind}"
        );
    }
}
#[test]
fn explicit_carrier_writes_refuse_but_opaque_calls_are_only_declarations() {
    for at in [fixture(0).child + 6, fixture(0).invoker + 16] {
        let mut f = fixture(0);
        f.normal[at..at + 4].copy_from_slice(&[0x79, if at == f.child + 6 { 4 } else { 5 }, 0, 0]);
        assert!(sink_declarations::bind(&f.normal, &f.kernel, f.seed).is_none());
    }
    let mut f = fixture(0);
    f.normal[f.invoker + 13..f.invoker + 16].copy_from_slice(&[0x10, 0x60, 0]);
    assert!(certificate(&f).is_cross_instruction_literal(f.seed, 4));
}
#[test]
fn ambiguous_declarations_and_incomplete_bodies_refuse() {
    let mut f = fixture(0);
    let copy = f.normal[f.adjacent..f.adjacent + 8].to_vec();
    f.normal[0x1a00..0x1a08].copy_from_slice(&copy);
    assert!(sink_declarations::bind(&f.normal, &f.kernel, f.seed).is_none());
    let mut f = fixture(0);
    f.normal[f.caller + 8..f.caller + 12].copy_from_slice(&jsr(f.owner + 4));
    assert!(sink_declarations::bind(&f.normal, &f.kernel, f.seed).is_none());
    let f = fixture(0);
    assert!(sink_declarations::bind(&f.normal[..f.owner + 25], &f.kernel, f.seed).is_none());
}
#[test]
fn actual_normal_kernel_and_full_immediate_interior_references_refuse() {
    let f = fixture(0);
    let c = certificate(&f);
    let target = NORMAL_BASE + (f.owner + 2) as u32;
    for opcode in [0, 0x5e, 0x5a] {
        let bytes = [
            opcode,
            (target >> 16) as u8,
            (target >> 8) as u8,
            target as u8,
        ];
        let mut n = f.normal.clone();
        n[0x20..0x24].copy_from_slice(&bytes);
        let b = sink_declarations::bind(&n, &f.kernel, f.seed).unwrap();
        assert!(declared_certificate(&n, &f.kernel, b).is_err());
        let mut k = f.kernel.clone();
        k[0x20..0x24].copy_from_slice(&bytes);
        assert!(!c.accepts_kernel(&k));
        let b = sink_declarations::bind(&f.normal, &k, f.seed).unwrap();
        assert!(declared_certificate(&f.normal, &k, b).is_err());
    }
    for (at, prefix, width) in [
        (f.owner - 8, alloc::vec![0x55], 2),
        (f.owner - 10, alloc::vec![0x58, 0], 4),
    ] {
        let mut n = f.normal.clone();
        let delta = (target - (NORMAL_BASE + at as u32 + width)) as i16;
        let mut bytes = prefix;
        if width == 2 {
            bytes.push(delta as i8 as u8);
        } else {
            bytes.extend(delta.to_be_bytes());
        }
        n[at..at + bytes.len()].copy_from_slice(&bytes);
        let b = sink_declarations::bind(&n, &f.kernel, f.seed).unwrap();
        assert!(declared_certificate(&n, &f.kernel, b).is_err());
    }
    let mut k = f.kernel.clone();
    let at = 0xfff0;
    let delta = i16::try_from(i64::from(target) - i64::from(KERNEL_BASE + at as u32 + 4)).unwrap();
    k[at..at + 4].copy_from_slice(&[0x5c, 0, delta.to_be_bytes()[0], delta.to_be_bytes()[1]]);
    assert!(!c.accepts_kernel(&k));
    let mut n = f.normal.clone();
    n[f.owner + 8..f.owner + 14].copy_from_slice(&imm(target, 0));
    let bodies = sink_declarations::bind(&n, &f.kernel, f.seed).unwrap();
    assert!(declared_certificate(&n, &f.kernel, bodies).is_err());
}
#[test]
fn generic_crossing_requires_complete_adjacent_instructions() {
    let ranges = alloc::vec![10..16, 16..20];
    assert!(crosses(&ranges, 14, 4));
    for (at, len) in [(12, 4), (10, 4), (14, 2), (18, 4)] {
        assert!(!crosses(&ranges, at, len));
    }
    assert!(!crosses(&[10..16, 18..22], 14, 4));
    assert!(!crosses(&[], 14, 4));
    let f = fixture(0);
    assert!(sink_declarations::bind(&f.normal, &f.kernel, 0x1f00).is_none());
}

#[test]
fn support_prefix_stops_at_first_connected_call_and_tail_stays_raw() {
    let mut f = fixture(0);
    // The byte after the selected call is unsupported, outside the prefix.
    f.normal[0x1010..0x1012].copy_from_slice(&[0xff, 0xff]);
    let c = certificate(&f);
    assert!(!c
        .bodies
        .iter()
        .any(|b| b.instructions.iter().any(|r| r.contains(&0x1000))));
    assert!(!c.is_cross_instruction_literal(0x1010, 4));
    let interior = c.forbidden_instruction_entries[0];
    f.normal[0x1010..0x1014].copy_from_slice(&interior.to_be_bytes());
    let bodies = sink_declarations::bind(&f.normal, &f.kernel, f.seed).unwrap();
    assert!(declared_certificate(&f.normal, &f.kernel, bodies).is_err());
    let mut f = fixture(0);
    // Unsupported control before the connected call cannot be skipped.
    f.normal[0x1006..0x100a].copy_from_slice(&[0x59, 0x10, 0, 0]);
    assert!(sink_declarations::bind(&f.normal, &f.kernel, f.seed).is_none());
    let mut f = fixture(0);
    f.normal[0x1006..0x100a].copy_from_slice(&[0x47, 3, 0, 0]);
    assert!(sink_declarations::bind(&f.normal, &f.kernel, f.seed).is_none());
}
#[test]
fn descriptor_record_arguments_and_prefix_candidate_uniqueness_are_required() {
    let mut f = fixture(0);
    // The SP-derived record argument must point at the actual record.
    f.normal[f.base + 43] ^= 1;
    assert!(sink_declarations::bind(&f.normal, &f.kernel, f.seed).is_none());
    let mut f = fixture(0);
    let at = f.invoker + 22;
    let mut block = f.normal[at..at + 30].to_vec();
    block[16..18].copy_from_slice(&48u16.to_be_bytes());
    block[22..24].copy_from_slice(&42u16.to_be_bytes());
    f.normal.copy_within(at + 30..at + 42, at + 60);
    f.normal[at + 30..at + 60].copy_from_slice(&block);
    f.normal[f.child_table + 48..f.child_table + 52]
        .copy_from_slice(&(NORMAL_BASE + f.caller as u32).to_be_bytes());
    f.normal[f.child_table + 42..f.child_table + 46].fill(0);
    assert!(sink_declarations::bind(&f.normal, &f.kernel, f.seed).is_none());
}

#[cfg(feature = "envelope")]
#[test]
#[ignore = "requires the exact original authenticated S2 fixture"]
fn authenticated_original_331_boundary_and_existing_sinks_result() {
    use sha2::{Digest, Sha256};
    let root = std::path::PathBuf::from(std::env::var("S2_FIXTURES").unwrap());
    let n = std::fs::read(root.join("331-normal.enc")).unwrap();
    let k = std::fs::read(root.join("331-kernel.enc")).unwrap();
    assert_eq!(
        alloc::format!("{:x}", Sha256::digest(&n)),
        "6a04d472f6531365cc71253bdd69599d342b520e1da54d766ee322c493221ad3"
    );
    assert_eq!(
        alloc::format!("{:x}", Sha256::digest(&k)),
        "c6bcdb46b8a1f575a2fe21838cdff7df466d68dfe62e1e136f6a26ff62591f22"
    );
    let u = crate::envelope::Update::load(&k, &n).unwrap();
    let normal = &u.normal().image;
    let kernel = &u.kernel().image;
    let diagnostic = super::super::sinks::diagnose(normal);
    std::println!("red_sink_diagnostic={diagnostic:?}");
    let Err(super::super::sinks::Failure::UnclassifiedAddressReference {
        stage: super::super::sinks::Stage::ClosedEntries,
        at,
        ..
    }) = diagnostic
    else {
        panic!("actual ClosedEntries seed")
    };
    let bodies = sink_declarations::bind(normal, kernel, at).expect("source-derived declaration");
    std::println!(
        "owned_instruction_counts={:?}",
        bodies
            .iter()
            .map(|b| b.instructions.len())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        bodies
            .iter()
            .map(|b| b.instructions.len())
            .collect::<Vec<_>>(),
        [532, 80]
    );
    let c = bind(normal, kernel).unwrap();
    assert_eq!(c.forbidden_instruction_entries.len(), 394);
    assert!(c.is_cross_instruction_literal(at, 4));
    assert!(c.accepts_kernel(kernel));
    std::println!(
        "green_sinks_result={:?}",
        super::super::sinks::diagnose_with_boundary(normal, &c)
    );
    let interior = c.forbidden_instruction_entries[0];
    let outside = c.bodies[0].instructions[0].start - 8;
    let mut changed_normal = normal.clone();
    changed_normal[outside..outside + 4].copy_from_slice(&interior.to_be_bytes());
    assert!(bind(&changed_normal, kernel).is_err());
    let displacement =
        i16::try_from(i64::from(interior) - i64::from(NORMAL_BASE + outside as u32 + 4)).unwrap();
    changed_normal[outside..outside + 2].copy_from_slice(&[0x58, 0]);
    changed_normal[outside + 2..outside + 4].copy_from_slice(&displacement.to_be_bytes());
    assert!(bind(&changed_normal, kernel).is_err());
    assert!(bind(normal, &[]).is_err());

    let interior = c.forbidden_instruction_entries[0];
    let mut changed = kernel.clone();
    changed[0x20..0x24].copy_from_slice(&interior.to_be_bytes());
    assert!(!c.accepts_kernel(&changed));
    assert!(bind(normal, &changed).is_err());
    let owner = &c.bodies[0].instructions;
    let address = NORMAL_BASE + owner[0].start as u32;
    assert!(
        (i64::from(address) - i64::from(KERNEL_BASE + kernel.len() as u32 - 2))
            > i64::from(i16::MAX)
    );
}
