//! Native selector/inverse execution and complete profile relocation checks.
#![cfg(feature = "envelope")]
use h8_asm::{
    isa::{decode_insn, Ea, Operand as O, Reg},
    Mode, Target,
};
use pioneer_optical::filters::phase::bundle::waveforms::resources::trajectory_profile as profile;
use std::collections::BTreeMap;
fn fixture(role: &str) -> Vec<u8> {
    let f: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/phase-trajectory-profile.json")).unwrap();
    let f = f
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["role"] == role)
        .unwrap();
    let mut n = vec![255; f["size"].as_u64().unwrap() as usize];
    for span in f["spans"].as_array().unwrap() {
        let a = span[0].as_u64().unwrap() as usize;
        let h = span[1].as_str().unwrap();
        for i in 0..h.len() / 2 {
            n[a + i] = u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap();
        }
    }
    n
}
fn plan(t: &[u8], s: &[u8]) -> profile::Plan {
    let [code, data] = profile::lengths();
    profile::plan(
        t,
        s,
        0x1000..0x1000 + code,
        0x3000..0x3000 + data,
        0x2100,
        profile::Services {
            report: [0x410800, 0x410804],
            state_getter: 0x538f56,
            hardware_mode: 0x538f7e,
        },
    )
    .unwrap()
}
fn coordinates(r: Reg) -> (usize, u32, u32) {
    match r {
        Reg::Byte(n) => ((n % 8) as usize, if n < 8 { 8 } else { 0 }, 255),
        Reg::Word(n) => ((n % 8) as usize, if n < 8 { 0 } else { 16 }, 65535),
        Reg::Long(n) => (n as usize, 0, u32::MAX),
        _ => panic!(),
    }
}
fn get(r: &[u32; 8], reg: Reg) -> u32 {
    let (n, s, m) = coordinates(reg);
    (r[n] >> s) & m
}
fn set(r: &mut [u32; 8], reg: Reg, v: u32) {
    let (n, s, m) = coordinates(reg);
    r[n] = (r[n] & !(m << s)) | ((v & m) << s);
}
fn execute(
    image: &[u8],
    entry: u32,
    memory: &mut BTreeMap<u32, u8>,
    input: u32,
) -> (u32, Vec<(u32, u8)>) {
    let mut r = [0x13579bdf; 8];
    r[0] = input;
    r[7] = 0x8000;
    let mut pc = entry;
    let mut zero = false;
    let mut carry = false;
    let mut saved = Vec::new();
    let mut returns = Vec::new();
    let mut writes = Vec::new();
    let read = |a: u32, size: usize, m: &BTreeMap<u32, u8>| -> u32 {
        (0..size).fold(0, |v, i| {
            (v << 8)
                | u32::from(if a + i as u32 >= 0x410000 {
                    image[(a + i as u32 - 0x410000) as usize]
                } else {
                    *m.get(&(a + i as u32)).unwrap_or(&0)
                })
        })
    };
    for _ in 0..1000 {
        let d = decode_insn(
            &image[(pc - 0x410000) as usize..],
            Target::H8S2000,
            Mode::Advanced,
        )
        .unwrap();
        let i = d.insn;
        pc += d.len as u32;
        let [a, b, _] = i.operands;
        let value = |op| match op {
            O::Register(reg) => get(&r, reg),
            O::Immediate { value, .. } => value,
            _ => panic!(),
        };
        match (i.mnemonic, a, b) {
            ("MOV", O::Register(reg), O::Address(Ea::PreDecrement(Reg::Long(7)))) => {
                saved.push(get(&r, reg));
                r[7] -= 2;
            }
            ("MOV", O::Address(Ea::PostIncrement(Reg::Long(7))), O::Register(reg)) => {
                set(&mut r, reg, saved.pop().unwrap());
                r[7] += 2;
            }
            ("MOV", O::Address(Ea::Absolute { value: a, .. }), O::Register(reg)) => {
                let v = read(a, if matches!(reg, Reg::Byte(_)) { 1 } else { 2 }, memory);
                set(&mut r, reg, v);
                zero = v == 0;
            }
            ("MOV", O::Address(Ea::Displacement { base, value, .. }), O::Register(reg)) => {
                let v = read(get(&r, base).wrapping_add_signed(value), 2, memory);
                set(&mut r, reg, v);
                zero = v == 0;
            }
            ("MOV", O::Register(reg), O::Address(Ea::Absolute { value: a, .. })) => {
                let v = get(&r, reg) as u8;
                memory.insert(a, v);
                writes.push((a, v));
                zero = v == 0;
            }
            ("MOV", a, O::Register(reg)) => {
                let v = value(a);
                set(&mut r, reg, v);
                zero = v == 0;
            }
            ("EXTU", O::Register(reg), _) => {
                let v = get(&r, reg)
                    & if matches!(reg, Reg::Long(_)) {
                        65535
                    } else {
                        255
                    };
                set(&mut r, reg, v);
                zero = v == 0;
            }
            ("EXTS", O::Register(Reg::Long(n)), _) => {
                let v = r[n as usize] as i16 as i32 as u32;
                r[n as usize] = v;
                zero = v == 0;
            }
            ("SHLL", a, O::Register(reg)) => {
                let v = get(&r, reg) << value(a);
                set(&mut r, reg, v);
                zero = v == 0;
            }
            ("ADD", a, O::Register(reg)) => {
                let v = get(&r, reg).wrapping_add(value(a));
                set(&mut r, reg, v);
                zero = get(&r, reg) == 0;
            }
            ("SUB", a, O::Register(reg)) => {
                let v = get(&r, reg).wrapping_sub(value(a));
                set(&mut r, reg, v);
                zero = get(&r, reg) == 0;
            }
            ("CMP", a, O::Register(reg)) => {
                let rhs = value(a);
                let lhs = get(&r, reg);
                carry = lhs < rhs;
                zero = lhs == rhs;
            }
            ("INC", a, O::Register(reg)) => {
                let v = get(&r, reg).wrapping_add(value(a));
                set(&mut r, reg, v);
                zero = get(&r, reg) == 0;
            }
            ("DEC", a, O::Register(reg)) => {
                let v = get(&r, reg).wrapping_sub(value(a));
                set(&mut r, reg, v);
                zero = get(&r, reg) == 0;
            }
            ("JSR", O::Address(Ea::Absolute { value, .. }), _) => {
                returns.push(pc);
                r[7] -= 4;
                pc = value;
            }
            ("RTS", _, _) => {
                if let Some(ret) = returns.pop() {
                    r[7] += 4;
                    pc = ret;
                } else {
                    assert!(saved.is_empty());
                    assert_eq!(r[7], 0x8000);
                    assert!(r[3..7].iter().all(|v| *v == 0x13579bdf));
                    return (r[0], writes);
                }
            }
            ("BRA" | "BNE" | "BCS" | "BCC", O::Address(Ea::PcRelative { value, .. }), _) => {
                if match i.mnemonic {
                    "BRA" => true,
                    "BNE" => !zero,
                    "BCS" => carry,
                    "BCC" => !carry,
                    _ => unreachable!(),
                } {
                    pc = pc.wrapping_add_signed(value);
                }
            }
            other => panic!("{other:?}"),
        }
    }
    panic!("did not return")
}
#[test]
fn prepares_all_target_native_domains_through_source_selector() {
    let t = fixture("target");
    let s = fixture("source");
    let p = plan(&t, &s);
    let mut changed = t.clone();
    for (span, b) in &p.writes {
        changed[span.clone()].copy_from_slice(b);
    }
    for index in 0..82u8 {
        let address = if index < 13 {
            0x5a4b54 + (u32::from(index) + 28) * 4 + 2
        } else {
            0x5a4bf8 + (u32::from(index) - 13) * 4 + 2
        };
        let a = (address - 0x410000) as usize;
        let frequency = u16::from_be_bytes([t[a], t[a + 1]]);
        let mut expected = BTreeMap::new();
        execute(
            &s,
            0x5d6068,
            &mut expected,
            (u32::from(frequency) << 16) | 1,
        );
        let mut memory = BTreeMap::from([(0x3265, index), (0x3266, 81 - index)]);
        let (_, writes) = execute(&changed, p.prepare, &mut memory, 0xa5a50000);
        assert_eq!(
            writes,
            vec![(0x2101, expected[&0x32bf])],
            "index{index} frequency{frequency}"
        );
        assert_eq!(memory[&0x3265], index);
        assert_eq!(memory[&0x3266], 81 - index);
    }
}
#[test]
fn complete_profile_relocation_preserves_native_instructions_and_call_effects() {
    let t = fixture("target");
    let s = fixture("source");
    let p = plan(&t, &s);
    let code = &p.writes[0].1;
    // Every sourceinit/updater instruction survives at the same relative offset;
    // only declared typed address operands may differ. Each source log survives.
    let mut reports = Vec::new();
    for (old, new) in &p.entries[..2] {
        let len = if *old == 0x5d5aa6 { 698 } else { 636 };
        let mut at = 0;
        while at < len {
            let d = decode_insn(
                &s[(*old - 0x410000) as usize + at..],
                Target::H8S2000,
                Mode::Advanced,
            )
            .unwrap();
            let e = decode_insn(
                &code[(*new - 0x411000) as usize + at..],
                Target::H8S2000,
                Mode::Advanced,
            )
            .unwrap();
            assert_eq!(d.len, e.len);
            assert_eq!(d.insn.mnemonic, e.insn.mnemonic);
            assert_eq!(d.insn.size, e.insn.size);
            for (a, b) in d.insn.operands.into_iter().zip(e.insn.operands) {
                if a != b {
                    assert!(matches!(
                        a,
                        O::Address(Ea::Absolute { .. })
                            | O::Immediate { bits: 32, .. }
                            | O::Address(Ea::Displacement { bits: 32, .. })
                    ));
                }
            }
            if d.insn.mnemonic == "JSR"
                && matches!(
                    d.insn.operands[0],
                    O::Address(Ea::Absolute {
                        value: 0x5f0102,
                        ..
                    })
                )
            {
                reports.push(e.insn.operands[0]);
            }
            at += d.len;
        }
    }
    assert_eq!(
        reports,
        vec![
            O::Address(Ea::Absolute {
                value: 0x410800,
                bits: 24
            }),
            O::Address(Ea::Absolute {
                value: 0x410804,
                bits: 24
            })
        ]
    );
    for offset in [
        0x5d5aa6 - 0x410000,
        0x65f142 - 0x410000,
        0x65ed70 - 0x410000,
    ] {
        let mut bad = s.clone();
        bad[offset] ^= 1;
        let [c, d] = profile::lengths();
        assert!(profile::plan(
            &t,
            &bad,
            0x1000..0x1000 + c,
            0x3000..0x3000 + d,
            0x2100,
            profile::Services {
                report: [0x410800, 0x410804],
                state_getter: 0x538f56,
                hardware_mode: 0x538f7e
            }
        )
        .is_none());
    }
}

#[test]
fn high_volatile_ram_relocates_without_instruction_widening() {
    let target = fixture("target");
    let source = fixture("source");
    let [code, data] = profile::lengths();
    let p = profile::plan(
        &target,
        &source,
        0x1000..0x1000 + code,
        0x3000..0x3000 + data,
        0xa05ddd,
        profile::Services {
            report: [0x410800, 0x410804],
            state_getter: 0x538f56,
            hardware_mode: 0x538f7e,
        },
    )
    .unwrap();
    assert_eq!(p.writes[0].1.len(), code);
    let mut changed = target;
    for (span, body) in &p.writes {
        changed[span.clone()].copy_from_slice(body);
    }
    let mut memory = BTreeMap::from([(0x3265, 13)]);
    let (_, writes) = execute(&changed, p.prepare, &mut memory, 0);
    assert_eq!(writes, vec![(0xa05dde, 9)]);
}

#[test]
fn default_client_binds_boot_seed_and_rejects_unknown_writers() {
    let target = fixture("target");
    let kernel = vec![255; pioneer_optical::image::KERNEL_LEN];
    profile::validate_default(&target, &kernel).unwrap();
    // Extent, copycallee, veneer ABI, initialbyte and selector bound all matter.
    for at in [0x4aefca, 0x4aefa8, 0x58062b, 0x5997d1, 0x5997d3, 0x537f3c] {
        let mut bad = target.clone();
        bad[at - 0x410000] ^= 1;
        assert!(profile::validate_default(&bad, &kernel).is_none(), "{at:x}");
    }
    for writer in [
        vec![0x6a, 0xa8, 0, 0, 0x32, 0x65],
        vec![0x6a, 0x88, 0x32, 0x65],
        vec![0x6a, 0xa8, 0, 0, 0x32, 0x67],
        vec![0x6b, 0xa0, 0, 0, 0x32, 0x64],
        vec![0x01, 0x00, 0x6b, 0xa0, 0, 0, 0x32, 0x62],
    ] {
        let mut bad = target.clone();
        bad[0x800..0x800 + writer.len()].copy_from_slice(&writer);
        assert!(profile::validate_default(&bad, &kernel).is_none());
        let mut resident = kernel.clone();
        resident[0x800..0x800 + writer.len()].copy_from_slice(&writer);
        assert!(profile::validate_default(&target, &resident).is_none());
    }
    let mut bad = target.clone();
    bad[0x801..0x805].copy_from_slice(&0x3265u32.to_be_bytes());
    assert!(profile::validate_default(&bad, &kernel).is_none());
    bad[0x801..0x805].copy_from_slice(&0x3267u32.to_be_bytes());
    assert!(profile::validate_default(&bad, &kernel).is_none());
    assert!(profile::validate_default(&target, &kernel[..100]).is_none());
}

#[test]
#[ignore = "requires actual paired Normal and Kernel"]
fn actual_default_client_closure() {
    let path = std::env::var("PIONEER_TRAJECTORY_TARGET").unwrap();
    let target = std::fs::read(&path).unwrap();
    let kernel = std::fs::read(path.replace(".bin", ".kernel.bin")).unwrap();
    profile::validate_default(&target, &kernel).unwrap();
}

#[test]
fn default_client_scans_expanded_normal_and_kernel() {
    use std::io::Write;
    fn comp(image: &mut [u8], expanded: &[u8]) {
        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(expanded).unwrap();
        let bytes = encoder.finish().unwrap();
        image[0x1000..0x1100].fill(255);
        image[0x1000..0x1004].copy_from_slice(b"COMP");
        image[0x1004..0x1008].copy_from_slice(&0x412000u32.to_be_bytes());
        image[0x1008..0x100c].copy_from_slice(&(0x412000u32 + bytes.len() as u32).to_be_bytes());
        image[0x2000..0x2004].copy_from_slice(&(expanded.len() as u32).to_be_bytes());
        image[0x2004..0x2004 + bytes.len()].copy_from_slice(&bytes);
    }
    let target = fixture("target");
    let kernel = vec![255; pioneer_optical::image::KERNEL_LEN];
    let mut benign = target.clone();
    comp(&mut benign, &[0x54, 0x70]);
    assert!(profile::validate_default(&benign, &kernel).is_some());
    let mut resident = kernel.clone();
    comp(&mut resident, &[0x54, 0x70]);
    assert!(profile::validate_default(&target, &resident).is_some());
    let writer = [0x6a, 0xa8, 0, 0, 0x32, 0x67];
    comp(&mut benign, &writer);
    assert!(profile::validate_default(&benign, &kernel).is_none());
    comp(&mut resident, &writer);
    assert!(profile::validate_default(&target, &resident).is_none());
}

fn shared_slots() -> profile::SharedPlacements {
    let (code, data) = profile::shared_lengths();
    profile::SharedPlacements {
        code: core::array::from_fn(|i| 0x1000 + i * 0x400..0x1000 + i * 0x400 + code[i]),
        data: core::array::from_fn(|i| 0x8000 + i * 0x400..0x8000 + i * 0x400 + data[i]),
    }
}
fn shared(t: &[u8], s: &[u8], k: &[u8]) -> Option<profile::SharedPlan> {
    profile::shared_plan(
        t,
        s,
        k,
        shared_slots(),
        0xa05ddd,
        profile::Services {
            report: [0x410800, 0x410804],
            state_getter: 0x538f56,
            hardware_mode: 0x538f7e,
        },
    )
}
#[test]
fn shared_profile_closes_native_callers_and_preserves_special_blocks() {
    let t = fixture("target");
    let s = fixture("source");
    let k = vec![255; pioneer_optical::image::KERNEL_LEN];
    let p = shared(&t, &s, &k).expect("shared native profile");
    assert_eq!(p.retired, vec![0x1278b6..0x127e26]);
    assert_eq!(p.replaced_by_outer, 0x129b1a..0x129b1e);
    let slots = shared_slots();
    for (r, b) in &p.profile.writes {
        assert_eq!(r.len(), b.len());
    }
    let emitted = |i: usize| {
        p.profile
            .writes
            .iter()
            .find(|(r, _)| *r == slots.code[i])
            .unwrap()
            .1
            .as_slice()
    };
    // The native nonzero init is copied byte-for-byte after removal of its
    // already-decided condition and the unconditional jump to its epilogue.
    let mut init = t[0x1278b6..0x1278c2].to_vec();
    init.extend_from_slice(&t[0x1278c6..0x1278e0]);
    init.extend_from_slice(&t[0x127b52..0x127b58]);
    assert_eq!(emitted(7), init);
    let update = emitted(8);
    let mut at = 0;
    let mut table = false;
    while at < update.len() {
        let d = decode_insn(&update[at..], Target::H8S2000, Mode::Advanced).unwrap();
        for op in d.insn.operands {
            match op {
                O::Immediate {
                    value: 0x5a4edc, ..
                }
                | O::Address(Ea::Displacement {
                    value: 0x5a4edc, ..
                }) => table = true,
                O::Address(Ea::PcRelative { value, .. }) => assert!((0..update.len())
                    .contains(&((at + d.len) as isize + value as isize).try_into().unwrap())),
                O::Address(Ea::Absolute { value, .. }) if d.insn.mnemonic == "JMP" => {
                    assert!((0x410000 + slots.code[8].start as u32
                        ..0x410000 + slots.code[8].end as u32)
                        .contains(&value))
                }
                _ => {}
            }
        }
        at += d.len;
    }
    assert!(table);
    for (at, pattern) in [
        (0x6000, vec![0x5e, 0x53, 0x78, 0xb6]),
        (0x6000, vec![0x5e, 0x53, 0x94, 0x06]),
        (0x6001, vec![0, 0x53, 0x7b, 0x59]),
    ] {
        let mut bad = t.clone();
        bad[at..at + pattern.len()].copy_from_slice(&pattern);
        assert!(shared(&bad, &s, &k).is_none());
        let mut badk = k.clone();
        badk[at..at + pattern.len()].copy_from_slice(&pattern);
        assert!(shared(&t, &s, &badk).is_none());
    }
    for at in [0x129406, 0x1292d2, 0x194edc] {
        let mut bad = t.clone();
        bad[at] ^= 1;
        assert!(shared(&bad, &s, &k).is_none());
    }
}
#[test]
#[ignore = "requires actual paired Normal and Kernel"]
fn actual_shared_profile_closure() {
    let path = std::env::var("PIONEER_TRAJECTORY_TARGET").unwrap();
    let t = std::fs::read(&path).unwrap();
    let k = std::fs::read(path.replace(".bin", ".kernel.bin")).unwrap();
    let p = shared(&t, &fixture("source"), &k).expect("actual shared closure");
    let slots = shared_slots();
    let roots = profile::SharedEntries {
        init: 0x410000 + slots.code[0].start as u32,
        update: 0x410000 + slots.code[1].start as u32,
        ctor: 0x410000 + slots.code[2].start as u32,
        prepare: p.profile.prepare,
    };
    let mut emitted = t;
    for (r, b) in p.profile.writes {
        emitted[r].copy_from_slice(&b);
    }
    profile::observe_shared(
        &emitted,
        &k,
        roots,
        profile::Services {
            report: [0x410800, 0x410804],
            state_getter: 0x538f56,
            hardware_mode: 0x538f7e,
        },
        0xa05ddd,
    )
    .expect("actual emitted observation");
}

#[test]
fn shared_observation_reads_complete_emitted_bodies_without_preimage() {
    let t = fixture("target");
    let s = fixture("source");
    let k = vec![255; pioneer_optical::image::KERNEL_LEN];
    let p = shared(&t, &s, &k).unwrap();
    let slots = shared_slots();
    let roots = profile::SharedEntries {
        init: 0x410000 + slots.code[0].start as u32,
        update: 0x410000 + slots.code[1].start as u32,
        ctor: 0x410000 + slots.code[2].start as u32,
        prepare: p.profile.prepare,
    };
    let services = profile::Services {
        report: [0x410800, 0x410804],
        state_getter: 0x538f56,
        hardware_mode: 0x538f7e,
    };
    let mut n = t;
    for (r, b) in p.profile.writes {
        n[r].copy_from_slice(&b);
    }
    let observed =
        profile::observe_shared(&n, &k, roots, services, 0xa05ddd).expect("emitted graph");
    assert_eq!(observed.placements.code, slots.code);
    assert_eq!(observed.placements.data, slots.data);
    let authority = &observed.data_authority;
    assert!(authority.is_bound_to(&n));
    assert_eq!(authority.ranges(), &slots.data);
    assert_eq!(authority.scalar_ranges(), &slots.data[..4]);
    assert_eq!(authority.diagnostic_range(), &slots.data[4]);
    let instruction = slots.code[0].start + 0xa6;
    let address = 0x410000 + slots.data[0].start;
    assert!(authority.allow_typed(instruction, 0, address));
    assert!(authority.allow_raw(instruction + 2, address));
    assert!(!authority.allow_typed(instruction, 1, address));
    assert!(!authority.allow_raw(instruction + 1, address));
    let mut stale = n.clone();
    stale[slots.data[0].start] ^= 1;
    assert!(!authority.is_bound_to(&stale));
    // Complete-body recognition catches damage far from entry signatures and
    // verifies code, tables, diagnostic strings, and retained native clients.
    for r in slots.code.iter().chain(&slots.data) {
        let mut bad = n.clone();
        bad[r.end - 1] ^= 1;
        assert!(
            profile::observe_shared(&bad, &k, roots, services, 0xa05ddd).is_none(),
            "{r:?}"
        );
    }
    for at in [0x129495, 0x1293f3, 0x12898f, 0x12e000, 0x1acc44] {
        let mut bad = n.clone();
        bad[at] ^= 1;
        if at == 0x12e000 {
            bad[at..at + 6].copy_from_slice(&[0x6a, 0xa8, 0, 0, 0x32, 0x67]);
        }
        assert!(
            profile::observe_shared(&bad, &k, roots, services, 0xa05ddd).is_none(),
            "{at:x}"
        );
    }
    assert!(profile::observe_shared(&n, &k, roots, services, 0xa05dde).is_none());
    let mut badk = k;
    badk[0x800..0x806].copy_from_slice(&[0x6a, 0xa8, 0, 0, 0x32, 0x67]);
    assert!(profile::observe_shared(&n, &badk, roots, services, 0xa05ddd).is_none());
}
