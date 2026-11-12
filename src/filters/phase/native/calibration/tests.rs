use super::*;
use h8_asm::{
    isa::{self, Ea, Insn, Operand, Reg},
    Mode, Target,
};
use std::collections::BTreeMap;

fn instructions(bytes: &[u8]) -> BTreeMap<usize, (Insn, usize)> {
    let mut result = BTreeMap::new();
    let mut at = 0;
    while at < bytes.len() {
        let decoded = isa::decode_insn(&bytes[at..], Target::H8S2600, Mode::Advanced).unwrap();
        result.insert(at, (decoded.insn, decoded.len));
        at += decoded.len;
    }
    assert_eq!(at, bytes.len());
    result
}

struct Reader {
    registers: [u32; 8],
    saved: Vec<u32>,
    reads: Vec<u16>,
    words: [u16; 2],
    zero: bool,
}
impl Reader {
    fn get(&self, reg: Reg) -> u32 {
        match reg {
            Reg::Byte(n) => (self.registers[(n % 8) as usize] >> if n < 8 { 8 } else { 0 }) & 255,
            Reg::Word(n) => {
                (self.registers[(n % 8) as usize] >> if n < 8 { 0 } else { 16 }) & 65535
            }
            Reg::Long(n) => self.registers[n as usize],
            _ => panic!("unsupported register {reg:?}"),
        }
    }
    fn set(&mut self, reg: Reg, value: u32) {
        let (n, shift, mask) = match reg {
            Reg::Byte(n) => (n % 8, if n < 8 { 8 } else { 0 }, 255),
            Reg::Word(n) => (n % 8, if n < 8 { 0 } else { 16 }, 65535),
            Reg::Long(n) => (n, 0, u32::MAX),
            _ => panic!("unsupported register {reg:?}"),
        };
        let old = &mut self.registers[n as usize];
        *old = (*old & !(mask << shift)) | ((value & mask) << shift);
        self.zero = value & mask == 0;
    }
    fn value(&self, operand: Operand) -> u32 {
        match operand {
            Operand::Register(r) => self.get(r),
            Operand::Immediate { value, .. } => value,
            _ => panic!("{operand:?}"),
        }
    }
    fn run(program: &Program, mode: u8, words: [u16; 2]) -> (u16, Vec<u16>) {
        let mut cpu = Self {
            registers: [0xa55a_5aa5; 8],
            saved: Vec::new(),
            reads: Vec::new(),
            words,
            zero: false,
        };
        cpu.set(Reg::Byte(8), mode.into());
        let original_r3 = cpu.registers[3];
        let mut at = program.entry;
        for _ in 0..64 {
            let (i, len) = program.instructions[&at];
            let [a, b, _] = i.operands;
            let next = at + len;
            at = next;
            match (i.mnemonic, a, b) {
                ("MOV", Operand::Register(r), Operand::Address(Ea::PreDecrement(Reg::Long(7)))) => {
                    cpu.saved.push(cpu.get(r))
                }
                (
                    "MOV",
                    Operand::Address(Ea::PostIncrement(Reg::Long(7))),
                    Operand::Register(r),
                ) => {
                    let v = cpu.saved.pop().unwrap();
                    cpu.set(r, v);
                }
                ("MOV", a, Operand::Register(r)) => cpu.set(r, cpu.value(a)),
                ("SUB", a, Operand::Register(r)) => {
                    cpu.set(r, cpu.get(r).wrapping_sub(cpu.value(a)))
                }
                ("AND", a, Operand::Register(r)) => cpu.set(r, cpu.get(r) & cpu.value(a)),
                ("CMP", a, b) => cpu.zero = cpu.value(a) == cpu.value(b),
                ("BRA" | "BEQ" | "BNE", Operand::Address(Ea::PcRelative { value, .. }), _) => {
                    if i.mnemonic == "BRA"
                        || (i.mnemonic == "BEQ" && cpu.zero)
                        || (i.mnemonic == "BNE" && !cpu.zero)
                    {
                        at = next.wrapping_add_signed(value as isize);
                    }
                }
                ("JMP", Operand::Address(Ea::Absolute { value, .. }), _) => at = value as usize,
                ("JSR", Operand::Address(Ea::Absolute { value, .. }), _) => {
                    assert_eq!(value, 0x410600);
                    let index = cpu.get(Reg::Word(0)) as u16;
                    assert!(matches!(index, 0x112 | 0x113));
                    cpu.reads.push(index);
                    cpu.set(Reg::Word(0), cpu.words[(index - 0x112) as usize].into());
                }
                ("NOP", _, _) => {}
                ("RTS", _, _) => {
                    assert!(cpu.saved.is_empty());
                    assert_eq!(cpu.registers[3], original_r3);
                    return (cpu.get(Reg::Word(0)) as u16, cpu.reads);
                }
                _ => panic!("unsupported reader instruction {i:?}"),
            }
        }
        panic!("reader did not terminate");
    }
}

fn fixture(packed: bool, address: u32) -> Vec<u8> {
    let mut normal = alloc::vec![0xff;0x800];
    let mut code = if packed {
        PACKED.to_vec()
    } else {
        WHOLE.to_vec()
    };
    for at in if packed { PACKED_CALLS } else { WHOLE_CALLS } {
        code[*at..*at + 3].copy_from_slice(&address.to_be_bytes()[1..]);
    }
    normal[0x100..0x100 + code.len()].copy_from_slice(&code);
    normal
}
struct Program {
    entry: usize,
    instructions: BTreeMap<usize, (Insn, usize)>,
}
fn program(normal: &[u8]) -> Program {
    let bound = bind(normal).unwrap();
    let mut decoded = BTreeMap::new();
    for span in &bound.body.spans {
        for (offset, instruction) in instructions(&normal[span.clone()]) {
            decoded.insert(0x410000 + span.start + offset, instruction);
        }
    }
    Program {
        entry: 0x410000 + bound.at,
        instructions: decoded,
    }
}

#[test]
fn rewritten_readers_preserve_consumed_calibration_bytes_for_every_word_and_mode() {
    let whole = fixture(false, 0x410600);
    let packed = fixture(true, 0x410600);
    let to_whole = rewrite(&packed, &fixture(false, 0x410700), None).unwrap();
    let to_packed = rewrite(&whole, &fixture(true, 0x410700), Some(0x300..0x344)).unwrap();
    let donor_whole = fixture(false, 0x410700);
    let donor_packed = fixture(true, 0x410700);
    let native_whole = transplant(&packed, &donor_whole, None).unwrap();
    let native_packed = transplant(&whole, &donor_packed, Some(0x300..0x344)).unwrap();
    for (target, donor, changed) in [
        (&packed, &donor_whole, &native_whole),
        (&whole, &donor_packed, &native_packed),
    ] {
        let source = bind(donor).unwrap();
        let after = bind(changed).unwrap();
        let len = if source.packed_shape {
            PACKED.len()
        } else {
            WHOLE.len()
        };
        let fields = if source.packed_shape {
            PACKED_CALLS
        } else {
            WHOLE_CALLS
        };
        for offset in 0..len {
            if !fields
                .iter()
                .any(|field| (*field..*field + 3).contains(&offset))
            {
                assert_eq!(after.body.bytes[offset], source.body.bytes[offset]);
            }
        }
        for (at, (old, new)) in target.iter().zip(changed).enumerate() {
            if old != new {
                assert!(
                    (0x100..0x100 + PACKED.len()).contains(&at) || (0x300..0x344).contains(&at)
                );
            }
        }
    }
    let cases = [
        (program(&native_whole), false),
        (program(&native_packed), true),
        (program(&whole), false),
        (program(&packed), true),
        (program(&to_whole), false),
        (program(&to_packed), true),
    ];
    for word in 0..=u16::MAX {
        let words = [word, !word];
        for mode in 0..4u8 {
            let index = usize::from(mode / 2);
            for (program, packed) in &cases {
                let (actual, reads) = Reader::run(program, mode, words);
                let expected = if *packed && mode % 2 == 0 {
                    words[index] >> 8
                } else {
                    words[index] & 255
                };
                assert_eq!(
                    actual & 255,
                    expected,
                    "word {word:#x}, mode {mode}, packed {packed}"
                );
                assert_eq!(reads, [0x112 + index as u16]);
            }
        }
    }
    for mode in 4..=255 {
        for (program, _) in &cases {
            let (actual, reads) = Reader::run(program, mode, [0x0205, 0x0f06]);
            assert_eq!(actual & 255, 255);
            assert!(reads.is_empty());
        }
    }
}

#[test]
fn split_calibration_reuses_prefix_and_refuses_a_branch_crossing_the_split() {
    let whole = fixture(false, 0x410600);
    let packed = fixture(true, 0x410700);
    // 54 bytes holds only the packed reader's suffix, not its complete 66 bytes.
    let changed = transplant(&whole, &packed, Some(0x300..0x336)).unwrap();
    let bound = bind(&changed).unwrap();
    assert_eq!(bound.at, 0x100);
    assert_eq!(bound.body.spans, [0x100..0x110, 0x300..0x336]);
    assert_eq!(&changed[0x100..0x10c], &packed[0x100..0x10c]);
    assert_eq!(transplant(&changed, &packed, None).unwrap(), changed);
    let restored = transplant(&changed, &whole, None).unwrap();
    assert_eq!(observe(&restored), Ok(Convention::WholeWord));
    for mode in 0..=255 {
        for word in [0, 1, 0xff, 0x100, 0x55aa, 0xffff] {
            assert_eq!(
                Reader::run(&program(&restored), mode, [word, !word]),
                Reader::run(&program(&whole), mode, [word, !word])
            );
        }
    }
    // An otherwise byte-identical reader split after the first conditional
    // branch would make that branch land in overwritten original bytes.
    let mut invalid = whole;
    let mut body = packed[0x100..0x100 + PACKED.len()].to_vec();
    for call in [42, 52] {
        super::super::encoding::retarget_call(&mut body, call, 0x410600).unwrap();
    }
    invalid[0x100..0x114].copy_from_slice(&body[..20]);
    invalid[0x114..0x118].copy_from_slice(&super::super::encoding::jump(0x410300).unwrap());
    invalid[0x300..0x300 + body.len() - 20].copy_from_slice(&body[20..]);
    assert_eq!(observe(&invalid), Err(Error::Unresolved));
}

#[test]
fn reader_binding_and_rewrite_refuse_partial_ambiguous_or_mismatched_getter_code() {
    let packed = fixture(true, 0x410600);
    let whole = fixture(false, 0x410600);
    for (template, holes) in [(PACKED, PACKED_CALLS), (WHOLE, WHOLE_CALLS)] {
        let original = if template.len() == PACKED.len() {
            &packed
        } else {
            &whole
        };
        for i in 0..template.len() {
            if holes.iter().any(|at| (*at..*at + 3).contains(&i)) {
                continue;
            }
            let mut broken = original.clone();
            broken[0x100 + i] ^= 0x80;
            assert_eq!(observe(&broken), Err(Error::Unresolved), "{i}");
        }
    }
    let mut mismatch = packed.clone();
    mismatch[0x100 + 55] ^= 2;
    assert_eq!(observe(&mismatch), Err(Error::Unresolved));
    let mut duplicate = packed.clone();
    duplicate[0x200..0x200 + PACKED.len()].copy_from_slice(&packed[0x100..0x100 + PACKED.len()]);
    assert_eq!(observe(&duplicate), Err(Error::Unresolved));
    assert_eq!(rewrite(&whole, &packed, None), Err(Error::SpaceRequired));
    assert_eq!(transplant(&whole, &packed, None), Err(Error::SpaceRequired));
    for space in [0x301..0x345, 0x300..0x320, 0x100..0x200, 0x300..0x900] {
        assert_eq!(
            transplant(&whole, &packed, Some(space.clone())),
            Err(Error::InvalidSpace)
        );
        assert_eq!(
            rewrite(&whole, &packed, Some(space)),
            Err(Error::InvalidSpace)
        );
    }
}

fn native_fixture(hash: &str) -> Vec<u8> {
    let fixtures: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/phase-native-spans.json"
    )))
    .unwrap();
    let fixture = fixtures
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["original_sha256"].as_str() == Some(hash))
        .unwrap();
    let mut image = vec![0xff; fixture["size"].as_u64().unwrap() as usize];
    for span in fixture["spans"].as_array().unwrap() {
        let at = span[0].as_u64().unwrap() as usize;
        let text = span[1].as_str().unwrap();
        for i in 0..text.len() / 2 {
            image[at + i] = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap();
        }
    }
    image
}
/// OEM whole-word reader with its low-byte four-mode caller.
fn oem_whole() -> Vec<u8> {
    native_fixture("84fab289c44ce2de98e96272e607869de4501b45f8f4badc43e492920ce07750")
}
/// OEM packed reader with its low-byte four-mode caller.
fn oem_packed() -> Vec<u8> {
    native_fixture("87e8152f1de1d3be53eb4ad9144c1bb0c45a9be6f78713a0b7487a637f989bf1")
}
/// Model the same bound word-getter contract while executing each reader's
/// actual instruction stream and both of its persistent addresses.
fn shared_getter(normal: &[u8]) -> Program {
    let mut program = program(normal);
    for (insn, _) in program.instructions.values_mut() {
        if insn.mnemonic == "JSR" {
            insn.operands[0] = Operand::Address(Ea::Absolute {
                value: 0x410600,
                bits: 24,
            });
        }
    }
    program
}

#[test]
fn rewrite_preserves_the_effective_interpretation_selected_at_the_bound_caller() {
    let whole = oem_whole();
    let packed = oem_packed();
    // Whole-word reader whose caller selects R0H for modes zero and two.
    let high = transplant_effective(&whole, &packed).unwrap();
    assert_eq!(observe(&whole), Ok(Convention::WholeWord));
    assert_eq!(observe(&packed), Ok(Convention::PackedBytes));
    assert_eq!(observe(&high), Ok(Convention::PackedBytes));
    // Equal effective interpretations need no reader change, whichever
    // program establishes them.
    assert_eq!(rewrite(&packed, &high, None), Ok(packed.clone()));
    assert_eq!(rewrite(&high, &packed, None), Ok(high.clone()));
    // A difference expressed only by the installed caller's byte selection
    // is refused: the installed reader holds no OEM selection instruction to
    // copy, and the library never synthesizes one.
    assert!(rewrite(&whole, &high, None).is_err());
    assert!(rewrite(&high, &whole, None).is_err());
    let unselected = rewrite(&packed, &whole, None).unwrap();
    assert_eq!(observe(&unselected), Ok(Convention::WholeWord));
    // That holds even for a packed-shape target whose own selection was
    // removed: restoring it would need bytes the donor does not supply.
    assert!(rewrite(&unselected, &high, None).is_err());
    // transplant_effective must verify the same effective result: copying a
    // whole-word reader cannot select packed bytes at a low-byte caller.
    assert!(transplant_effective(&unselected, &high).is_err());
    assert_eq!(
        transplant_effective(&unselected, &packed),
        Ok(packed.clone())
    );
}

#[test]
fn growing_rewrite_keeps_the_bound_caller_entry_for_every_word_and_mode() {
    let whole = oem_whole();
    let packed = oem_packed();
    let reservation = 0x1000..0x1050;
    let changed = rewrite(&whole, &packed, Some(reservation.clone())).unwrap();
    assert_eq!(observe(&changed), Ok(Convention::PackedBytes));
    // The same four calls still reach the unmoved reader entry.
    assert_eq!(callers::observe(&changed), callers::observe(&whole));
    let reader = bind(&whole).unwrap().body.spans[0].clone();
    for (at, (a, b)) in whole.iter().zip(&changed).enumerate() {
        assert!(a == b || reader.contains(&at) || reservation.contains(&at));
    }
    let (grown, donor) = (shared_getter(&changed), shared_getter(&packed));
    // Modes zero to three plus the shared out-of-range default.
    for word in 0..=u16::MAX {
        for mode in 0..=4 {
            let words = [word, !word];
            let (actual, reads) = Reader::run(&grown, mode, words);
            let (expected, expected_reads) = Reader::run(&donor, mode, words);
            assert_eq!(actual & 255, expected & 255, "word {word:#x}, mode {mode}");
            assert_eq!(reads, expected_reads);
        }
    }
}

#[test]
fn whole_reader_consumers_select_packed_bytes_without_growth_for_every_word() {
    let target = oem_whole();
    let donor = oem_packed();
    let changed = transplant_effective(&target, &donor).unwrap();
    let caller = callers::observe(&changed).unwrap();
    assert!(caller.high_byte_modes);
    assert_eq!(observe(&changed), Ok(Convention::PackedBytes));
    assert_eq!(
        bind(&changed).unwrap().body.bytes,
        bind(&target).unwrap().body.bytes
    );
    let changes: Vec<_> = target
        .iter()
        .zip(&changed)
        .enumerate()
        .filter_map(|(at, (a, b))| (a != b).then_some(at))
        .collect();
    assert_eq!(changes, [11, 13, 29].map(|i| caller.program.start + i));
    assert_eq!(transplant_effective(&changed, &donor).unwrap(), changed);
    assert_eq!(transplant_effective(&changed, &target).unwrap(), target);
    assert_eq!(transplant_effective(&target, &changed).unwrap(), changed);
    let raw = shared_getter(&target);
    let packed = shared_getter(&donor);
    let selects: Vec<_> = [10, 12, 20, 28]
        .into_iter()
        .map(|i| {
            isa::decode_insn(
                &changed[caller.program.start + i..],
                Target::H8S2000,
                Mode::Advanced,
            )
            .unwrap()
            .insn
        })
        .collect();
    for word in 0..=u16::MAX {
        for mode in 0..4 {
            let words = [word, !word];
            let (full, reads) = Reader::run(&raw, mode, words);
            let (expected, expected_reads) = Reader::run(&packed, mode, words);
            assert_eq!(reads, expected_reads);
            let mut cpu = Reader {
                registers: [0xa55a_5aa5; 8],
                saved: vec![],
                reads: vec![],
                words,
                zero: false,
            };
            cpu.set(Reg::Word(0), full.into());
            let instructions: &[Insn] = match mode {
                0 => &selects[..2],
                1 => &selects[2..3],
                2 => &selects[3..],
                _ => &[],
            };
            for insn in instructions {
                assert_eq!(insn.mnemonic, "MOV");
                let Operand::Register(destination) = insn.operands[1] else {
                    panic!("byte destination")
                };
                cpu.set(destination, cpu.value(insn.operands[0]));
                assert_eq!(cpu.get(destination), u32::from(expected & 255));
            }
            if mode == 3 {
                assert_eq!(full & 255, expected & 255);
            }
        }
    }
    // A partial source-operand edit must never masquerade as either convention.
    for at in changes {
        let mut broken = changed.clone();
        broken[at] = target[at];
        assert!(callers::observe(&broken).is_err());
        assert!(observe(&broken).is_err());
    }
}
