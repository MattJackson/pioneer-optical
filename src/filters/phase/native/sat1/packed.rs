//! Lossless random-access packing of native paired-word tables. Symmetries are
//! proved against every original word; asymmetric signals retain raw words.
use super::*;
const QUARTER: u8 = 1;
const REVERSE: u8 = 2;
const ZERO: u8 = 4;
const RAW: u8 = 8;
const RICE: u8 = 16;
const HEADERS: usize = 40;

/// Five tables, each with two independent scalar descriptors followed by seeds.
/// Every decoded value is the original sixteen-bit word, including all low bits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packed {
    /// Four bytes per channel: flags, phase bias, big-endian seed displacement
    /// relative to the displacement field. All offsets remain image-independent.
    pub bytes: Vec<u8>,
}
#[derive(Clone)]
struct Seed {
    words: Vec<u16>,
    kind: u8,
    at: usize,
}
fn sample(seed: &Seed, phase: u8) -> u16 {
    let phase = usize::from(phase & 63);
    if seed.kind & RAW != 0 {
        return seed.words[phase];
    }
    let mut index = phase & 31;
    if seed.kind & QUARTER != 0 && index > 16 {
        index = 32 - index;
    }
    let word = seed.words[index];
    if phase >= 32 {
        word.wrapping_neg()
    } else {
        word
    }
}
fn agrees(seed: &Seed, words: &[u16; 64], bias: u8, reverse: bool) -> bool {
    words.iter().enumerate().all(|(phase, word)| {
        let phase = if reverse {
            (phase as u8).wrapping_neg()
        } else {
            phase as u8
        };
        sample(seed, phase.wrapping_add(bias)) == *word
    })
}

// Fixed Rice parameter five avoids a per-seed runtime parameter. This transform
// is admitted only after proving every source word's six low bits are zero.
fn rice(words: &[u16]) -> Option<Vec<u8>> {
    if !matches!(words.len(), 17 | 32 | 64) || words.iter().any(|word| word & 63 != 0) {
        return None;
    }
    let mut output = ((words[0] as i16) >> 6).to_be_bytes().to_vec();
    let mut bits = 0usize;
    let mut emit = |bit: bool| {
        if bits % 8 == 0 {
            output.push(0);
        }
        let last = output.len() - 1;
        if bit {
            output[last] |= 1 << (7 - bits % 8);
        }
        bits += 1;
    };
    for pair in words.windows(2) {
        let difference = i32::from((pair[1] as i16) >> 6) - i32::from((pair[0] as i16) >> 6);
        let encoded = if difference < 0 {
            (-difference * 2 - 1) as u32
        } else {
            (difference * 2) as u32
        };
        for _ in 0..encoded >> 5 {
            emit(true);
        }
        emit(false);
        for bit in (0..5).rev() {
            emit(encoded & (1 << bit) != 0);
        }
    }
    (output.len() < words.len() * 2).then_some(output)
}

/// Pack exact native tables. No storage or ownership claim is made: callers must
/// compare the resulting length plus executable code with positively owned space.
/// Raw fallbacks ensure an asymmetric donor is never approximated or truncated.
pub fn pack(tables: &[[u8; 256]; 5]) -> Result<Packed, Error> {
    let mut bytes = alloc::vec![0; HEADERS];
    let mut seeds: Vec<Seed> = Vec::new();
    for (table, source) in tables.iter().enumerate() {
        for channel in 0..2 {
            let mut words = [0u16; 64];
            for (phase, word) in words.iter_mut().enumerate() {
                let at = phase * 4 + channel * 2;
                *word = u16::from_be_bytes([source[at], source[at + 1]]);
            }
            let descriptor = (table * 2 + channel) * 4;
            if words.iter().all(|word| *word == 0) {
                bytes[descriptor] = ZERO;
                continue;
            }
            let mut selected = None;
            'existing: for (index, seed) in seeds.iter().enumerate() {
                for reverse in [false, true] {
                    for bias in 0..64 {
                        if agrees(seed, &words, bias, reverse) {
                            selected = Some((index, bias, reverse));
                            break 'existing;
                        }
                    }
                }
            }
            if selected.is_none() {
                let mut quarter = None;
                for bias in 0..64u8 {
                    let seed = Seed {
                        words: (0..17)
                            .map(|i| words[(i + 64 - usize::from(bias)) & 63])
                            .collect(),
                        kind: QUARTER,
                        at: bytes.len(),
                    };
                    if agrees(&seed, &words, bias, false) {
                        quarter = Some((seed, bias));
                        break;
                    }
                }
                let (mut seed, bias) = quarter.unwrap_or_else(|| {
                    let half = Seed {
                        words: words[..32].to_vec(),
                        kind: 0,
                        at: bytes.len(),
                    };
                    if agrees(&half, &words, 0, false) {
                        (half, 0)
                    } else {
                        (
                            Seed {
                                words: words.to_vec(),
                                kind: RAW,
                                at: bytes.len(),
                            },
                            0,
                        )
                    }
                });
                if let Some(stream) = rice(&seed.words) {
                    seed.kind |= RICE;
                    bytes.extend_from_slice(&stream);
                    if bytes.len() & 1 != 0 {
                        bytes.push(0);
                    }
                } else {
                    for word in &seed.words {
                        bytes.extend_from_slice(&word.to_be_bytes());
                    }
                }
                selected = Some((seeds.len(), bias, false));
                seeds.push(seed);
            }
            let (index, bias, reverse) = selected.ok_or(Error::Verification)?;
            let seed = &seeds[index];
            let displacement =
                u16::try_from(seed.at - (descriptor + 2)).map_err(|_| Error::ResourceMismatch)?;
            bytes[descriptor] = seed.kind | if reverse { REVERSE } else { 0 };
            bytes[descriptor + 1] = bias;
            bytes[descriptor + 2..descriptor + 4].copy_from_slice(&displacement.to_be_bytes());
        }
    }
    let packed = Packed { bytes };
    // A successful operation has an explicit exact inverse for all 640 words.
    for (table, source) in tables.iter().enumerate() {
        for phase in 0..64 {
            for channel in 0..2 {
                let at = phase * 4 + channel * 2;
                if packed.lookup(table, channel, phase as u8)?
                    != u16::from_be_bytes([source[at], source[at + 1]])
                {
                    return Err(Error::Verification);
                }
            }
        }
    }
    Ok(packed)
}
impl Packed {
    /// Emit only the decoder paths used by these descriptors. The ABI matches
    /// [`lookup_leaf`]; encoded data remains independently relocatable.
    pub fn lookup_leaf(&self) -> Result<Vec<u8>, Error> {
        let headers = self.bytes.get(..HEADERS).ok_or(Error::ResourceMismatch)?;
        let mut plain = false;
        let mut rice = false;
        for header in headers.chunks_exact(4) {
            if header[0] & ZERO != 0 {
                continue;
            }
            if header[0] & RICE != 0 {
                rice = true;
            } else {
                plain = true;
            }
        }
        emit_lookup(plain || !rice, rice)
    }
    /// Decode one exact native word. Phase has the native six-bit wrap.
    pub fn lookup(&self, table: usize, channel: usize, phase: u8) -> Result<u16, Error> {
        if table >= 5 || channel >= 2 {
            return Err(Error::ResourceMismatch);
        }
        let descriptor = (table * 2 + channel) * 4;
        let header = self
            .bytes
            .get(descriptor..descriptor + 4)
            .ok_or(Error::ResourceMismatch)?;
        let flags = header[0];
        if flags & !31 != 0 || (flags & (QUARTER | RAW)).count_ones() > 1 {
            return Err(Error::ResourceMismatch);
        }
        if flags & ZERO != 0 {
            return Ok(0);
        }
        let phase = if flags & REVERSE != 0 {
            phase.wrapping_neg()
        } else {
            phase
        };
        let phase = phase.wrapping_add(header[1]) & 63;
        let start = descriptor + 2 + usize::from(u16::from_be_bytes([header[2], header[3]]));
        let mut index = if flags & RAW != 0 { phase } else { phase & 31 };
        if flags & QUARTER != 0 && index > 16 {
            index = 32 - index;
        }
        if flags & RICE != 0 {
            let initial = self
                .bytes
                .get(start..start + 2)
                .ok_or(Error::ResourceMismatch)?;
            let mut value = i16::from_be_bytes([initial[0], initial[1]]);
            let mut bit = 0usize;
            let mut read = || -> Result<u16, Error> {
                let byte = *self
                    .bytes
                    .get(start + 2 + bit / 8)
                    .ok_or(Error::ResourceMismatch)?;
                let value = u16::from((byte >> (7 - bit % 8)) & 1);
                bit += 1;
                Ok(value)
            };
            for _ in 0..index {
                let mut code = 0u16;
                while read()? != 0 {
                    code = code
                        .checked_add(1)
                        .filter(|q| *q < 64)
                        .ok_or(Error::ResourceMismatch)?;
                }
                for _ in 0..5 {
                    code = (code << 1) | read()?;
                }
                let delta = if code & 1 == 0 {
                    (code >> 1) as i16
                } else {
                    !((code >> 1) as i16)
                };
                value = value
                    .checked_add(delta)
                    .filter(|v| (-512..512).contains(v))
                    .ok_or(Error::ResourceMismatch)?;
            }
            let word = (value as u16) << 6;
            return Ok(if flags & RAW == 0 && phase >= 32 {
                word.wrapping_neg()
            } else {
                word
            });
        }
        let at = descriptor
            + 2
            + usize::from(u16::from_be_bytes([header[2], header[3]]))
            + usize::from(index) * 2;
        let word = self.bytes.get(at..at + 2).ok_or(Error::ResourceMismatch)?;
        let word = u16::from_be_bytes([word[0], word[1]]);
        Ok(if flags & RAW == 0 && phase >= 32 {
            word.wrapping_neg()
        } else {
            word
        })
    }
}

/// Emit a position-independent H8 scalar lookup leaf. Input: R0L phase and ER1
/// descriptor address. Output: R0 original word. Clobbers ER0..ER3 and CCR;
/// preserves ER4..ER7. Rice decoding uses one nested BSR return slot on the
/// existing stack; no other RAM, MMIO or persistent storage is written. An
/// independent random-access lookup decodes at most63 native deltas.
pub fn lookup_leaf() -> Result<Vec<u8>, Error> {
    emit_lookup(true, true)
}
fn emit_lookup(plain: bool, rice: bool) -> Result<Vec<u8>, Error> {
    let mut asm =
        h8_asm::Asm::new(Target::H8S2000, Mode::Advanced).map_err(|_| Error::Unresolved)?;
    macro_rules! ins { ($($b:expr),+) => { asm.instruction(&[$($b),+]).map_err(|_| Error::Unresolved)? }; }
    macro_rules! branch {
        ($cc:expr,$label:expr) => {
            asm.branch($cc, $label).map_err(|_| Error::Unresolved)?
        };
    }
    macro_rules! label {
        ($label:expr) => {
            asm.label($label).map_err(|_| Error::Unresolved)?
        };
    }
    ins!(0x6c, 0x1a); // MOV.B @ER1+,R2L (flags)
    ins!(0x6c, 0x1b); // MOV.B @ER1+,R3L (bias)
    ins!(0x73, 0x2a);
    branch!(6, "zero");
    ins!(0x73, 0x1a);
    branch!(7, "forward");
    ins!(0x17, 0x88); // NEG.B R0L
    label!("forward");
    ins!(0x08, 0xb8);
    ins!(0xe8, 0x3f);
    ins!(0x0c, 0x82);
    ins!(0x69, 0x13);
    ins!(0x17, 0x73);
    ins!(0x0a, 0xb1);
    ins!(0x73, 0x3a);
    branch!(6, "lookup"); // raw keeps all six index bits
    ins!(0xe8, 0x1f);
    ins!(0x73, 0x0a);
    branch!(7, "lookup");
    ins!(0xa8, 0x10);
    branch!(3, "lookup");
    ins!(0x17, 0x88);
    ins!(0x88, 0x20);
    label!("lookup");
    ins!(0x17, 0x50);
    if rice {
        if plain {
            ins!(0x73, 0x4a);
            branch!(6, "rice");
        } else {
            branch!(0, "rice");
        }
    }
    if plain {
        ins!(0x17, 0x70);
        ins!(0x10, 0x30);
        ins!(0x0a, 0x81);
        ins!(0x69, 0x10);
    }
    label!("word");
    ins!(0x73, 0x3a);
    branch!(6, "done");
    ins!(0x73, 0x52);
    branch!(7, "done");
    ins!(0x17, 0x90);
    label!("done");
    ins!(0x54, 0x70);
    label!("zero");
    ins!(0x19, 0x00);
    ins!(0x54, 0x70);
    if rice {
        label!("rice");
        ins!(0x0d, 0x2a); // preserve descriptor flags and phase in E2
        ins!(0x0d, 0x0b); // phase count in E3, independent of bit buffer R3
        ins!(0x6d, 0x12); // MOV.W @ER1+,R2 initial signed ten-bit coefficient
        ins!(0x18, 0x33); // empty bit buffer
        ins!(0x0d, 0xbb);
        branch!(7, "rice_done");
        label!("rice_delta");
        ins!(0x19, 0x00);
        label!("unary");
        asm.call("bit");
        branch!(4, "remainder");
        ins!(0x0b, 0x50);
        branch!(0, "unary");
        label!("remainder");
        ins!(0x79, 0x08, 0x00, 0x05);
        label!("bits");
        asm.call("bit");
        ins!(0x12, 0x10);
        ins!(0x1b, 0x58);
        branch!(6, "bits");
        ins!(0x73, 0x08);
        branch!(7, "positive");
        ins!(0x11, 0x10);
        ins!(0x17, 0x10);
        branch!(0, "add_delta");
        label!("positive");
        ins!(0x11, 0x10);
        label!("add_delta");
        ins!(0x09, 0x02);
        ins!(0x1b, 0x5b);
        branch!(6, "rice_delta");
        label!("rice_done");
        ins!(0x0d, 0x20);
        ins!(0x10, 0x50);
        ins!(0x10, 0x50);
        ins!(0x10, 0x50);
        ins!(0x0d, 0xa2);
        branch!(0, "word");
        label!("bit");
        ins!(0x0c, 0x33);
        branch!(6, "have_bit");
        ins!(0x6c, 0x1b);
        ins!(0xf3, 0x08);
        label!("have_bit");
        ins!(0x1a, 0x03);
        ins!(0x10, 0x0b);
        ins!(0x54, 0x70);
    }
    asm.finish(0).map_err(|_| Error::Unresolved)
}

#[cfg(all(test, feature = "envelope"))]
mod tests {
    use super::*;
    fn coords(register: Reg) -> (usize, u32, u32) {
        match register {
            Reg::Byte(n) => ((n % 8) as usize, if n < 8 { 8 } else { 0 }, 255),
            Reg::Word(n) => ((n % 8) as usize, if n < 8 { 0 } else { 16 }, 65535),
            Reg::Long(n) => (n as usize, 0, u32::MAX),
            _ => panic!("register {register:?}"),
        }
    }
    fn get(regs: &[u32; 8], register: Reg) -> u32 {
        let (index, shift, mask) = coords(register);
        (regs[index] >> shift) & mask
    }
    fn set(regs: &mut [u32; 8], register: Reg, value: u32) {
        let (index, shift, mask) = coords(register);
        regs[index] = (regs[index] & !(mask << shift)) | ((value & mask) << shift);
    }
    // Instruction-level execution, independent of the compression formulas.
    fn execute(code: &[u8], packed: &[u8], descriptor: usize, phase: u8) -> u16 {
        let mut regs = [0x12345678; 8];
        regs[0] = 0x87654300 | u32::from(phase);
        regs[1] = descriptor as u32;
        let preserved = regs[4..].to_vec();
        let (mut pc, mut z, mut c) = (0usize, false, false);
        let mut returns = Vec::new();
        for _ in 0..20000 {
            let d = decode_insn(&code[pc..], Target::H8S2000, Mode::Advanced).unwrap();
            pc += d.len;
            let i = d.insn;
            let value = |op| match op {
                O::Register(r) => get(&regs, r),
                O::Immediate { value, .. } => value,
                _ => panic!("value {op:?}"),
            };
            match i.mnemonic {
                "RTS" => {
                    if let Some(return_pc) = returns.pop() {
                        pc = return_pc;
                        continue;
                    }
                    assert_eq!(&regs[4..], preserved);
                    return regs[0] as u16;
                }
                "BSR" => {
                    let O::Address(Ea::PcRelative { value, .. }) = i.operands[0] else {
                        panic!()
                    };
                    returns.push(pc);
                    assert!(returns.len() <= 1);
                    pc = pc.checked_add_signed(value as isize).unwrap();
                }
                "BEQ" | "BNE" | "BLS" | "BCC" | "BRA" => {
                    let take = match i.mnemonic {
                        "BEQ" => z,
                        "BNE" => !z,
                        "BCC" => !c,
                        "BRA" => true,
                        _ => c || z,
                    };
                    if take {
                        let O::Address(Ea::PcRelative { value, .. }) = i.operands[0] else {
                            panic!()
                        };
                        pc = pc.checked_add_signed(value as isize).unwrap();
                    }
                }
                "BTST" => {
                    z = value(i.operands[1]) & (1 << value(i.operands[0])) == 0;
                }
                "CMP" => {
                    let a = value(i.operands[1]);
                    let b = value(i.operands[0]);
                    z = a == b;
                    c = a < b;
                }
                "MOV" => {
                    let O::Register(to) = i.operands[1] else {
                        panic!("no writes allowed")
                    };
                    let v = match i.operands[0] {
                        O::Address(Ea::Indirect(r)) | O::Address(Ea::PostIncrement(r)) => {
                            let address = get(&regs, r) as usize;
                            let width = match i.size.unwrap() {
                                Size::Byte => 1,
                                Size::Word => 2,
                                Size::Long => 4,
                            };
                            let v = integer(&packed[address..address + width]);
                            if matches!(i.operands[0], O::Address(Ea::PostIncrement(_))) {
                                set(&mut regs, r, (address + width) as u32);
                            }
                            v
                        }
                        op => value(op),
                    };
                    set(&mut regs, to, v);
                    z = get(&regs, to) == 0;
                }
                "ADD" | "SUB" | "AND" => {
                    let O::Register(to) = i.operands[1] else {
                        panic!()
                    };
                    let a = value(i.operands[1]);
                    let b = value(i.operands[0]);
                    let v = match i.mnemonic {
                        "ADD" => a.wrapping_add(b),
                        "SUB" => a.wrapping_sub(b),
                        _ => a & b,
                    };
                    set(&mut regs, to, v);
                    z = get(&regs, to) == 0;
                }
                "NEG" => {
                    let O::Register(to) = i.operands[0] else {
                        panic!()
                    };
                    let v = get(&regs, to).wrapping_neg();
                    set(&mut regs, to, v);
                    z = get(&regs, to) == 0;
                }
                "EXTU" => {
                    let O::Register(to) = i.operands[0] else {
                        panic!()
                    };
                    let mask = if i.size == Some(Size::Word) {
                        255
                    } else {
                        65535
                    };
                    let v = get(&regs, to) & mask;
                    set(&mut regs, to, v);
                    z = v == 0;
                }
                "SHLL" | "SHLR" | "ROTXL" => {
                    let O::Register(to) = i.operands[1] else {
                        panic!()
                    };
                    let mut v = get(&regs, to);
                    let width = coords(to).2.count_ones();
                    for _ in 0..value(i.operands[0]) {
                        if i.mnemonic == "SHLR" {
                            c = v & 1 != 0;
                            v >>= 1;
                        } else {
                            let previous = c;
                            c = v & (1 << (width - 1)) != 0;
                            v <<= 1;
                            if i.mnemonic == "ROTXL" {
                                v |= u32::from(previous);
                            }
                        }
                    }
                    set(&mut regs, to, v);
                    z = get(&regs, to) == 0;
                }
                "INC" | "DEC" => {
                    let (to, count) = match (i.operands[0], i.operands[1]) {
                        (O::Register(to), O::None) => (to, 1),
                        (O::Immediate { value, .. }, O::Register(to)) => (to, value),
                        _ => panic!("{i:?}"),
                    };
                    let old = get(&regs, to);
                    let v = if i.mnemonic == "INC" {
                        old.wrapping_add(count)
                    } else {
                        old.wrapping_sub(count)
                    };
                    set(&mut regs, to, v);
                    z = get(&regs, to) == 0;
                }
                "NOT" => {
                    let O::Register(to) = i.operands[0] else {
                        panic!()
                    };
                    let v = !get(&regs, to);
                    set(&mut regs, to, v);
                    z = get(&regs, to) == 0;
                }
                mnemonic => panic!("unsupported {mnemonic}: {i:?}"),
            }
        }
        panic!("lookup did not return")
    }
    #[test]
    fn sat1_packed_native_words_and_h8_leaf_are_exact_for_both_conventions() {
        let fixtures: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/phase-sat1-native.json"
        )))
        .unwrap();
        for fixture in fixtures.as_array().unwrap() {
            let tables: Vec<[u8; 256]> = fixture["spans"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|span| {
                    let h = span[1].as_str().unwrap();
                    if h.len() != 512 {
                        return None;
                    }
                    let mut table = [0; 256];
                    for (i, b) in table.iter_mut().enumerate() {
                        *b = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap();
                    }
                    Some(table)
                })
                .collect();
            let tables: [_; 5] = tables.try_into().unwrap();
            let packed = pack(&tables).unwrap();
            let code = packed.lookup_leaf().unwrap();
            println!(
                "{}: data {} + lookup {}",
                fixture["normal"],
                packed.bytes.len(),
                code.len()
            );
            for (table, source) in tables.iter().enumerate() {
                for channel in 0..2 {
                    for phase in 0..=255u8 {
                        let at = usize::from(phase & 63) * 4 + channel * 2;
                        let expected = u16::from_be_bytes([source[at], source[at + 1]]);
                        assert_eq!(packed.lookup(table, channel, phase).unwrap(), expected);
                        assert_eq!(
                            execute(&code, &packed.bytes, (table * 2 + channel) * 4, phase),
                            expected
                        );
                    }
                }
            }
        }
    }
    #[test]
    fn sat1_packed_preserves_all_low_bits_and_asymmetric_signs() {
        let mut tables = [[0u8; 256]; 5];
        for (table, t) in tables.iter_mut().enumerate() {
            for phase in 0..64 {
                for axis in 0..2 {
                    let value = (phase as u16)
                        .wrapping_mul(997)
                        .wrapping_add((table * 37 + axis * 91) as u16);
                    let at = phase * 4 + axis * 2;
                    t[at..at + 2].copy_from_slice(&value.to_be_bytes());
                }
            }
        }
        for phase in 0..64usize {
            let folded = phase & 31;
            let magnitude = if folded > 16 { 32 - folded } else { folded };
            let word = (magnitude as u16) << 6;
            let word = if phase >= 32 {
                word.wrapping_neg()
            } else {
                word
            };
            tables[0][phase * 4..phase * 4 + 2].copy_from_slice(&word.to_be_bytes());
        }
        let packed = pack(&tables).unwrap();
        let code = packed.lookup_leaf().unwrap();
        for (table, t) in tables.iter().enumerate() {
            for phase in 0..64 {
                for axis in 0..2 {
                    let at = phase * 4 + axis * 2;
                    assert_eq!(
                        execute(&code, &packed.bytes, (table * 2 + axis) * 4, phase as u8),
                        u16::from_be_bytes([t[at], t[at + 1]])
                    );
                }
            }
        }
    }
}
