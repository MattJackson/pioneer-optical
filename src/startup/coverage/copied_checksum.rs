//! Startup checksum code relocated by the native C initializer into low RAM.
//! Recognizes the complete stored routine and the native copy argument graph;
//! does not scan low addresses as ROM or treat them as unexplained predicates.
//!
//! The external ROM body at 0x1058dc is not present in these images. Its memcpy
//! ABI (ER0 source, ER1 destination, ER2 length; ER3/ER4 preserved) is an explicit
//! platform contract inferred from the complete C-startup copy graph. This
//! contract applies only to the bound wrapper and adapter below. Recognition
//! does not claim that the ROM instructions were observed or executed.
use crate::image::layout::{Observation, Unresolved};
use alloc::vec::Vec;
use core::ops::Range;
use h8_asm::{
    isa::{decode_insn, Operand, Reg},
    Mode, Target,
};
const BASE: u32 = 0x410000;

/// Binding of a whole Kernel+Normal additive checksum routine copied to RAM.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checksum {
    /// Actual JSR destination used by the startup checksum predicate.
    pub entry: u32,
    /// Stored complete checksum implementation in decoded Normal.
    pub body: Range<usize>,
    /// Source block copied into RAM, containing the checksum body.
    pub source: Range<usize>,
    /// RAM destination corresponding to the start of source.
    pub destination: u32,
    /// Native C-startup argument loads and indirect copy call.
    pub copy: Range<usize>,
    /// Complete copy wrapper and call adapter bodies.
    pub helpers: [Range<usize>; 2],
    /// Complete native clear wrapper and implementation used by C startup.
    pub clear_helpers: [Range<usize>; 2],
    /// Complete C initializer, including every copy/clear argument and call.
    pub initializer: Range<usize>,
    /// Fixed platform memcpy entry explicitly retained as an external contract.
    pub memcpy_service: u32,
}
const BODY: &[u8] = &[
    1, 0, 0x6d, 0xf3, 0x1a, 0xa2, 0x7a, 1, 0, 0x40, 0, 0, 1, 0, 0x6b, 0x23, 0, 0x41, 0, 0x14, 0x7a,
    0x13, 0, 0x41, 0, 0, 0x40, 6, 1, 0, 0x6d, 0x10, 0x0a, 0x82, 0x1f, 0xb1, 0x46, 0xf6, 0x0f, 0xa0,
    1, 0, 0x6d, 0x73, 0x54, 0x70,
];
const COPY: &[u8] = &[
    1, 0, 0x6d, 0xf4, 0x0f, 0xa4, 0x1a, 0x81, 0x0f, 0x92, 0x0f, 0x81, 0x0f, 0xc0, 0x5e, 0, 0, 0, 1,
    0, 0x6d, 0x74, 0x54, 0x70,
];
const ADAPTER: &[u8] = &[
    0x1f, 0x81, 0x47, 0x18, 0x0f, 0xa2, 0x47, 0x14, 1, 0, 0x6d, 0xf2, 0x0f, 0x82, 0x0f, 0x90, 0x0f,
    0xa1, 1, 0, 0x6d, 0x72, 0x5e, 0, 0, 0, 0x0f, 0x90, 0x54, 0x70,
];
const MEMCPY: u32 = 0x1058dc;
/// Offsets of the copy and clear helper-pointer `MOV.L` immediates in every
/// `boot_shapes::C_STARTUP` shape (holes in both shapes).
const COPY_HELPER_OPERAND: usize = 34;
const CLEAR_HELPER_OPERAND: usize = 56;
const CLEAR: &[u8] = &[
    0x6d, 0xf4, 0x0d, 0x24, 0x0f, 0x92, 0x1a, 0x82, 0x0d, 0x41, 0x5e, 0, 0, 0, 0x6d, 0x74, 0x54,
    0x70,
];
/// The native fill leaf the clear wrapper calls: the same routine cache
/// writers bind, so one recognition contract covers both.
const FILL: &[u8] = super::cache_writers::MEMSET;

#[cfg(all(test, feature = "envelope"))]
pub(super) fn install_fixture(normal: &mut [u8]) -> usize {
    for (at, body) in [
        (0x2a00, BODY),
        (0x2b00, COPY),
        (0x2b40, ADAPTER),
        (0x2b80, CLEAR),
        (0x2bc0, FILL),
    ] {
        normal[at..at + body.len()].copy_from_slice(body);
    }
    for (at, target) in [(0x2b0f, 0x412b40u32), (0x2b57, MEMCPY), (0x2b8b, 0x412bc0)] {
        normal[at..at + 3].copy_from_slice(&target.to_be_bytes()[1..]);
    }
    BODY.len()
}

fn addr(b: &[u8]) -> u32 {
    u32::from_be_bytes([0, b[0], b[1], b[2]])
}
fn matches(b: &[u8], shape: &[u8], hole: Range<usize>) -> bool {
    b.len() == shape.len()
        && b.iter()
            .zip(shape)
            .enumerate()
            .all(|(i, (a, b))| hole.contains(&i) || a == b)
}
/// A single C-startup memcpy whose RAM destination contains the requested
/// entry, with its complete bound copy/clear helper chain and initializer.
/// Body-independent: callers add their own stored-content requirements.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Relocation {
    /// Source block copied into RAM, in decoded Normal.
    pub source: Range<usize>,
    /// RAM destination corresponding to the start of `source`.
    pub destination: u32,
    /// Native C-startup argument loads and indirect copy call.
    pub copy: Range<usize>,
    /// Complete copy wrapper and call adapter bodies.
    pub helpers: [Range<usize>; 2],
    /// Complete native clear wrapper and implementation used by C startup.
    pub clear_helpers: [Range<usize>; 2],
    /// Complete C initializer, including every copy/clear argument and call.
    pub initializer: Range<usize>,
    /// Fixed platform memcpy entry explicitly retained as an external contract.
    pub memcpy_service: u32,
    /// Every RAM range the bound C initializer copies or clears: the
    /// firmware's own initialized and zeroed data.
    pub sections: Vec<Range<u32>>,
}

/// The positively bound C initializer and its two helper entries.
struct Initializer {
    boot: Range<usize>,
    copy_helper: u32,
    clear_helper: u32,
    clear: Range<usize>,
    fill: Range<usize>,
}

fn stored(normal: &[u8], regions: &crate::image::Regions<'_>, span: &Range<usize>) -> bool {
    regions.stored.iter().any(|r| {
        let at = r.as_ptr() as usize - normal.as_ptr() as usize;
        span.start >= at && span.end <= at + r.len()
    })
}

fn initializer(normal: &[u8], regions: &crate::image::Regions<'_>) -> Option<Initializer> {
    let Observation::Known(boot) = super::boot::c_startup_in(normal, regions) else {
        return None;
    };
    // Both complete C-startup shapes load the two saved helper registers at
    // these decoded MOV.L instructions. Their register numbers may swap.
    let operand = |at: usize| {
        u32::from_be_bytes(
            normal[boot.start + at..boot.start + at + 4]
                .try_into()
                .unwrap(),
        )
    };
    let copy_helper = operand(COPY_HELPER_OPERAND);
    let clear_helper = operand(CLEAR_HELPER_OPERAND);
    let clear_start = clear_helper.checked_sub(BASE)? as usize;
    let clear = clear_start..clear_start + CLEAR.len();
    if !stored(normal, regions, &clear) || !matches(&normal[clear.clone()], CLEAR, 11..14) {
        return None;
    }
    let fill_start = addr(&normal[clear_start + 11..clear_start + 14]).checked_sub(BASE)? as usize;
    let fill = fill_start..fill_start + FILL.len();
    if !stored(normal, regions, &fill) || normal.get(fill.clone()) != Some(FILL) {
        return None;
    }
    Some(Initializer {
        boot: boot.start..boot.end,
        copy_helper,
        clear_helper,
        clear,
        fill,
    })
}

/// One C-startup helper call with its tracked `(ER0, ER1, ER2)` arguments.
struct Call {
    helper: u32,
    begin: u32,
    end: u32,
    value: u32,
}

/// Track one initializer instruction. `Err` when a helper call's arguments
/// are not all tracked immediates or describe an inverted range.
fn step(d: &h8_asm::isa::Decoded, registers: &mut [Option<u32>; 8]) -> Result<Option<Call>, ()> {
    match (d.insn.mnemonic, d.insn.operands[0], d.insn.operands[1]) {
        ("MOV", Operand::Immediate { value, bits: 32 }, Operand::Register(Reg::Long(reg))) => {
            registers[reg as usize] = Some(value)
        }
        ("JSR", Operand::Address(h8_asm::isa::Ea::Indirect(Reg::Long(reg))), _) => {
            let (Some(begin), Some(end), Some(value), Some(helper)) = (
                registers[0],
                registers[1],
                registers[2],
                registers[reg as usize],
            ) else {
                return Err(());
            };
            if end < begin {
                return Err(());
            }
            // Bound C startup saves ER3/ER4 for its helper pointers; they
            // are revalidated against complete save/restore helper bodies.
            registers[..3].fill(None);
            return Ok(Some(Call {
                helper,
                begin,
                end,
                value,
            }));
        }
        ("SUB", Operand::Register(Reg::Word(2)), Operand::Register(Reg::Word(2))) => {
            // The native clear wrapper consumes only R2, not ER2.
            registers[2] = Some(0);
        }
        ("JSR" | "BSR", _, _) => registers[..3].fill(None),
        _ => {
            // The complete C-startup shape leaves ER3/ER4 untouched except
            // for the explicit immediate loads and saved-register epilogue.
            // Any other destination destroys a tracked argument value.
            if let Operand::Register(Reg::Long(reg)) = d.insn.operands[1] {
                registers[reg as usize] = None;
            }
        }
    }
    Ok(None)
}

/// Resolve the single validated C-startup copy that relocates `[entry, entry +
/// extent)` into low RAM, through the positively bound C initializer and the
/// complete native copy helper chain. Any other write to the copied RAM block
/// refuses (`Conflicting`); an unrecognized initializer or helper refuses
/// (`Unresolved`). The returned source bytes are a verbatim copy of what runs
/// at the RAM destination, so a caller may analyze the whole relocated block.
pub(crate) fn relocated(normal: &[u8], entry: u32, extent: u32) -> Observation<Relocation> {
    let unknown = || Observation::Unresolved(Unresolved::ReaderNotRecognized);
    let Some(regions) = crate::image::regions(normal) else {
        return unknown();
    };
    let Some(Initializer {
        boot,
        copy_helper,
        clear_helper,
        clear,
        fill,
    }) = initializer(normal, &regions)
    else {
        return unknown();
    };
    let stored = |span: &Range<usize>| stored(normal, &regions, span);
    let Some(last) = entry.checked_add(extent) else {
        return unknown();
    };
    let overlaps = |begin: u32, end: u32| begin < last && entry < end;
    let mut registers = [None; 8];
    // Offset of the instruction that set each register's tracked value.
    let mut loaded = [0usize; 8];
    let mut copies = Vec::new();
    // Every RAM range the initializer writes, by call position.
    let mut writes = Vec::new();
    let mut at = boot.start;
    while at < boot.end {
        let Ok(d) = decode_insn(&normal[at..boot.end], Target::H8S2000, Mode::Advanced) else {
            return unknown();
        };
        // Mirrors the two ways `step` sets a tracked argument register.
        match (d.insn.mnemonic, d.insn.operands[0], d.insn.operands[1]) {
            ("MOV", Operand::Immediate { bits: 32, .. }, Operand::Register(Reg::Long(reg))) => {
                loaded[reg as usize] = at
            }
            ("SUB", Operand::Register(Reg::Word(2)), Operand::Register(Reg::Word(2))) => {
                loaded[2] = at
            }
            _ => {}
        }
        let Ok(call) = step(&d, &mut registers) else {
            return unknown();
        };
        if let Some(Call {
            helper,
            begin,
            end,
            value,
        }) = call
        {
            if helper == copy_helper {
                let Some(write_end) = value.checked_add(end - begin) else {
                    return unknown();
                };
                writes.push((at, value..write_end));
                if overlaps(value, write_end) {
                    // Partial writes and repeated copies cannot establish one
                    // unambiguous whole routine at the called RAM entry.
                    if value > entry || write_end < last {
                        return Observation::Conflicting;
                    }
                    // From the first of the three argument loads; the first
                    // copy also loads its saved helper pointer in between.
                    let first = loaded[..3].iter().copied().min().unwrap_or(at);
                    copies.push((at, begin, end, value, helper, first..at + d.len));
                }
            } else if helper == clear_helper {
                if value != 0 || overlaps(begin, end) {
                    return Observation::Conflicting;
                }
                writes.push((at, begin..end));
            } else {
                return unknown();
            }
        }
        at += d.len;
    }
    if copies.len() != 1 {
        return if copies.len() > 1 {
            Observation::Conflicting
        } else {
            unknown()
        };
    }
    let (call_at, begin, end, destination, helper, copy) = copies.remove(0);
    // The caller analyzes the whole copied block, not only the requested
    // entry, so any other write into any part of it refuses.
    let block = destination..destination + (end - begin);
    if writes.iter().any(|(call, w)| {
        *call != call_at && !w.is_empty() && w.start < block.end && block.start < w.end
    }) {
        return Observation::Conflicting;
    }
    let Some(source_start) = begin.checked_sub(BASE).map(|v| v as usize) else {
        return unknown();
    };
    let Some(source_end) = end.checked_sub(BASE).map(|v| v as usize) else {
        return unknown();
    };
    let source = source_start..source_end;
    let Some(helper_start) = helper.checked_sub(BASE).map(|v| v as usize) else {
        return unknown();
    };
    let wrapper = helper_start..helper_start + COPY.len();
    if !stored(&source) || !stored(&wrapper) || !matches(&normal[wrapper.clone()], COPY, 15..18) {
        return unknown();
    }
    let Some(adapter_start) = addr(&normal[helper_start + 15..helper_start + 18])
        .checked_sub(BASE)
        .map(|v| v as usize)
    else {
        return unknown();
    };
    let adapter = adapter_start..adapter_start + ADAPTER.len();
    if !stored(&adapter) || !matches(&normal[adapter.clone()], ADAPTER, 23..26) {
        return unknown();
    }
    let memcpy_service = addr(&normal[adapter_start + 23..adapter_start + 26]);
    if memcpy_service != MEMCPY {
        return unknown();
    }
    Observation::Known(Relocation {
        source,
        destination,
        copy,
        helpers: [wrapper, adapter],
        clear_helpers: [clear, fill],
        initializer: boot.start..boot.end,
        memcpy_service,
        sections: writes.into_iter().map(|(_, range)| range).collect(),
    })
}

/// Resolve a low-RAM entry only through the positively bound C initializer and
/// complete native copy helper chain. Multiple writes to the selected RAM range
/// refuse; missing source bytes or altered checksum instructions refuse.
pub fn discover(normal: &[u8], entry: u32) -> Observation<Checksum> {
    let unknown = || Observation::Unresolved(Unresolved::ReaderNotRecognized);
    let relocation = match relocated(normal, entry, BODY.len() as u32) {
        Observation::Known(relocation) => relocation,
        Observation::Unresolved(reason) => return Observation::Unresolved(reason),
        Observation::Conflicting => return Observation::Conflicting,
    };
    let body_start = relocation.source.start + (entry - relocation.destination) as usize;
    let body = body_start..body_start + BODY.len();
    if normal.get(body.clone()) != Some(BODY) {
        return unknown();
    }
    Observation::Known(Checksum {
        entry,
        body,
        source: relocation.source,
        destination: relocation.destination,
        copy: relocation.copy,
        helpers: relocation.helpers,
        clear_helpers: relocation.clear_helpers,
        initializer: relocation.initializer,
        memcpy_service: relocation.memcpy_service,
    })
}

#[cfg(all(test, feature = "envelope"))]
mod tests {
    use super::*;

    fn word(normal: &mut [u8], at: usize, value: u32) {
        normal[at..at + 4].copy_from_slice(&value.to_be_bytes());
    }

    /// Bound C startup (shape 0) at 0x2800 whose third call copies the
    /// checksum body to RAM 0x600; `writes` overrides further operands.
    fn startup(writes: &[(usize, u32)]) -> Vec<u8> {
        let mut normal = alloc::vec![0u8; 0x3000];
        let body_len = install_fixture(&mut normal);
        let shape = &super::super::boot_shapes::C_STARTUP[0];
        normal[0x2800..0x2800 + shape.bytes.len()].copy_from_slice(shape.bytes);
        for &(at, len) in shape.holes {
            let value: u32 = if len == 3 { 0x412f00 } else { 0x800 };
            normal[0x2800 + at..0x2800 + at + len].copy_from_slice(&value.to_be_bytes()[4 - len..]);
        }
        normal[0x2f00..0x2f02].copy_from_slice(&[0x54, 0x70]);
        for &(at, value) in [
            (16, 0x412f00),
            (22, 0x412f04),
            (34, 0x412b00),
            (56, 0x412b80),
            (64, 0x412a00),
            (70, 0x412a00 + body_len as u32),
            (76, 0x600),
        ]
        .iter()
        .chain(writes)
        {
            word(&mut normal, 0x2800 + at, value);
        }
        normal[0x2000..0x2004].copy_from_slice(&[0x5a, 0x41, 0x28, 0]);
        normal
    }

    #[test]
    fn another_write_into_the_copied_block_refuses_even_away_from_the_entry() {
        let clean = startup(&[]);
        assert!(matches!(
            relocated(&clean, 0x600, 1),
            Observation::Known(Relocation {
                destination: 0x600,
                ..
            })
        ));
        // The fourth call clears RAM 0x610..0x620, inside the copied block but
        // after the requested one-byte entry: the source is no longer verbatim.
        let cleared = startup(&[(84, 0x610), (90, 0x620)]);
        let result = relocated(&cleared, 0x600, 1);
        assert!(matches!(result, Observation::Conflicting), "{result:?}");
    }

    #[test]
    fn the_copy_range_spans_every_argument_load_and_the_call() {
        let normal = startup(&[]);
        // The first copy loads its helper pointer between the arguments and
        // the call: ER0 at +14, ER1 +20, ER2 +26, ER4 +32, JSR @ER4 at +38.
        let Observation::Known(first) = relocated(&normal, 4, 1) else {
            panic!("first copy unresolved");
        };
        assert_eq!(first.copy, 0x2800 + 14..0x2800 + 40);
        let Observation::Known(third) = relocated(&normal, 0x600, 1) else {
            panic!("third copy unresolved");
        };
        assert_eq!(third.copy, 0x2800 + 62..0x2800 + 82);
    }

    #[test]
    fn helper_operand_offsets_are_holes_in_every_c_startup_shape() {
        for shape in super::super::boot_shapes::C_STARTUP {
            for at in [COPY_HELPER_OPERAND, CLEAR_HELPER_OPERAND] {
                assert!(shape.holes.contains(&(at, 4)));
                assert_eq!(shape.bytes[at - 2], 0x7a);
            }
        }
    }
}
