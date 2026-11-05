//! Split placement for OEM routines with no branches crossing the split.
use super::encoding;
use alloc::vec::Vec;
use core::ops::Range;
use h8_asm::{
    isa::{decode_insn, Ea, Operand},
    Mode, Target,
};

const BASE: usize = 0x410000;

/// A complete logical OEM body and the physical spans containing it.
#[derive(Debug, Clone)]
pub(crate) struct Body {
    pub bytes: Vec<u8>,
    pub spans: Vec<Range<usize>>,
}

fn stored(normal: &[u8], regions: &[&[u8]], span: &Range<usize>) -> bool {
    regions.iter().any(|r| {
        let at = r.as_ptr() as usize - normal.as_ptr() as usize;
        span.start >= at && span.end <= at + r.len()
    })
}

/// Read a complete template, optionally crossing one absolute JMP between
/// instructions. All physical bytes must be stored, disjoint and recognized.
pub(crate) fn read(
    normal: &[u8],
    regions: &[&[u8]],
    start: usize,
    template: &[Option<u8>],
) -> Option<Body> {
    let mut bytes = Vec::new();
    let mut spans = Vec::new();
    let mut at = start;
    let mut begin = start;
    let mut cut = None;
    while bytes.len() < template.len() {
        let decoded = decode_insn(normal.get(at..)?, Target::H8S2000, Mode::Advanced).ok()?;
        let end = at.checked_add(decoded.len)?;
        if !stored(normal, regions, &(at..end)) {
            return None;
        }
        if decoded.insn.mnemonic == "JMP" {
            if bytes.is_empty() || !spans.is_empty() {
                return None;
            }
            let Operand::Address(Ea::Absolute { value, bits: 24 }) = decoded.insn.operands[0]
            else {
                return None;
            };
            let next = (value as usize).checked_sub(BASE)?;
            if next & 1 != 0 {
                return None;
            }
            spans.push(begin..end);
            cut = Some(bytes.len());
            begin = next;
            at = next;
            continue;
        }
        let logical_end = bytes.len().checked_add(decoded.len)?;
        if !normal[at..end]
            .iter()
            .zip(template.get(bytes.len()..logical_end)?)
            .all(|(b, t)| t.map_or(true, |t| t == *b))
        {
            return None;
        }
        bytes.extend_from_slice(&normal[at..end]);
        at = end;
    }
    spans.push(begin..at);
    if spans.len() == 2 && spans[0].start < spans[1].end && spans[1].start < spans[0].end {
        return None;
    }
    let Flow { edges, .. } = flow(&bytes)?;
    if cut.is_some_and(|cut| edges.iter().any(|(from, to)| (*from < cut) != (*to < cut))) {
        return None;
    }
    Some(Body { bytes, spans })
}

/// Decode every instruction and resolve every relative edge to an instruction
/// start inside the OEM routine. Computed branches and early returns are refused.
struct Flow {
    starts: Vec<usize>,
    edges: Vec<(usize, usize)>,
}
fn flow(bytes: &[u8]) -> Option<Flow> {
    let mut starts = Vec::new();
    let mut edges = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        starts.push(at);
        let d = decode_insn(&bytes[at..], Target::H8S2000, Mode::Advanced).ok()?;
        if matches!(d.insn.mnemonic, "JMP" | "RTE" | "TRAPA" | "SLEEP")
            || (d.insn.mnemonic == "RTS" && at + d.len != bytes.len())
        {
            return None;
        }
        for operand in d.insn.operands {
            if let Operand::Address(Ea::PcRelative { value, .. }) = operand {
                let destination = (at + d.len).checked_add_signed(value as isize)?;
                edges.push((at, destination));
            }
        }
        at += d.len;
        if at == bytes.len() && d.insn.mnemonic != "RTS" {
            return None;
        }
    }
    if edges.iter().any(|(_, to)| !starts.contains(to)) {
        return None;
    }
    Some(Flow { starts, edges })
}

/// Relocate two branch-closed pieces through h8-asm, retaining OEM bytes.
/// The selected cut cannot redirect any conditional or subroutine branch.
pub(crate) fn split_closed(
    bytes: &[u8],
    original_address: u32,
    original_len: usize,
    spill_address: u32,
) -> Option<(Vec<u8>, Vec<u8>)> {
    let jump = encoding::jump(spill_address)?;
    let capacity = original_len.checked_sub(jump.len())?;
    let Flow { starts, edges } = flow(bytes)?;
    let cut = starts.into_iter().rev().find(|cut| {
        *cut != 0
            && *cut <= capacity
            && edges
                .iter()
                .all(|(from, to)| (*from < *cut) == (*to < *cut))
    })?;
    let suffix_address = original_address.checked_add(u32::try_from(cut).ok()?)?;
    let prefix = h8_asm::relocate::relocate(
        &bytes[..cut],
        original_address,
        original_address,
        Target::H8S2000,
        Mode::Advanced,
    )
    .ok()?;
    let spill = h8_asm::relocate::relocate(
        &bytes[cut..],
        suffix_address,
        spill_address,
        Target::H8S2000,
        Mode::Advanced,
    )
    .ok()?;
    // All relative edges were internal to their piece, so no widening or operand
    // changes are needed. Refuse any deviation from the copied OEM stream.
    if prefix.bytes != bytes[..cut] || spill.bytes != bytes[cut..] {
        return None;
    }
    let mut prefix = prefix.bytes;
    prefix.extend_from_slice(&jump);
    let used = prefix.len();
    prefix.resize(original_len, 0);
    encoding::nops(&mut prefix[used..])?;
    Some((prefix, spill.bytes))
}

/// Check the references visible in a Normal component before reusing part of a
/// completely bound, replaced routine. This rejects direct entries into the
/// routine interior and address-taken uses of any part of the original routine.
/// Expanded streams have no execution mapping here: their absolute references
/// are checked, but relative/indirect execution and other components remain the
/// complete operation owner's obligation.
pub(crate) fn retirement_references_clear(
    normal: &[u8],
    original: &Range<usize>,
    retired: &Range<usize>,
) -> Option<()> {
    retirement_references_clear_covered(normal, original, retired, &[])
}

/// A caller may supply additional complete, positively grammar-bound routines
/// to distinguish real instruction starts from accidental opcodes in operands.
/// Their full CFGs are checked; actual instructions and raw pointer data retain
/// all reference checks. Arbitrary enclosing byte ranges are not proof inputs.
pub(crate) fn retirement_references_clear_covered(
    normal: &[u8],
    original: &Range<usize>,
    retired: &Range<usize>,
    covered: &[Range<usize>],
) -> Option<()> {
    let bodies = covered
        .iter()
        .map(|span| {
            Some(Body {
                bytes: normal.get(span.clone())?.to_vec(),
                spans: alloc::vec![span.clone()],
            })
        })
        .collect::<Option<Vec<_>>>()?;
    retirement_references_clear_bodies(normal, original, retired, &bodies)
}

/// As above, with complete native logical bodies that may have one proved
/// closed suffix spill. Reconstruct the physical bytes before trusting any
/// instruction boundary; fragments alone cannot suppress reference checks.
pub(crate) fn retirement_references_clear_bodies(
    normal: &[u8],
    original: &Range<usize>,
    retired: &Range<usize>,
    covered: &[Body],
) -> Option<()> {
    let regions = crate::image::regions(normal)?;
    if original.start >= retired.start
        || retired.start >= retired.end
        || retired.end != original.end
        || !stored(normal, &regions.stored, original)
    {
        return None;
    }
    flow(normal.get(original.clone())?)?;
    let parent = BASE.checked_add(original.start)?..BASE.checked_add(original.end)?;
    component_references_clear(normal, BASE, parent, Some(original), covered, None)
}

/// Check the exact supplied resident component at its own execution base.
/// Routine ownership remains bounded to native entries and visible references;
/// this does not assert absence of arbitrary runtime address synthesis.
pub(crate) fn retirement_kernel_references_clear(
    kernel: &[u8],
    original: &Range<usize>,
) -> Option<()> {
    if kernel.len() != crate::image::KERNEL_LEN {
        return None;
    }
    let parent = BASE.checked_add(original.start)?..BASE.checked_add(original.end)?;
    component_references_clear(
        kernel,
        crate::image::KERNEL_BASE as usize,
        parent,
        None,
        &[],
        None,
    )
}

/// Loader entries retain their complete native call ABI. Raw data candidates
/// own only bytes in the reclaimed suffix; elsewhere in the original body an
/// even instruction-interior address remains a possible alternate entry. Odd
/// values cannot be executable H8 entries and do not own an unrelated suffix.
pub(crate) fn retirement_loader_references_clear(
    normal: &[u8],
    kernel: &[u8],
    original: &Range<usize>,
    retired: &Range<usize>,
) -> Option<()> {
    let regions = crate::image::regions(normal)?;
    if kernel.len() != crate::image::KERNEL_LEN
        || original.start >= retired.start
        || retired.start >= retired.end
        || retired.end != original.end
        || !stored(normal, &regions.stored, original)
    {
        return None;
    }
    flow(normal.get(original.clone())?)?;
    let parent = BASE.checked_add(original.start)?..BASE.checked_add(original.end)?;
    let tail = BASE.checked_add(retired.start)?..BASE.checked_add(retired.end)?;
    component_references_clear(
        normal,
        BASE,
        parent.clone(),
        Some(original),
        &[],
        Some(&tail),
    )?;
    component_references_clear(
        kernel,
        crate::image::KERNEL_BASE as usize,
        parent,
        None,
        &[],
        Some(&tail),
    )
}

fn component_references_clear(
    component: &[u8],
    load_base: usize,
    parent: Range<usize>,
    exclusion: Option<&Range<usize>>,
    covered: &[Body],
    retired_data: Option<&Range<usize>>,
) -> Option<()> {
    let conflicts = |value: usize, address_taken: bool| {
        if let Some(tail) = retired_data {
            tail.contains(&value)
                || (value & 1 == 0 && value != parent.start && parent.contains(&value))
        } else if address_taken {
            parent.contains(&value)
        } else {
            value != parent.start && parent.contains(&value)
        }
    };
    let regions = crate::image::regions(component)?;
    let mut interiors = Vec::new();
    for body in covered {
        flow(&body.bytes)?;
        if !(1..=2).contains(&body.spans.len()) {
            return None;
        }
        let mut reconstructed = Vec::new();
        for (index, span) in body.spans.iter().enumerate() {
            if !stored(component, &regions.stored, span) {
                return None;
            }
            let mut at = span.start;
            while at < span.end {
                let d = decode_insn(
                    component.get(at..span.end)?,
                    Target::H8S2000,
                    Mode::Advanced,
                )
                .ok()?;
                if d.insn.mnemonic == "JMP" {
                    let Operand::Address(Ea::Absolute { value, bits: 24 }) = d.insn.operands[0]
                    else {
                        return None;
                    };
                    if index != 0
                        || body.spans.len() != 2
                        || at + d.len != span.end
                        || value as usize != load_base.checked_add(body.spans[1].start)?
                    {
                        return None;
                    }
                } else {
                    reconstructed.extend_from_slice(&component[at..at + d.len]);
                }
                interiors.push(at + 1..at + d.len);
                at += d.len;
            }
        }
        if reconstructed != body.bytes {
            return None;
        }
    }
    for (bytes, offset) in regions
        .stored
        .iter()
        .map(|r| (*r, Some(r.as_ptr() as usize - component.as_ptr() as usize)))
        .chain(regions.expanded.iter().map(|r| (r.as_slice(), None)))
    {
        for at in (offset.unwrap_or(0) % 2..bytes.len()).step_by(2) {
            if offset
                .is_some_and(|offset| exclusion.is_some_and(|range| range.contains(&(offset + at))))
            {
                continue;
            }
            if offset
                .is_some_and(|offset| interiors.iter().any(|range| range.contains(&(offset + at))))
            {
                continue;
            }
            let Ok(d) = decode_insn(&bytes[at..], Target::H8S2000, Mode::Advanced) else {
                continue;
            };
            for operand in d.insn.operands {
                let (value, address_taken) = match operand {
                    Operand::Address(Ea::Absolute {
                        value,
                        bits: 24 | 32,
                    }) => (
                        Some(value as usize),
                        !matches!(d.insn.mnemonic, "JSR" | "JMP"),
                    ),
                    Operand::Immediate { value, bits: 32 } => (Some(value as usize), true),
                    Operand::Address(Ea::PcRelative { value, .. }) => (
                        offset.and_then(|offset| {
                            (load_base + offset + at + d.len).checked_add_signed(value as isize)
                        }),
                        false,
                    ),
                    _ => (None, false),
                };
                if value.is_some_and(|value| conflicts(value, address_taken)) {
                    return None;
                }
            }
        }
        // Also find pointer-table entries, including unaligned data that is not
        // an instruction stream. h8-asm owns signature search and word decoding.
        for high in parent.start >> 16..=(parent.end - 1) >> 16 {
            let prefix = (high as u16).to_be_bytes();
            let mut start = 0;
            while let Some(at) =
                h8_asm::image::find(bytes, h8_asm::image::Needle::Bytes(&prefix), start)
            {
                start = at + 1;
                if offset.is_some_and(|offset| {
                    exclusion.is_some_and(|range| range.contains(&(offset + at)))
                }) {
                    continue;
                }
                if h8_asm::image::read_u32(bytes, at)
                    .is_some_and(|value| conflicts(value as usize, true))
                {
                    return None;
                }
            }
        }
    }
    Some(())
}

#[cfg(test)]
mod ownership_tests {
    use super::*;
    use h8_asm::isa::{encode_insn, Insn, Reg, Size};

    #[test]
    fn retired_routine_checks_resident_entries_pointers_and_its_actual_base() {
        let mut normal = alloc::vec![0xff; 0x800];
        normal[0x100..0x106].copy_from_slice(&[0, 0, 0, 0, 0x54, 0x70]);
        let original = 0x100..0x106;
        let tail = 0x102..0x106;
        assert!(retirement_references_clear(&normal, &original, &tail).is_some());
        let kernel = alloc::vec![0xff;crate::image::KERNEL_LEN];
        assert!(retirement_kernel_references_clear(&kernel, &original).is_some());
        for missing in [&[][..], &kernel[..kernel.len() - 2]] {
            assert!(retirement_kernel_references_clear(missing, &original).is_none());
        }
        let encode = |mnemonic, size, operands| {
            encode_insn(
                Insn::new(mnemonic, size, operands),
                Target::H8S2000,
                Mode::Advanced,
            )
            .unwrap()
        };
        for (bytes, at) in [
            (
                encode(
                    "JSR",
                    None,
                    [
                        Operand::Address(Ea::Absolute {
                            value: 0x410102,
                            bits: 24,
                        }),
                        Operand::None,
                        Operand::None,
                    ],
                ),
                0x800,
            ),
            (
                encode(
                    "MOV",
                    Some(Size::Long),
                    [
                        Operand::Immediate {
                            value: 0x410100,
                            bits: 32,
                        },
                        Operand::Register(Reg::Long(0)),
                        Operand::None,
                    ],
                ),
                0x800,
            ),
            (0x410102u32.to_be_bytes().to_vec(), 0x801),
            // This branch crosses from the resident Kernel into the retired
            // Normal suffix. Its displacement must use 0x400000, not 0x410000.
            (
                encode(
                    "BRA",
                    None,
                    [
                        Operand::Address(Ea::PcRelative {
                            value: 0x1fe,
                            bits: 16,
                        }),
                        Operand::None,
                        Operand::None,
                    ],
                ),
                0xff00,
            ),
        ] {
            let mut broken = kernel.clone();
            broken[at..at + bytes.len()].copy_from_slice(&bytes);
            assert!(
                retirement_kernel_references_clear(&broken, &original).is_none(),
                "{at:x}"
            );
        }
        let bytes = encode(
            "JSR",
            None,
            [
                Operand::Address(Ea::Absolute {
                    value: 0x410100,
                    bits: 24,
                }),
                Operand::None,
                Operand::None,
            ],
        );
        let mut entry = kernel;
        entry[0x800..0x800 + bytes.len()].copy_from_slice(&bytes);
        assert!(
            retirement_kernel_references_clear(&entry, &original).is_some(),
            "unchanged native entry remains callable"
        );
    }
    #[test]
    fn loader_suffix_ownership_separates_entries_from_data_addresses() {
        let mut normal = alloc::vec![0xff; 0x800];
        normal[0x100..0x106].copy_from_slice(&[0, 0, 0, 0, 0x54, 0x70]);
        let kernel = alloc::vec![0xff; crate::image::KERNEL_LEN];
        let original = 0x100..0x106;
        let tail = 0x104..0x106;
        // An odd value outside the reclaimed span cannot be a native H8
        // executable entry and does not reserve unrelated tail bytes.
        for (value, allowed) in [
            (0x410101u32, true),
            (0x410100, true),
            (0x410102, false),
            (0x410104, false),
            (0x410105, false),
        ] {
            let mut changed = normal.clone();
            changed[0x701..0x705].copy_from_slice(&value.to_be_bytes());
            assert_eq!(
                retirement_loader_references_clear(&changed, &kernel, &original, &tail).is_some(),
                allowed
            );
            let mut resident = kernel.clone();
            resident[0x701..0x705].copy_from_slice(&value.to_be_bytes());
            assert_eq!(
                retirement_loader_references_clear(&normal, &resident, &original, &tail).is_some(),
                allowed
            );
        }
        assert!(retirement_loader_references_clear(&normal, &[], &original, &tail).is_none());
        assert!(
            retirement_loader_references_clear(&normal, &kernel[..0xfffe], &original, &tail)
                .is_none()
        );
    }
}
