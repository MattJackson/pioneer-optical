//! Profile storage closure with positively bound unchanged native code authority.
//!
//! The owner must positively bind every supplied range to complete OEM code or
//! data and prove the replacement entry ABI. This scanner does not discover free
//! space. It checks visible references in stored/expanded Normal and the exact
//! resident Kernel; arbitrary runtime address synthesis is outside this contract.
use alloc::vec::Vec;
use core::ops::Range;
use h8_asm::{
    isa::{decode_insn, Ea, Operand},
    Mode, Target,
};

const BASE: usize = 0x410000;

/// Reject external references and return unchanged code authority witnesses.
/// Complete native profile client grammars authorize instruction boundaries;
/// every typed address/control operand remains checked, including literals.
/// Retained entry instructions must be excluded from `retired`. Callers provide
/// complete grammar-bound instruction bodies in `known_complete_bodies` solely
/// to avoid interpreting their operand interiors as independent instructions.
pub fn prove(
    normal: &[u8],
    kernel: &[u8],
    retired: &[Range<usize>],
    replaced: &[Range<usize>],
    known_complete_bodies: &[Range<usize>],
) -> Option<Vec<Range<usize>>> {
    prove_inner(
        normal,
        kernel,
        retired,
        replaced,
        known_complete_bodies,
        None,
    )
}
/// Close a recognized emitted profile beside exclusive native software tables.
/// The four arrays gain data authority only after every external reference is
/// bound to the selector's exact MOV.L address operand. Raw pointers inside
/// their bytes remain checked against the profile being protected.
pub fn prove_with_software_tables(
    normal: &[u8],
    kernel: &[u8],
    retired: &[Range<usize>],
    replaced: &[Range<usize>],
    known_complete_bodies: &[Range<usize>],
    profile: &super::trajectory_profile::ProfileDataAuthority,
) -> Option<Vec<Range<usize>>> {
    let data = software_data(normal, kernel, retired, known_complete_bodies, profile)?;
    let mut protected = prove_inner(
        normal,
        kernel,
        retired,
        replaced,
        known_complete_bodies,
        Some(&data),
    )?;
    protected.extend(data.protected);
    Some(protected)
}
fn prove_inner(
    normal: &[u8],
    kernel: &[u8],
    retired: &[Range<usize>],
    replaced: &[Range<usize>],
    known_complete_bodies: &[Range<usize>],
    data: Option<&SoftwareData>,
) -> Option<Vec<Range<usize>>> {
    // Classification authority is optional: without a complete native match,
    // every instruction candidate and raw pointer window remains scanned.
    // Absence never grants an exemption or certifies an allocation.
    let authority = super::profile_code::observe(normal);
    if kernel.len() != crate::image::KERNEL_LEN || retired.is_empty() {
        return None;
    }
    let regions = crate::image::regions(normal)?;
    let stored = |span: &Range<usize>| {
        span.start < span.end
            && regions.stored.iter().any(|bytes| {
                let start = bytes.as_ptr() as usize - normal.as_ptr() as usize;
                start <= span.start && span.end <= start + bytes.len()
            })
    };
    if replaced.iter().any(|span| !stored(span))
        || retired.iter().any(|span| {
            !stored(span)
                || !replaced
                    .iter()
                    .any(|owner| owner.start <= span.start && span.end <= owner.end)
        })
    {
        return None;
    }
    let mut interiors = Vec::new();
    for body in known_complete_bodies {
        if !stored(body) || body.start & 1 != 0 {
            return None;
        }
        let mut at = body.start;
        let mut starts = Vec::new();
        let mut branches = Vec::new();
        while at < body.end {
            let d = decode_insn(normal.get(at..body.end)?, Target::H8S2000, Mode::Advanced).ok()?;
            starts.push(at);
            interiors.push(at + 1..at + d.len);
            if d.insn.mnemonic != "BSR" {
                for operand in d.insn.operands {
                    if let Operand::Address(Ea::PcRelative { value, .. }) = operand {
                        branches.push((at + d.len).checked_add_signed(value as isize)?);
                    }
                }
            }
            at += d.len;
        }
        if branches.iter().any(|to| !starts.contains(to)) {
            return None;
        }
    }
    check_component(
        normal,
        BASE,
        retired,
        replaced,
        &interiors,
        authority.as_ref(),
        data,
    )?;
    check_component(
        kernel,
        crate::image::KERNEL_BASE as usize,
        retired,
        &[],
        &[],
        None,
        None,
    )?;
    let mut protected = authority
        .as_ref()
        .map_or_else(Vec::new, |a| a.protected_normal());
    protected.extend(known_complete_bodies.iter().cloned());
    Some(protected)
}

fn check_component(
    component: &[u8],
    base: usize,
    retired: &[Range<usize>],
    replaced: &[Range<usize>],
    interiors: &[Range<usize>],
    authority: Option<&super::profile_code::Authority>,
    data: Option<&SoftwareData>,
) -> Option<()> {
    let regions = crate::image::regions(component)?;
    let conflict = |address: usize| {
        address
            .checked_sub(BASE)
            .is_some_and(|offset| retired.iter().any(|span| span.contains(&offset)))
    };
    let excluded = |offset: Option<usize>, at: usize, len: usize| {
        offset.is_some_and(|offset| {
            if data.is_some_and(|d| {
                d.ordinary.start < offset + at + len && offset + at < d.ordinary.end
            }) {
                return false;
            }
            replaced
                .iter()
                .any(|span| span.start <= offset + at && offset + at + len <= span.end)
        })
    };
    for (bytes, offset) in regions
        .stored
        .iter()
        .map(|bytes| {
            (
                *bytes,
                Some(bytes.as_ptr() as usize - component.as_ptr() as usize),
            )
        })
        .chain(
            regions
                .expanded
                .iter()
                .map(|bytes| (bytes.as_slice(), None)),
        )
    {
        for at in (offset.unwrap_or(0) % 2..bytes.len()).step_by(2) {
            if offset.is_some_and(|offset| {
                interiors.iter().any(|span| span.contains(&(offset + at)))
                    || authority.is_some_and(|proof| {
                        proof.instruction_interior((base + offset + at) as u32)
                    })
            }) {
                continue;
            }
            if offset.is_some_and(|origin| {
                data.is_some_and(|d| d.arrays.iter().any(|r| r.contains(&(origin + at))))
            }) {
                continue;
            }
            let Ok(d) = decode_insn(&bytes[at..], Target::H8S2000, Mode::Advanced) else {
                continue;
            };
            if excluded(offset, at, d.len) {
                continue;
            }
            for operand in d.insn.operands {
                let address = |ea| match ea {
                    Ea::Absolute { value, .. } => Some(value as usize),
                    Ea::Displacement {
                        value, bits: 32, ..
                    }
                    | Ea::Indexed {
                        value, bits: 32, ..
                    } => Some(value as u32 as usize),
                    Ea::PcRelative { value, .. } => offset.and_then(|offset| {
                        (base + offset + at + d.len).checked_add_signed(value as isize)
                    }),
                    _ => None,
                };
                let addresses = match operand {
                    Operand::Address(ea) => [address(ea), None],
                    Operand::Immediate { value, bits: 32 } => [Some(value as usize), None],
                    Operand::IndexedMemory {
                        address: ea,
                        value,
                        bits,
                        ..
                    } => [address(ea), (bits == 32).then_some(value as u32 as usize)],
                    _ => [None, None],
                };
                if addresses.into_iter().flatten().any(conflict) {
                    return None;
                }
            }
        }
        // Scan unaligned pointer-table entries too. A pointer crossing a replaced
        // range boundary is still live and must not be excluded by its first byte.
        for at in 0..bytes.len().saturating_sub(3) {
            let scalar = offset.is_some_and(|o| {
                data.is_some_and(|d| d.arrays.iter().any(|r| r.contains(&(o + at))))
            });
            if (!excluded(offset, at, 4) || scalar)
                && !offset.is_some_and(|offset| {
                    authority.is_some_and(|proof| {
                        proof.instruction_bytes((base + offset + at) as u32, 4)
                    })
                })
                && h8_asm::image::read_u32(bytes, at).is_some_and(|address| {
                    conflict(address as usize)
                        && !(scalar
                            && data.is_some_and(|d| {
                                address.checked_sub(BASE as u32).is_some_and(|a| {
                                    d.arrays.iter().any(|r| r.contains(&(a as usize)))
                                })
                            }))
                })
            {
                return None;
            }
        }
    }
    Some(())
}

struct SoftwareData {
    arrays: Vec<Range<usize>>,
    // Logging arguments are not certified as exclusively data by an opaque
    // call. Their bytes retain both typed-instruction and raw-pointer scans.
    ordinary: Range<usize>,
    protected: Vec<Range<usize>>,
}
fn software_data(
    normal: &[u8],
    kernel: &[u8],
    executable_and_profile: &[Range<usize>],
    known: &[Range<usize>],
    profile: &super::trajectory_profile::ProfileDataAuthority,
) -> Option<SoftwareData> {
    use crate::filters::phase::native::encoders;
    use h8_asm::isa::{Reg, Size};
    if !profile.is_bound_to(normal) {
        return None;
    }
    let graph = super::dispatch_bridge::observe(normal).ok()?;
    let coils = encoders::observe(normal).ok()?;
    let software = super::software::observe(normal).ok()?;
    if graph.kind != super::dispatch_bridge::Kind::Software
        || graph.selector.len() != 58
        || coils.representation != encoders::Representation::HighByte
    {
        return None;
    }
    let mut arrays: Vec<_> = software
        .choices
        .into_iter()
        .map(|(_, s)| match s {
            super::software::Source::Image(r) => Some(r),
            _ => None,
        })
        .collect::<Option<_>>()?;
    if arrays.len() != 4
        || arrays.iter().enumerate().any(|(i, a)| {
            a.len() != 256
                || arrays[..i]
                    .iter()
                    .chain(executable_and_profile)
                    .chain(known)
                    .any(|b| a.start < b.end && b.start < a.end)
        })
    {
        return None;
    }
    for range in profile.scalar_ranges() {
        if arrays
            .iter()
            .any(|a| a.start < range.end && range.start < a.end)
            || executable_and_profile
                .iter()
                .any(|r| r != range && r.start < range.end && range.start < r.end)
        {
            return None;
        }
        arrays.push(range.clone());
    }
    let mut bodies = known.to_vec();
    bodies.extend([graph.dispatch.clone(), graph.selector.clone()]);
    bodies.extend(coils.programs.iter().flatten().cloned());
    if bodies
        .iter()
        .any(|b| arrays.iter().any(|a| a.start < b.end && b.start < a.end))
    {
        return None;
    }
    let mut instructions = Vec::new();
    for b in &bodies {
        let mut at = b.start;
        while at < b.end {
            let d = decode_insn(normal.get(at..b.end)?, Target::H8S2000, Mode::Advanced).ok()?;
            instructions.push(at..at + d.len);
            at += d.len;
        }
    }
    let authority = super::profile_code::observe(normal);
    let mut fields = Vec::new();
    for field in (20..52).step_by(8) {
        let at = graph.selector.start + field - 2;
        let d = decode_insn(
            normal.get(at..graph.selector.end)?,
            Target::H8S2000,
            Mode::Advanced,
        )
        .ok()?;
        let Operand::Immediate { value, bits: 32 } = d.insn.operands[0] else {
            return None;
        };
        if d.len != 6
            || d.insn.mnemonic != "MOV"
            || d.insn.size != Some(Size::Long)
            || d.insn.operands[1] != Operand::Register(Reg::Long(1))
            || !arrays.iter().any(|r| r.start + BASE == value as usize)
        {
            return None;
        }
        fields.push((at, at + 2, value as usize));
    }
    let touches = |address: usize| {
        address
            .checked_sub(BASE)
            .is_some_and(|at| arrays.iter().any(|r| r.contains(&at)))
    };
    for (component, base) in [(normal, BASE), (kernel, crate::image::KERNEL_BASE as usize)] {
        let regions = crate::image::regions(component)?;
        for (bytes, offset) in regions
            .stored
            .iter()
            .map(|b| (*b, Some(b.as_ptr() as usize - component.as_ptr() as usize)))
            .chain(regions.expanded.iter().map(|b| (b.as_slice(), None)))
        {
            let normal_at = |at| {
                if base == BASE {
                    offset.map(|o| o + at)
                } else {
                    None
                }
            };
            let in_array =
                |at| normal_at(at).is_some_and(|at| arrays.iter().any(|r| r.contains(&at)));
            let code_interior = |at| {
                normal_at(at).is_some_and(|at| {
                    instructions.iter().any(|r| r.start < at && at < r.end)
                        || authority
                            .as_ref()
                            .is_some_and(|a| a.instruction_interior((BASE + at) as u32))
                })
            };
            for at in (offset.unwrap_or(0) % 2..bytes.len()).step_by(2) {
                if in_array(at) || code_interior(at) {
                    continue;
                }
                let Ok(d) = decode_insn(&bytes[at..], Target::H8S2000, Mode::Advanced) else {
                    continue;
                };
                let ea = |address| match address {
                    Ea::Absolute { value, .. } => Some(value as usize),
                    Ea::Displacement {
                        value, bits: 32, ..
                    }
                    | Ea::Indexed {
                        value, bits: 32, ..
                    } => Some(value as u32 as usize),
                    Ea::PcRelative { value, .. } => offset
                        .and_then(|o| (base + o + at + d.len).checked_add_signed(value as isize)),
                    _ => None,
                };
                for (index, operand) in d.insn.operands.into_iter().enumerate() {
                    let addresses = match operand {
                        Operand::Address(a) => [ea(a), None],
                        Operand::Immediate { value, bits: 32 } => [Some(value as usize), None],
                        Operand::IndexedMemory {
                            address,
                            value,
                            bits,
                            ..
                        } => [ea(address), (bits == 32).then_some(value as u32 as usize)],
                        _ => [None, None],
                    };
                    for address in addresses.into_iter().flatten().filter(|a| touches(*a)) {
                        if !(index == 0
                            && matches!(operand, Operand::Immediate { bits: 32, .. })
                            && normal_at(at).is_some_and(|at| {
                                fields
                                    .iter()
                                    .any(|(insn, _, value)| *insn == at && *value == address)
                            })
                            || matches!(d.insn.mnemonic, "MOV" | "ADD")
                                && normal_at(at)
                                    .is_some_and(|at| profile.allow_typed(at, index, address)))
                        {
                            return None;
                        }
                    }
                }
            }
            for at in 0..bytes.len().saturating_sub(3) {
                let address = h8_asm::image::read_u32(bytes, at)? as usize;
                if !touches(address) || in_array(at) {
                    continue;
                }
                let code = normal_at(at).is_some_and(|at| {
                    (0..4).all(|i| instructions.iter().any(|r| r.contains(&(at + i))))
                        || authority
                            .as_ref()
                            .is_some_and(|a| a.instruction_bytes((BASE + at) as u32, 4))
                });
                if !code
                    && !normal_at(at).is_some_and(|at| {
                        fields
                            .iter()
                            .any(|(_, field, value)| *field == at && *value == address)
                            || profile.allow_raw(at, address)
                    })
                {
                    return None;
                }
            }
        }
    }
    let mut protected = authority
        .as_ref()
        .map_or_else(Vec::new, |a| a.protected_normal());
    protected.extend(arrays.iter().cloned());
    protected.extend(bodies);
    protected.push(coils.leaf);
    protected.extend(graph.callers.into_iter().flatten());
    Some(SoftwareData {
        arrays,
        protected,
        ordinary: profile.diagnostic_range().clone(),
    })
}
