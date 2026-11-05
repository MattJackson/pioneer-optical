//! Reference checks for a simultaneously replaced native resource graph.
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

/// Reject references from outside the replaced graph into any retired byte.
/// Retained entry instructions must be excluded from `retired`. Callers provide
/// complete grammar-bound instruction bodies in `known_complete_bodies` solely
/// to avoid interpreting their operand interiors as independent instructions.
pub fn references_clear(
    normal: &[u8],
    kernel: &[u8],
    retired: &[Range<usize>],
    replaced: &[Range<usize>],
    known_complete_bodies: &[Range<usize>],
) -> Option<()> {
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
    check_component(normal, BASE, retired, replaced, &interiors)?;
    check_component(
        kernel,
        crate::image::KERNEL_BASE as usize,
        retired,
        &[],
        &[],
    )
}

fn check_component(
    component: &[u8],
    base: usize,
    retired: &[Range<usize>],
    replaced: &[Range<usize>],
    interiors: &[Range<usize>],
) -> Option<()> {
    let regions = crate::image::regions(component)?;
    let conflict = |address: usize| {
        address
            .checked_sub(BASE)
            .is_some_and(|offset| retired.iter().any(|span| span.contains(&offset)))
    };
    let excluded = |offset: Option<usize>, at: usize, len: usize| {
        offset.is_some_and(|offset| {
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
            if offset
                .is_some_and(|offset| interiors.iter().any(|span| span.contains(&(offset + at))))
            {
                continue;
            }
            let Ok(d) = decode_insn(&bytes[at..], Target::H8S2000, Mode::Advanced) else {
                continue;
            };
            if excluded(offset, at, d.len) {
                continue;
            }
            for operand in d.insn.operands {
                let address = match operand {
                    Operand::Address(Ea::Absolute {
                        value,
                        bits: 24 | 32,
                    })
                    | Operand::Immediate { value, bits: 32 } => Some(value as usize),
                    Operand::Address(Ea::PcRelative { value, .. }) => offset.and_then(|offset| {
                        (base + offset + at + d.len).checked_add_signed(value as isize)
                    }),
                    _ => None,
                };
                if address.is_some_and(&conflict) {
                    return None;
                }
            }
        }
        // Scan unaligned pointer-table entries too. A pointer crossing a replaced
        // range boundary is still live and must not be excluded by its first byte.
        for at in 0..bytes.len().saturating_sub(3) {
            if !excluded(offset, at, 4)
                && h8_asm::image::read_u32(bytes, at)
                    .is_some_and(|address| conflict(address as usize))
            {
                return None;
            }
        }
    }
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn simultaneous_retirement_rejects_external_and_resident_edges() {
        let mut normal = alloc::vec![0xff; 0x800];
        let kernel = alloc::vec![0xff; crate::image::KERNEL_LEN];
        let retired = [0x104..0x120, 0x200..0x220];
        let replaced = [0x100..0x120, 0x200..0x220];
        normal[0x110..0x114].copy_from_slice(&0x410200u32.to_be_bytes());
        normal[0x210..0x214].copy_from_slice(&0x410104u32.to_be_bytes());
        assert!(references_clear(&normal, &kernel, &retired, &replaced, &[]).is_some());
        for address in [0x410104u32, 0x41011f, 0x410200, 0x41021f] {
            let mut changed = normal.clone();
            changed[0x401..0x405].copy_from_slice(&address.to_be_bytes());
            assert!(references_clear(&changed, &kernel, &retired, &replaced, &[]).is_none());
            let mut resident = kernel.clone();
            resident[0x801..0x805].copy_from_slice(&address.to_be_bytes());
            assert!(references_clear(&normal, &resident, &retired, &replaced, &[]).is_none());
        }
        let mut resident = kernel.clone();
        // BRA at Kernel0x40ff00 to Normal0x410104: displacement0x200.
        resident[0xff00..0xff04].copy_from_slice(&[0x58, 0x00, 0x02, 0x00]);
        assert!(references_clear(&normal, &resident, &retired, &replaced, &[]).is_none());
        assert!(references_clear(&normal, &kernel[..100], &retired, &replaced, &[]).is_none());
        let mut entry = normal.clone();
        entry[0x401..0x405].copy_from_slice(&0x410100u32.to_be_bytes());
        assert!(references_clear(&entry, &kernel, &retired, &replaced, &[]).is_some());
    }
    #[test]
    fn replacement_bounds_do_not_hide_live_pointer_suffixes() {
        let mut normal = alloc::vec![0xff; 0x800];
        let kernel = alloc::vec![0xff; crate::image::KERNEL_LEN];
        normal[0x11e..0x122].copy_from_slice(&0x410200u32.to_be_bytes());
        assert!(references_clear(
            &normal,
            &kernel,
            core::slice::from_ref(&(0x200..0x220)),
            &[0x100..0x120, 0x200..0x220],
            &[]
        )
        .is_none());
        assert!(references_clear(
            &normal,
            &kernel,
            core::slice::from_ref(&(0x200..0x220)),
            core::slice::from_ref(&(0x100..0x120)),
            &[]
        )
        .is_none());
    }

    #[test]
    fn bound_call_retargeting_retires_entry_without_hiding_other_callers() {
        let mut normal = alloc::vec![0xff; 0x800];
        let kernel = alloc::vec![0xff; crate::image::KERNEL_LEN];
        // Complete native JSR instruction whose owner will retarget its operand.
        normal[0x400..0x404].copy_from_slice(&[0x5e, 0x41, 0x01, 0x00]);
        let retired = core::slice::from_ref(&(0x100..0x120));
        assert!(references_clear(&normal, &kernel, retired, retired, &[]).is_none());
        let replaced = [0x100..0x120, 0x400..0x404];
        assert!(references_clear(&normal, &kernel, retired, &replaced, &[]).is_some());
        normal[0x500..0x504].copy_from_slice(&[0x5e, 0x41, 0x01, 0x00]);
        assert!(references_clear(&normal, &kernel, retired, &replaced, &[]).is_none());
        normal[0x500..0x504].fill(0xff);
        // The retained four-byte entry is callable only at its first byte.
        let reject_interiors = core::slice::from_ref(&(0x101..0x120));
        normal[0x500..0x504].copy_from_slice(&[0x5e, 0x41, 0x01, 0x02]);
        assert!(references_clear(&normal, &kernel, reject_interiors, &replaced, &[]).is_none());
    }
}
