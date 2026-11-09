//! Relocation-normalized digest of the capacity discriminator, proved from the
//! two images alone with `h8-asm` (no live query, no hand-rolled decoding).
//!
//! The discriminator does not run in place: the C initializer copies a block
//! out of Normal into low RAM, and the versioned contract calls it there. So we
//! first resolve that copy generically — `coverage::copied_checksum::relocated`
//! recognizes the bound C-startup memcpy (the `0x1058dc` ABI) and returns the
//! Normal source and its RAM destination — then rebuild the RAM image where the
//! routine actually executes.
//!
//! On that image `h8-asm` bounds the discriminator by control-flow reachability
//! (not a byte-length guess) and we digest the transitive closure of the
//! routines it *calls within the copied block* (the query plus its builder and
//! any other relocated callee). Calls that leave the block — the resident OEM
//! service — stay as retained absolute operands, not digested bodies, exactly
//! as the capacity relation's external contract allows. `relocate` normalizes
//! PC-relative control flow and refuses an absolute branch into a routine;
//! every other operand, including each absolute in-block call target, is kept.
//! A routine that decodes differently, calls a different helper, or reads a
//! different absolute datum therefore digests differently and never matches —
//! the proof can only under-accept, never admit two programs that could select
//! differently.
use crate::image::layout::Observation;
use crate::startup::coverage::copied_checksum;
use alloc::collections::BTreeSet;
use alloc::{vec, vec::Vec};
use core::ops::Range;
use sha2::{Digest, Sha256};

const TARGET: h8_asm::Target = h8_asm::Target::H8S2000;
const MODE: h8_asm::Mode = h8_asm::Mode::Advanced;

/// Bound one routine entered at `at`: require fully contiguous control-flow
/// coverage from the entry (a gap would be data we cannot equate), returning
/// the `[at, end)` byte range it occupies.
fn routine(image: &[u8], at: u32) -> Option<Range<usize>> {
    let starts = h8_asm::analysis::reachable(image, at, TARGET, MODE).ok()?;
    let mut next = at;
    for &start in &starts {
        if start != next {
            return None;
        }
        let len = h8_asm::isa::insn_len(image.get(start as usize..)?, TARGET, MODE)?;
        next = start.checked_add(len as u32)?;
    }
    Some(at as usize..next as usize)
}

/// Fingerprint the capacity discriminator called at `entry` (a RAM address).
/// `None` — refuse — unless the discriminator's copy into RAM is generically
/// recognized and every routine it calls within that copied block decodes as a
/// contiguous control-flow region with no embedded data.
pub(super) fn digest(normal: &[u8], entry: u32) -> Option<[u8; 32]> {
    // Resolve the C-startup memcpy that relocates the discriminator into RAM.
    let Observation::Known(relocation) = copied_checksum::relocated(normal, entry, 1) else {
        return None;
    };
    let source = normal.get(relocation.source.clone())?;
    let destination = relocation.destination;
    // Rebuild the RAM view: the verbatim copied block sits at its destination,
    // so h8-asm resolves the routine's own PC-relative and in-block addresses.
    let mut image = vec![0u8; destination as usize];
    image.extend_from_slice(source);
    let block = destination..destination.checked_add(source.len() as u32)?;
    closure_digest(&image, entry, block)
}

/// Digest the transitive closure of routines called within `block`, starting at
/// `entry`. The RAM-addressed `image` holds the verbatim copied block at its
/// destination so each routine decodes where it executes. `None` — refuse —
/// unless `entry` is in the block and every reached routine decodes as one
/// contiguous control-flow region wholly inside the block. Calls that leave the
/// block (the resident OEM service) are kept as retained absolute operands.
fn closure_digest(image: &[u8], entry: u32, block: Range<u32>) -> Option<[u8; 32]> {
    if !block.contains(&entry) {
        return None;
    }
    let mut seen = BTreeSet::new();
    let mut pending = vec![entry];
    let mut routines: Vec<(u32, Vec<u8>)> = Vec::new();
    while let Some(at) = pending.pop() {
        if !seen.insert(at) {
            continue;
        }
        if !block.contains(&at) {
            return None;
        }
        let span = routine(image, at)?;
        if span.end > block.end as usize {
            return None;
        }
        let bytes = image.get(span.clone())?;
        // Normalize to a canonical base: PC-relative branches normalize; an
        // absolute internal branch refuses; absolute operands are retained.
        let canonical = h8_asm::relocate::relocate(bytes, at, 0, TARGET, MODE).ok()?;
        for xref in h8_asm::analysis::xrefs(image, span, TARGET, MODE).ok()? {
            if xref.kind == h8_asm::analysis::XrefKind::Call {
                if let Some(target) = xref.to {
                    if block.contains(&target) {
                        pending.push(target);
                    }
                }
            }
        }
        routines.push((at, canonical.bytes));
    }

    // Order by block-relative entry so the same block at a different RAM base
    // still digests identically through the normalized bodies.
    routines.sort_unstable_by_key(|(at, _)| *at);
    let mut hash = Sha256::new();
    hash.update((routines.len() as u32).to_be_bytes());
    for (at, bytes) in &routines {
        hash.update(at.checked_sub(block.start)?.to_be_bytes());
        hash.update((bytes.len() as u32).to_be_bytes());
        hash.update(bytes);
    }
    Some(hash.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    // JSR @aa:24 to `target`.
    fn jsr(target: u32) -> [u8; 4] {
        let b = target.to_be_bytes();
        [0x5e, b[1], b[2], b[3]]
    }
    const RTS: [u8; 2] = [0x54, 0x70];

    /// A RAM image with a query at 0x600 that calls an in-block builder at 0x640
    /// and an out-of-block resident service at 0x107c72, each ending in RTS.
    fn ram() -> (Vec<u8>, Range<u32>) {
        let mut image = vec![0u8; 0x700];
        // query @0x600: JSR builder; JSR resident; RTS
        image[0x600..0x604].copy_from_slice(&jsr(0x640));
        image[0x604..0x608].copy_from_slice(&jsr(0x107c72));
        image[0x608..0x60a].copy_from_slice(&RTS);
        // builder @0x640: RTS
        image[0x640..0x642].copy_from_slice(&RTS);
        (image, 0x5f0..0x680)
    }

    #[test]
    fn identical_discriminators_digest_equally_and_follow_in_block_callees() {
        let (image, block) = ram();
        let a = closure_digest(&image, 0x600, block.clone()).unwrap();
        // Same bytes digest the same; a second call is deterministic.
        assert_eq!(a, closure_digest(&image, 0x600, block.clone()).unwrap());
        // Bytes outside both reached routines do not affect the proof: the
        // digest scopes to the discriminator closure, not the whole block.
        let mut other = image.clone();
        other[0x660] ^= 0xff;
        assert_eq!(closure_digest(&other, 0x600, block.clone()).unwrap(), a);
    }

    #[test]
    fn any_change_inside_the_reached_closure_changes_the_digest() {
        let (image, block) = ram();
        let base = closure_digest(&image, 0x600, block.clone()).unwrap();
        // A changed builder body (in-block callee) must break the relation.
        let mut builder = image.clone();
        builder[0x640] ^= 1;
        assert_ne!(closure_digest(&builder, 0x600, block.clone()), Some(base));
        // A changed resident-service call target must break it too (retained as
        // an absolute operand, not normalized away).
        let mut resident = image.clone();
        resident[0x604..0x608].copy_from_slice(&jsr(0x107c80));
        assert_ne!(closure_digest(&resident, 0x600, block.clone()), Some(base));
    }

    #[test]
    fn an_entry_outside_the_block_refuses() {
        let (image, block) = ram();
        assert_eq!(closure_digest(&image, 0x700, block), None);
    }
}
