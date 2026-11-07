//! Bounded SAT1 output corrections over complete native templates.
use super::*;
#[derive(Clone, Copy)]
pub(super) enum Patch {
    Byte(usize),
    LeafCall(usize),
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Change {
    offset: usize,
    original: Vec<u8>,
    swapped: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Binding {
    start: usize,
    end: usize,
    native: Phase,
    observed: Phase,
    changes: Vec<Change>,
    operand_only: bool,
}
fn binding(t: &Template, normal: &[u8], at: usize) -> Option<Binding> {
    let candidate = normal.get(at..at.checked_add(t.bytes.len())?)?;
    let mut changes = Vec::new();
    for &p in t.patches {
        match p {
            Patch::Byte(offset) => changes.push(Change {
                offset: at + offset,
                original: alloc::vec![t.bytes[offset]],
                swapped: alloc::vec![t.bytes[offset] ^ 1],
            }),
            Patch::LeafCall(offset) => {
                let leaf = at.checked_sub(6)?;
                if normal.get(leaf..at)? != [0x6a, 0x88, 0xf9, 9, 0x54, 0x70] {
                    return None;
                }
                let address = u32::try_from(0x410000usize.checked_add(leaf)?).ok()?;
                if address > 0xffffff {
                    return None;
                }
                let encoded = address.to_be_bytes();
                changes.push(Change {
                    offset: at + offset,
                    original: alloc::vec![0x5e, encoded[1], encoded[2], encoded[3]],
                    swapped: alloc::vec![0x6a, 0x88, 0xf9, 8],
                });
            }
        }
    }
    if changes.is_empty() {
        return None;
    }
    changes.sort_by_key(|c| c.offset);
    if changes
        .windows(2)
        .any(|w| w[0].offset + w[0].original.len() > w[1].offset)
    {
        return None;
    }
    let flipped = normal.get(changes[0].offset..changes[0].offset + changes[0].original.len())?
        != changes[0].original;
    let mut canonical = candidate.to_vec();
    for c in &changes {
        let expected = if flipped { &c.swapped } else { &c.original };
        if normal.get(c.offset..c.offset + expected.len())? != expected {
            return None;
        }
        canonical[c.offset - at..c.offset - at + c.original.len()].copy_from_slice(&c.original);
    }
    if !template_matches_bytes(t, normal, at, &canonical) {
        return None;
    }
    let native = Phase {
        assignment: t.assignment,
        interface: t.interface,
    };
    let assignment = if flipped {
        match t.assignment {
            Assignment::Direct => Assignment::Swapped,
            Assignment::Swapped => Assignment::Direct,
        }
    } else {
        t.assignment
    };
    Some(Binding {
        start: at,
        end: at + t.bytes.len(),
        native,
        observed: Phase {
            assignment,
            interface: t.interface,
        },
        changes,
        operand_only: t.patches.iter().all(|patch| matches!(patch, Patch::Byte(_))),
    })
}
fn stored(normal: &[u8], regions: &[&[u8]], at: usize, len: usize) -> bool {
    regions.iter().any(|region| {
        let start = region.as_ptr() as usize - normal.as_ptr() as usize;
        at >= start
            && at
                .checked_add(len)
                .is_some_and(|end| end <= start + region.len())
    })
}

pub(super) fn observe(t: &Template, normal: &[u8], at: usize, regions: &[&[u8]]) -> Option<Phase> {
    if !stored(normal, regions, at, t.bytes.len()) {
        return None;
    }
    normal.get(at..at.checked_add(t.bytes.len())?)?;
    if let Some(b) = binding(t, normal, at) {
        if !t.requires_leaf
            || at
                .checked_sub(6)
                .is_some_and(|leaf| stored(normal, regions, leaf, 6))
        {
            return Some(b.observed);
        }
    }
    // Keep recognition of original variants with a non-adjacent leaf. Those
    // variants cannot be corrected without an independently reversible binding.
    let leaf_stored = !t.requires_leaf
        || t.relocations
            .iter()
            .filter(|r| matches!(r.kind, RelocationKind::Call))
            .all(|r| {
                integer(&normal[at + r.start..at + r.end])
                    .checked_sub(0x410000)
                    .is_some_and(|leaf| stored(normal, regions, leaf as usize, 6))
            });
    (leaf_stored && template_matches(t, normal, at)).then_some(Phase {
        assignment: t.assignment,
        interface: t.interface,
    })
}
fn bindings(normal: &[u8]) -> Option<Vec<Binding>> {
    let regions = crate::image::regions(normal)?;
    let mut result = Vec::new();
    for region in regions.stored {
        let start = region.as_ptr() as usize - normal.as_ptr() as usize;
        let end = start + region.len();
        for t in templates::TEMPLATES {
            let prefix = [Some(t.bytes[0]), Some(t.bytes[1])];
            for at in crate::filters::phase::bundle::sites(normal, &[region], &prefix) {
                if (t.requires_leaf && at - start < 6) || at + t.bytes.len() > end {
                    continue;
                }
                if let Some(b) = binding(t, normal, at) {
                    if !result.contains(&b) {
                        result.push(b);
                    }
                }
            }
        }
    }
    Some(result)
}
pub(super) fn correct(normal: &[u8], target: Assignment) -> Result<Vec<u8>, CorrectionError> {
    let before = bindings(normal).ok_or(CorrectionError::Unresolved)?;
    if before.len() != 1 {
        return Err(CorrectionError::Unresolved);
    }
    let b = &before[0];
    if !matches!(discover(normal),Observation::Known(p)if p==b.observed) {
        return Err(CorrectionError::Unresolved);
    }
    if target == b.observed.assignment {
        return Ok(normal.to_vec());
    }
    // LeafCall recognizes both the native JSR and the previously emitted inline
    // MOV. Rewriting between them changes call/return latency and temporary
    // stack effects. Output/register equivalence alone does not establish that
    // this preserves execution, so neither direction is an authorized edit.
    if !b.operand_only {
        return Err(CorrectionError::Unresolved);
    }
    let mut output = normal.to_vec();
    for c in &b.changes {
        let replacement = if target == b.native.assignment {
            &c.original
        } else {
            &c.swapped
        };
        output[c.offset..c.offset + replacement.len()].copy_from_slice(replacement);
    }
    let mut expected = b.clone();
    expected.observed.assignment = target;
    if bindings(&output).as_deref() != Some(&[expected])
        || !matches!(discover(&output),Observation::Known(p)if p.assignment==target&&p.interface==b.native.interface)
    {
        return Err(CorrectionError::VerificationFailed);
    }
    Ok(output)
}

#[cfg(test)]
mod tests;
