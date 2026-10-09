//! Offline settings-format evidence from recognized H8 response builders.
//! Literal stores are code observations, not a claim of unconditional runtime support.
use super::{
    error::{ensure, unique, Context},
    Error, Result,
};

/// A literal response-byte assignment found in a recognized builder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LiteralStore {
    /// Instruction address in the decoded image's address space.
    pub address: u32,
    /// Response byte offset.
    pub offset: u8,
    /// Assigned literal value.
    pub value: u8,
}
/// Evidence for a particular command implementation, retaining source addresses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evidence {
    /// READ BUFFER command handler.
    pub read_buffer: u32,
    /// Start of the recognized F4 response builder.
    pub response_builder: u32,
    /// Next handler, bounding the response builder scan.
    pub next_handler: u32,
    /// Literal assignments; branches and dynamic stores remain unresolved.
    pub literal_stores: Vec<LiteralStore>,
}
fn branch(b: &[u8], at: usize) -> Option<usize> {
    if b.get(at..at + 2)? != [0x58, 0x70] {
        return None;
    }
    (at + 4)
        .checked_add_signed(i16::from_be_bytes(b.get(at + 2..at + 4)?.try_into().ok()?) as isize)
}

fn dispatches(b: &[u8]) -> impl Iterator<Item = usize> + '_ {
    b.windows(14).enumerate().step_by(2).filter_map(|(p, w)| {
        (w[..4] == [0xa1, 0xf1, 0x58, 0x70]
            && w[6..10] == [0xa1, 0xf4, 0x58, 0x70]
            && w[12..14] == [0xa1, 0xa4])
        .then_some(p)
    })
}

fn literals(b: &[u8], buffer_move: u8) -> impl Iterator<Item = (usize, u8, u8)> + '_ {
    b.windows(10)
        .enumerate()
        .step_by(2)
        .filter_map(move |(p, w)| {
            if w[..3] != [0x79, 1, 0]
                || w[6..9] != [0x0f, buffer_move, 0x5d]
                || !matches!(w[9], 0x40 | 0x50 | 0x60)
            {
                return None;
            }
            let value = match &w[4..6] {
                [0xfa, v] => *v,
                [0x18, 0xaa] => 0,
                _ => return None,
            };
            Some((p, w[3], value))
        })
}

/// Inspect a decoded Normal image at its established runtime base.
/// Unknown/ambiguous layouts return an error, never inferred support or a codec fallback.
pub fn inspect(b: &[u8], base: u32) -> Result<Evidence> {
    let site = super::callbacks::read_buffer_site(b, base)?;
    let start = site
        .main_address
        .checked_sub(base)
        .context("handler below image")? as usize;
    ensure!(start < b.len(), "handler outside image");
    let end = start.saturating_add(4096).min(b.len());
    let candidates: Vec<_> = dispatches(&b[start..end]).map(|p| start + p).collect();
    let p = unique(candidates, "F4 branch")?;
    let stop = branch(b, p + 2).context("invalid following handler branch")?;
    let begin = branch(b, p + 8).context("invalid F4 branch")?;
    if begin >= stop
        || stop > b.len()
        || b.get(begin..begin + 5) != Some(&[0x79, 1, 1, 0, 0x0f])
        || !matches!(b.get(begin + 5), Some(0xc0 | 0xd0 | 0xe0))
    {
        return Err(Error::Unsupported {
            context: "response builder",
        });
    }
    let address = |at: usize| {
        base.checked_add(u32::try_from(at).ok()?)
            .filter(|_| at < b.len())
    };
    let mut evidence = Evidence {
        read_buffer: site.main_address,
        response_builder: address(begin).context("address overflow")?,
        next_handler: base
            .checked_add(u32::try_from(stop)?)
            .context("address overflow")?,
        literal_stores: Vec::new(),
    };
    for (offset, field, value) in literals(&b[begin..stop], b[begin + 5]) {
        evidence.literal_stores.push(LiteralStore {
            address: address(begin + offset).context("address overflow")?,
            offset: field,
            value,
        });
    }
    Ok(evidence)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dispatch_scan_includes_exact_end_and_rejects_truncation() {
        let pattern = [
            0xa1, 0xf1, 0x58, 0x70, 0, 4, 0xa1, 0xf4, 0x58, 0x70, 0, 2, 0xa1, 0xa4,
        ];
        assert_eq!(dispatches(&pattern).collect::<Vec<_>>(), [0]);
        for len in 0..pattern.len() {
            assert_eq!(dispatches(&pattern[..len]).count(), 0);
        }
        let mut bytes = vec![0; 2];
        bytes.extend_from_slice(&pattern);
        assert_eq!(dispatches(&bytes).collect::<Vec<_>>(), [2]);
        bytes.insert(0, 0);
        assert_eq!(dispatches(&bytes).count(), 0);
    }
    #[test]
    fn literal_scan_includes_exact_end_without_reading_next_handler() {
        let bytes = [0, 0, 0x79, 1, 0, 49, 0xfa, 4, 0x0f, 0xd0, 0x5d, 0x60];
        assert_eq!(literals(&bytes, 0xd0).collect::<Vec<_>>(), [(2, 49, 4)]);
        assert_eq!(literals(&bytes[..11], 0xd0).count(), 0);
        assert_eq!(literals(&bytes, 0xe0).count(), 0);
    }
    #[test]
    fn branch_targets_are_bounded_and_signed() {
        assert_eq!(branch(&[0x58, 0x70, 0xff, 0xfc], 0), Some(0));
        assert_eq!(branch(&[0x58, 0x70, 0xff, 0xfb], 0), None);
        assert_eq!(branch(&[0x58, 0x70, 0], 0), None);
        assert_eq!(branch(&[0x58, 0x60, 0, 0], 0), None);
    }
}
