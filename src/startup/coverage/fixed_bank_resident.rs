//! Finite fixed-bank Normal / resident Kernel predicate preservation.
//!
//! This binds local header, flag and conditional image-validation predicates.
//! It does not prove global startup termination, host READY, or the absence of
//! parameter requirements. External callees retain their original semantics.

use super::sinks::{self, Certificate};
use crate::image::layout::{self, H8ReaderComponent, Observation};
use crate::startup::bank::{self, Addresses, Contract, Validation};
use alloc::{vec, vec::Vec};
use core::ops::Range;

#[path = "fixed_bank_resident_shapes.rs"]
mod shapes;
#[cfg(test)]
#[path = "fixed_bank_resident_tests.rs"]
mod tests;

const NORMAL_BASE: u32 = 0x410000;
const KERNEL_BASE: u32 = 0x400000;

struct Shape {
    start: usize,
    bytes: &'static [u8],
}
impl Shape {
    fn span(&self) -> Range<usize> {
        self.start..self.start + self.bytes.len()
    }
    fn matches(&self, image: &[u8]) -> bool {
        image.get(self.span()) == Some(self.bytes)
    }
}

struct Form {
    shapes: &'static [Shape],
    wrapper: usize,
    wrapper_calls: [usize; 3],
    helper: usize,
    console_call: usize,
    console_field: usize,
    initializer: usize,
    initializer_calls: [usize; 2],
}
const FORMS: &[Form] = &[
    Form {
        shapes: shapes::NORMAL_130,
        wrapper: 0x6fbfc,
        wrapper_calls: [0x5d850, 0x1263c2, 0x1263e4],
        helper: 0x1263ba,
        console_call: 0x6e1a0,
        console_field: 0x2182ec,
        initializer: 0x1d8846,
        initializer_calls: [0x799d6, 0x1d8d2c],
    },
    Form {
        shapes: shapes::NORMAL_135,
        wrapper: 0x703c8,
        wrapper_calls: [0x5db6e, 0x127332, 0x127354],
        helper: 0x12732a,
        console_call: 0x6e96c,
        console_field: 0x219624,
        initializer: 0x1d9a18,
        initializer_calls: [0x7a1a2, 0x1d9efe],
    },
];

/// Bound resident predicates and immutable paired image authority.
///
/// The incoming Kernel is protected in full, including opaque callees. The
/// checksum word itself belongs to final integrity repair, not this certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResidentValidation {
    /// Full Kernel protection plus named native recognition evidence.
    pub kernel_spans: Vec<Range<usize>>,
    /// Resident descriptor and destination compared against Normal metadata.
    pub identity_spans: Vec<Range<usize>>,
    /// Complete bound Normal evidence and consumed metadata.
    pub normal_spans: Vec<Range<usize>>,
    /// Normal big-endian length word.
    pub image_length_field: usize,
    /// Runtime entry of the copied additive checksum body.
    pub checksum_entry: u32,
    /// Native rejection continuation; its eventual host behavior is opaque.
    pub reject_entry: u32,
    /// RAM address and bit gating the native checksum call.
    pub conditional_state: (u32, u8),
}

fn word(image: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(image.get(at..at + 4)?.try_into().ok()?))
}

fn form(normal: &[u8]) -> Option<&'static Form> {
    let mut found = FORMS
        .iter()
        .filter(|f| f.shapes.iter().all(|s| s.matches(normal)));
    let result = found.next()?;
    found.next().is_none().then_some(result)
}

fn paired_header(normal: &[u8], kernel: &[u8]) -> Option<()> {
    if normal.get(..16)? != kernel.get(0x6ae4..0x6af4)?
        || normal.get(0x18..0x20)? != kernel.get(0x1008..0x1010)?
    {
        return None;
    }
    let length = word(normal, 0x14)? as usize;
    (length == normal.len() && length <= 0x3c0000 && length & 3 == 0).then_some(())
}

/// Recheck the final native representation after the existing integrity stage.
/// Discovery deliberately permits a stale checksum while edits are composed.
/// Authentication/emission under the actual receiver remains a separate duty.
impl ResidentValidation {
    /// Check the final paired header, length and native additive checksum.
    pub fn final_integrity(&self, normal: &[u8], kernel: &[u8]) -> bool {
        if kernel.len() != 0x10000 || paired_header(normal, kernel).is_none() {
            return false;
        }
        kernel
            .chunks_exact(4)
            .chain(normal.chunks_exact(4))
            .fold(0u32, |sum, bytes| {
                sum.wrapping_add(u32::from_be_bytes(bytes.try_into().unwrap()))
            })
            == 0
    }
}

fn overlap(a: &Range<usize>, b: &Range<usize>) -> bool {
    a.start < b.end && b.start < a.end
}

// Arguments are decoded from the complete exact warm-root shape, rather than
// assuming an unavailable ROM memcpy. All writes below precede validation.
fn copy_contract(kernel: &[u8]) -> Option<()> {
    let source = word(kernel, 0x180)?.checked_sub(KERNEL_BASE)? as usize
        ..word(kernel, 0x186)?.checked_sub(KERNEL_BASE)? as usize;
    let destination = word(kernel, 0x18c)? as usize;
    let end = destination.checked_add(source.end.checked_sub(source.start)?)?;
    let checksum = destination.checked_add(0x10d2usize.checked_sub(source.start)?)?;
    if source != (0x1024..0x134a)
        || (destination..end) != (0x190..0x4b6)
        || checksum != 0x23e
        || checksum.checked_add(0x1100 - 0x10d2)? > end
    {
        return None;
    }
    let mut writes = Vec::new();
    // Three earlier copies and two earlier clears cannot replace the final
    // checksum producer. No copy/clear instructions follow it before the call.
    for (start, finish, target) in [
        (0x11a, 0x120, 0x126),
        (0x134, 0x13a, 0x140),
        (0x15a, 0x160, 0x166),
    ] {
        let length = word(kernel, finish)?.checked_sub(word(kernel, start)?)? as usize;
        let target = word(kernel, target)? as usize;
        writes.push(target..target.checked_add(length)?);
    }
    for (start, finish) in [(0x148, 0x14e), (0x16e, 0x174)] {
        writes.push(word(kernel, start)? as usize..word(kernel, finish)? as usize);
    }
    if writes
        .iter()
        .any(|r| r.start > r.end || overlap(r, &(destination..end)))
    {
        return None;
    }
    // The held root has no later copy/clear call; verify its complete bytes
    // through the checksum call (including opaque initialization calls).
    shapes::KERNEL
        .iter()
        .all(|s| s.matches(kernel))
        .then_some(())
}

// Conservative instruction-shaped JSR/JMP, BSR, and aligned address-literal
// census. No operand exclusions. Branches into Normal scopes are separately
// checked by the unchanged closed_entries scanner.
fn kernel_census(kernel: &[u8]) -> Option<()> {
    for (target, absolute, relative) in [
        (0x400252u32, &[0x1c0, 0x1de][..], &[0x20e, 0x234, 0x23e][..]),
        (0x400466, &[0xa14, 0x5638][..], &[][..]),
        (0x400478, &[0xa1a, 0x563e][..], &[][..]),
    ] {
        let mut abs = Vec::new();
        let mut rel = Vec::new();
        for at in (0..kernel.len().saturating_sub(1)).step_by(2) {
            let b = &kernel[at..];
            if b.len() >= 4 && word(kernel, at) == Some(target) {
                return None;
            }
            if b.len() >= 4
                && (b[0] == 0x5e || b[0] == 0x5a)
                && b[1..4] == target.to_be_bytes()[1..]
            {
                if b[0] != 0x5e {
                    return None;
                }
                abs.push(at);
            }
            let reference = if b[0] == 0x55 {
                Some((2, b[1] as i8 as isize))
            } else if b.len() >= 4 && b[..2] == [0x5c, 0] {
                Some((4, i16::from_be_bytes([b[2], b[3]]) as isize))
            } else {
                None
            };
            if reference.is_some_and(|(length, delta)| {
                (KERNEL_BASE as usize + at + length).checked_add_signed(delta)
                    == Some(target as usize)
            }) {
                rel.push(at);
            }
        }
        if abs != absolute || rel != relative {
            return None;
        }
    }
    Some(())
}

/// Bind one complete supplied Normal form with its exact resident predicate.
/// Unrecognized, ambiguous, missing and truncated forms refuse. This adds no
/// parameter words and does not alter the independent modern sink recognizer.
pub fn discover(normal: &[u8], kernel: &[u8]) -> Option<(Certificate, ResidentValidation)> {
    if kernel.len() != 0x10000 || !shapes::KERNEL.iter().all(|s| s.matches(kernel)) {
        return None;
    }
    let f = form(normal)?;
    paired_header(normal, kernel)?;
    copy_contract(kernel)?;
    kernel_census(kernel)?;
    if bank::analyze(normal)?
        != (Contract {
            magic: 0xfedc4321,
            addresses: Addresses::Fixed([0x7dfffa, 0x7efffa]),
            validation: Validation::InitializeAndSelect,
        })
    {
        return None;
    }
    let Observation::Known(reader) = layout::discover_h8_reader(normal, None) else {
        return None;
    };
    if reader.component != H8ReaderComponent::Normal {
        return None;
    }
    if sinks::calls(normal, 0x400a1a)? != [f.wrapper]
        || sinks::calls(normal, NORMAL_BASE + f.wrapper as u32)? != f.wrapper_calls
        || sinks::calls(normal, NORMAL_BASE + f.helper as u32)? != [f.console_call]
        || sinks::calls(normal, NORMAL_BASE + f.initializer as u32)? != f.initializer_calls
    {
        return None;
    }
    let console = sinks::console(normal, f.console_call, NORMAL_BASE + f.helper as u32)?;
    if word(normal, f.console_field)? != NORMAL_BASE + console.first()?.start as u32 {
        return None;
    }
    let host = sinks::write_buffer(normal, f.wrapper_calls[0])?;
    let host_entry = host.instructions.first()?.start;
    let scopes = vec![
        (console[0].clone(), vec![f.console_field]),
        (f.helper..f.helper + 18, vec![f.console_call]),
        (f.wrapper..f.wrapper + 6, f.wrapper_calls.to_vec()),
        (f.wrapper_calls[2] - 2..f.wrapper_calls[2] + 4, vec![]),
        (
            host_entry..host.instructions.last()?.end,
            vec![host.tables.last()?.start + 0x24],
        ),
        (
            f.initializer..f.initializer + 98,
            f.initializer_calls.to_vec(),
        ),
    ];
    sinks::closed_entries(normal, &scopes)?;
    let mut protected = vec![0..0x10, 0x14..0x20];
    protected.extend(f.shapes.iter().map(Shape::span));
    protected.extend(f.initializer_calls.iter().map(|&at| at..at + 4));
    for function in reader.functions {
        let at = function.address.checked_sub(NORMAL_BASE)? as usize;
        let end = at.checked_add(function.bytes)?;
        normal.get(at..end)?;
        protected.push(at..end);
    }
    let mut entries = vec![
        NORMAL_BASE + f.helper as u32,
        NORMAL_BASE + f.wrapper as u32,
        NORMAL_BASE + console[0].start as u32,
        NORMAL_BASE + host_entry as u32,
    ];
    protected.extend(console);
    protected.extend(host.tables);
    protected.extend(host.instructions);
    // Shapes and their installer edges must be stored native bytes, never
    // coincidental bytes inside a compressed stream.
    let regions = crate::image::regions(normal)?;
    if protected.iter().any(|span| {
        !regions.stored.iter().any(|bytes| {
            let start = bytes.as_ptr() as usize - normal.as_ptr() as usize;
            span.start >= start && span.end <= start + bytes.len()
        })
    }) {
        return None;
    }
    protected.sort_by_key(|r| (r.start, r.end));
    protected.dedup();
    entries.sort_unstable();
    entries.dedup();
    let certificate = Certificate {
        protected,
        entries,
        generation: None,
    };
    if !certificate.accepts_kernel(kernel) {
        return None;
    }
    let identity_spans = vec![0x6ae4..0x6af4, 0x1008..0x1010];
    let mut kernel_spans = Vec::new();
    kernel_spans.push(0..0x10000);
    kernel_spans.extend(shapes::KERNEL.iter().map(Shape::span));
    kernel_spans.extend(identity_spans.iter().cloned());
    let resident = ResidentValidation {
        kernel_spans,
        identity_spans,
        normal_spans: certificate.protected.clone(),
        image_length_field: 0x14,
        checksum_entry: 0x23e,
        reject_entry: 0x400252,
        conditional_state: (0x144, 5),
    };
    Some((certificate, resident))
}
