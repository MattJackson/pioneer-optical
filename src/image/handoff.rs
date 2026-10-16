//! Signature-derived post-programming Kernel handoff. Addresses are operands,
//! never model, SAT or firmware-version rules. This checks entry compatibility,
//! not arbitrary semantic equivalence of two startup implementations.
use super::{KERNEL_BASE, KERNEL_LEN};

/// Kernel replacement cannot establish a supported post-write handoff.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KernelHandoffError {
    /// Installed programming routine is missing, ambiguous or unsupported.
    UnknownInstalled,
    /// Incoming startup sequence is missing, ambiguous or unsupported.
    UnknownTarget,
    /// The installed updater calls a different incoming startup address.
    Mismatch {
        /// Address called by the installed programming routine.
        installed: u32,
        /// Startup entry extracted from the incoming Kernel.
        target: u32,
    },
}

impl core::fmt::Display for KernelHandoffError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnknownInstalled => f.write_str("installed Kernel programming handoff is unsupported or ambiguous; refusing Kernel replacement"),
            Self::UnknownTarget => f.write_str("incoming Kernel startup entry is unsupported or ambiguous; refusing Kernel replacement"),
            Self::Mismatch { installed, target } => write!(f, "Kernel handoff mismatch: installed updater calls {installed:#08x}, incoming Kernel startup is {target:#08x}; refusing Kernel replacement"),
        }
    }
}
impl std::error::Error for KernelHandoffError {}

/// Check the directed installed-updater -> incoming-startup transition.
/// Unknown signatures refuse even when the two bodies happen to be identical.
pub fn check_kernel_handoff(installed: &[u8], target: &[u8]) -> Result<(), KernelHandoffError> {
    let installed = kernel_handoff_entry(installed).ok_or(KernelHandoffError::UnknownInstalled)?;
    let target = kernel_startup_entry(target).ok_or(KernelHandoffError::UnknownTarget)?;
    if installed == target {
        Ok(())
    } else {
        Err(KernelHandoffError::Mismatch { installed, target })
    }
}

fn word(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn unique(values: impl Iterator<Item = u32>) -> Option<u32> {
    let mut value = None;
    for candidate in values {
        if value.is_some_and(|v| v != candidate) {
            return None;
        }
        value = Some(candidate);
    }
    value
}

// Startup preserves caller registers, resets SP, then masks interrupts. The
// newer form clears the update-state bit before that prologue. Recognize both
// push variants without assuming a particular SP value or entry address.
fn prologue(b: &[u8], at: usize) -> bool {
    if b.get(at..at + 4) != Some(&[1, 0, 0x6d, 0xf3]) {
        return false;
    }
    let mut p = at + 4;
    if b.get(p) == Some(&1)
        && matches!(b.get(p + 1), Some(0 | 0x10 | 0x20))
        && b.get(p + 2..p + 4) == Some(&[0x6d, 0xf4])
    {
        p += 4;
    }
    b.get(p..p + 2) == Some(&[0x7a, 7])
        && word(b, p + 2).is_some_and(|sp| sp > 0 && sp <= 0x10000 && sp % 4 == 0)
        && b.get(p + 6..p + 8) == Some(&[4, 0x80])
}

const STATE_CLEAR: &[u8] = &[0x6a, 0x38, 0, 0, 1, 0x44, 0x72, 0x40];

/// Unique supported warm-start entry, extracted from the startup signature.
/// Restrict to the startup area, not incidental prologues elsewhere in code.
pub fn kernel_startup_entry(kernel: &[u8]) -> Option<u32> {
    if kernel.len() != KERNEL_LEN {
        return None;
    }
    let mut hits = (0..0x200).step_by(2).filter_map(|at| {
        let state_clear = kernel.get(at..at + STATE_CLEAR.len()) == Some(STATE_CLEAR)
            && prologue(kernel, at + STATE_CLEAR.len());
        let plain = prologue(kernel, at)
            && !(at >= STATE_CLEAR.len()
                && kernel.get(at - STATE_CLEAR.len()..at) == Some(STATE_CLEAR));
        (state_clear || plain).then_some(KERNEL_BASE + at as u32)
    });
    let first = hits.next()?;
    // Two startup signatures are ambiguous even if their surrounding code agrees.
    hits.next().is_none().then_some(first)
}

/// Restart operand inside a programming routine which the Kernel copies to RAM.
/// The signature binds the RAM-copy source/end/destination, in-range copy helper,
/// interrupt-mask epilogue and absolute restart call/jump. Multiple copied
/// programmers are accepted only when all recognized restart operands agree.
pub fn kernel_handoff_entry(kernel: &[u8]) -> Option<u32> {
    if kernel.len() != KERNEL_LEN {
        return None;
    }
    unique(
        (0..kernel.len().saturating_sub(22))
            .step_by(2)
            .flat_map(|at| {
                let copy = (|| {
                    if kernel.get(at..at + 2) != Some(&[0x7a, 0])
                        || kernel.get(at + 6..at + 8) != Some(&[0x7a, 1])
                        || kernel.get(at + 12..at + 14) != Some(&[0x7a, 2])
                        || kernel[at + 18] != 0x5e
                    {
                        return None;
                    }
                    let start = word(kernel, at + 2)?.checked_sub(KERNEL_BASE)? as usize;
                    let end = word(kernel, at + 8)?.checked_sub(KERNEL_BASE)? as usize;
                    let ram = word(kernel, at + 14)? as usize;
                    let helper =
                        u32::from_be_bytes([0, kernel[at + 19], kernel[at + 20], kernel[at + 21]]);
                    if start >= end
                        || end > kernel.len()
                        || start % 2 != 0
                        || end % 2 != 0
                        || ram == 0
                        || ram % 2 != 0
                        || ram.checked_add(end - start)? > 0x10000
                        || !(KERNEL_BASE..KERNEL_BASE + KERNEL_LEN as u32).contains(&helper)
                    {
                        return None;
                    }
                    Some((start, end))
                })();
                copy.into_iter().flat_map(move |(start, end)| {
                    (start..end.saturating_sub(7))
                        .step_by(2)
                        .filter_map(move |p| {
                            if !(0xf8..=0xfb).contains(&kernel[p])
                                || kernel[p + 1] != 0x80
                                || kernel[p + 2] != 3
                                || kernel[p + 3] != kernel[p] - 0xf0
                            {
                                return None;
                            }
                            let mut call = p + 4;
                            // Some programmers kick a hardware service after masking CCR.
                            if kernel.get(call) == Some(&0xf8)
                                && kernel.get(call + 2) == Some(&0x5d)
                                && kernel.get(call + 3).is_some_and(|r| r & 0x8f == 0)
                            {
                                call += 4;
                            }
                            if call + 4 > end || !matches!(kernel[call], 0x5a | 0x5e) {
                                return None;
                            }
                            let target = u32::from_be_bytes([
                                0,
                                kernel[call + 1],
                                kernel[call + 2],
                                kernel[call + 3],
                            ]);
                            ((KERNEL_BASE..KERNEL_BASE + 0x200).contains(&target)
                                && target % 2 == 0)
                                .then_some(target)
                        })
                })
            }),
    )
}

#[cfg(test)]
#[path = "handoff_tests.rs"]
pub(crate) mod tests;
