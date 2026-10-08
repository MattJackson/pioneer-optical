//! Content-derived update-entry control key recognition.

const ACCEPT_COMPARE: [u8; 7] = [0x7a, 0x20, 0x9a, 0x78, 0x23, 0x61, 0x47];
const ACCEPT_BRANCH_END: usize = 8;
const KEY_COMPARE: [u8; 2] = [0x7a, 0x20];
const REJECT_BRANCH: [u8; 2] = [0x58, 0x60];
const KEY_OFFSET: usize = 2;
const KEY_LEN: usize = 4;
const REJECT_OFFSET: usize = KEY_OFFSET + KEY_LEN;
const REJECT_BRANCH_END: usize = 10;
const SHORT_REJECT_BRANCH_END: usize = 8;
const SHORT_REJECT_BRANCH: u8 = 0x46;

#[path = "control_descriptor.rs"]
mod descriptor;

/// Control data checked by a recognized Normal update-entry handler.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReceiverControl {
    /// Only the 16-byte resident descriptor is checked; remaining bytes are unused.
    DescriptorOnly,
    /// The descriptor and these four bytes at control offset 16 are checked.
    Key([u8; KEY_LEN]),
}

/// Recognize the update-entry control requirement from installed Normal code.
/// Missing, truncated and ambiguous implementations return `None`.
/// This establishes entry control only, not a complete transfer protocol.
pub fn receiver_control(body: &[u8]) -> Option<ReceiverControl> {
    let mut matches = keys(body)
        .map(ReceiverControl::Key)
        .chain(descriptor::matches(body).map(|()| ReceiverControl::DescriptorOnly));
    let first = matches.next()?;
    matches.next().is_none().then_some(first)
}

fn keys(body: &[u8]) -> impl Iterator<Item = [u8; KEY_LEN]> + '_ {
    body.windows(ACCEPT_BRANCH_END)
        .enumerate()
        .step_by(2)
        .filter_map(|(i, candidate)| {
            if candidate[..ACCEPT_COMPARE.len()] != ACCEPT_COMPARE {
                return None;
            }
            let displacement = candidate[ACCEPT_BRANCH_END - 1] as i8;
            if displacement < SHORT_REJECT_BRANCH_END as i8 {
                return None;
            }
            let accept = i
                .checked_add(ACCEPT_BRANCH_END)?
                .checked_add(displacement as usize)?;
            for length in [SHORT_REJECT_BRANCH_END, REJECT_BRANCH_END] {
                if displacement < length as i8 {
                    continue;
                }
                let compare = accept.checked_sub(length)?;
                let Some(second) = body.get(compare..accept) else {
                    continue;
                };
                let reject = if length == SHORT_REJECT_BRANCH_END {
                    second[REJECT_OFFSET] == SHORT_REJECT_BRANCH
                } else {
                    second[REJECT_OFFSET..REJECT_OFFSET + REJECT_BRANCH.len()] == REJECT_BRANCH
                };
                if second[..KEY_OFFSET] == KEY_COMPARE && reject {
                    return second[KEY_OFFSET..KEY_OFFSET + KEY_LEN].try_into().ok();
                }
            }
            None
        })
}

#[cfg(test)]
#[path = "control_tests.rs"]
mod tests;
