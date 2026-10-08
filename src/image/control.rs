//! Content-derived update-entry control key recognition.

const ACCEPT_COMPARE: [u8; 7] = [0x7a, 0x20, 0x9a, 0x78, 0x23, 0x61, 0x47];
const ACCEPT_BRANCH_END: usize = 8;
const KEY_COMPARE: [u8; 2] = [0x7a, 0x20];
const REJECT_BRANCH: [u8; 2] = [0x58, 0x60];
const KEY_OFFSET: usize = 2;
const KEY_LEN: usize = 4;
const REJECT_OFFSET: usize = KEY_OFFSET + KEY_LEN;
const REJECT_BRANCH_END: usize = 10;

/// Extract the four on-wire control-key bytes from a decoded Normal's
/// recognized update-entry comparison arms. Unknown or ambiguous code returns
/// `None`; there is no model lookup or default-key fallback.
pub fn receiver_control_key(body: &[u8]) -> Option<[u8; KEY_LEN]> {
    let mut found = None;
    for (i, candidate) in body.windows(ACCEPT_BRANCH_END).enumerate() {
        if candidate[..ACCEPT_COMPARE.len()] != ACCEPT_COMPARE {
            continue;
        }
        let displacement = candidate[ACCEPT_BRANCH_END - 1] as i8;
        if displacement < REJECT_BRANCH_END as i8 {
            continue;
        }
        let accept = i
            .checked_add(ACCEPT_BRANCH_END)?
            .checked_add(displacement as usize)?;
        let compare = accept.checked_sub(REJECT_BRANCH_END)?;
        let Some(second) = body.get(compare..accept) else {
            continue;
        };
        if second[..KEY_OFFSET] != KEY_COMPARE
            || second[REJECT_OFFSET..REJECT_OFFSET + REJECT_BRANCH.len()] != REJECT_BRANCH
        {
            continue;
        }
        let key = second[KEY_OFFSET..KEY_OFFSET + KEY_LEN].try_into().ok()?;
        if found.replace(key).is_some() {
            return None;
        }
    }
    found
}

#[cfg(test)]
#[path = "control_tests.rs"]
mod tests;
