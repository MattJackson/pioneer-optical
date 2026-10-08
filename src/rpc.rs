//! Read-only DVD RPC state reported by the drive, not firmware-file metadata.

/// Length of a REPORT KEY RPC-state response.
pub const RESPONSE_LEN: usize = 8;
/// REPORT KEY format 08, requesting RPC state without changing it.
pub const fn report_key() -> [u8; 12] {
    [0xa4, 0, 0, 0, 0, 0, 0, 0, 0, RESPONSE_LEN as u8, 0x08, 0]
}

/// Standard RPC fields. Counts are the three-bit host-reported values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct State {
    /// RPC type code. Type zero alone does not establish region-free behavior.
    pub type_code: u8,
    /// Vendor resets remaining, not the number already performed.
    pub vendor_resets_remaining: u8,
    /// User region changes remaining, not the number already performed.
    pub user_changes_remaining: u8,
    /// A zero bit permits the corresponding DVD region (bit zero = region 1).
    pub prohibited_regions: u8,
    /// Reported RPC scheme.
    pub scheme: u8,
}
impl State {
    /// Decode a complete RPC response with its declared length checked.
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        let b = bytes.get(..RESPONSE_LEN)?;
        if u16::from_be_bytes([b[0], b[1]]) != (RESPONSE_LEN - 2) as u16 {
            return None;
        }
        Some(Self {
            type_code: b[4] >> 6,
            vendor_resets_remaining: (b[4] >> 3) & 7,
            user_changes_remaining: b[4] & 7,
            prohibited_regions: b[5],
            scheme: b[6],
        })
    }
    /// Whether a numbered DVD region is allowed by the reported mask.
    /// An unset FF mask permits no region; it is not “region free.”
    pub fn allows(self, region: u8) -> bool {
        (1..=8).contains(&region) && self.prohibited_regions & (1 << (region - 1)) == 0
    }
}

#[cfg(test)]
#[path = "rpc_tests.rs"]
mod tests;
