//! SAT 1xxx loading/tray input-pin fingerprint.
//!
//! SAT 1xxx firmware reads its tray/loading switches inline — a bit-test or
//! bit-load on the `FF4140xx`–`FF4142xx` loading port — rather than through the
//! wrapped selector predicates the SAT8/SAT9 reader (`initialization`,
//! `loading`) recognizes. Because of that, two SAT1 drives on genuinely
//! different loading hardware (for example BDR-205 `SAT 1014`, which also reads
//! `FF414100`, versus BDR-206 `SAT 1030`, which does not) carried identical
//! values on every other owner and so hashed into one family — a crossflash the
//! drive's own firmware rejects and that leaves the tray inoperable.
//!
//! This owner fingerprints the exact set of loading-port input pins a SAT1
//! Normal reads. Two SAT1 drives that read the same set are crossflash
//! candidates; a different set is different loading hardware and refuses, unless
//! the operator bypasses the family check. A SAT1 image with no loading-port
//! input read reports the empty set, which differs from any set that has one. On
//! every other platform the loading inputs are owned by `initialization`/
//! `loading`, so this owner reports `NotApplicable` and contributes no SAT-only
//! value to those identities.
use super::identity::Domain;
use super::{Assessment, Context, Filter, Finding, Role, Value};
use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::{format, vec, vec::Vec};

/// Owner of the SAT1 loading-input fingerprint.
pub struct Sat1LoadingInput;
/// Registered SAT1 loading-input owner.
pub static FILTER: Sat1LoadingInput = Sat1LoadingInput;

const ID: &str = "sat1-loading-input";

/// Positive-exclusion proof tag for platforms that do not use this owner.
const NON_SAT1_PROOF: u16 = 0x1a71;

/// Loading/tray input-port block on SAT1 (`FF414000`, `FF414100`, `FF414200`).
const PORT_LO: u32 = 0xff41_4000;
const PORT_HI: u32 = 0xff41_4300;

/// Rules declared beside this owner's enforcing code; rendered verbatim by reports.
static RULES: super::Rules = super::Rules {
    description: "Fingerprints the SAT 1xxx loading/tray input pins the firmware reads inline: every bit-test or bit-load on the FF4140xx-FF4142xx loading port, as the sorted set of (port address, operation, bit). It establishes which physical loading-input pins the firmware reads, not the open/closed predicate roles, timing, debounce or output drive. A different pin set is different loading hardware.",
    role: super::Role::Hardware,
    correctability: super::Correctability::Fixed,
    correction: "Never corrected. The SAT1 loading-input pin set must match; a different set is different loading hardware and refuses. Like every hardware value, it is part of the family ID, so a deliberate \"bypass family\" ignores the mismatch. An image with no loading-port read reports the empty set.",
    policies: &[
        super::Policy {
            domains: &[Domain::Sat1],
            text: "SAT1 reads its tray/loading switches inline, not through the SAT8/SAT9 wrapped selector predicates, so the recognized input-pin set is the identity value. Equal set is required; no recognized read is the empty set.",
        },
        super::Policy {
            domains: &[],
            text: "Only SAT 1xxx contributes this field. On every other platform the loading inputs are owned by the initialization and loading filters, so this owner reports a positive exclusion.",
        },
    ],
};

/// A port bit-operation that READS an input: `BTST` (0x73) or `BLD` (0x77).
fn reads_input(op: u8) -> bool {
    op == 0x73 || op == 0x77
}

/// The sorted set of distinct loading-port input bit-reads in `body`, as typed
/// `(address, operation, bit)` sequences. `body` is a decoded SAT1 Normal.
fn loading_input_pins(body: &[u8]) -> Vec<Value> {
    let mut set: BTreeSet<(u32, u8, u8)> = BTreeSet::new();
    let mut at = 0usize;
    while at + 8 <= body.len() {
        // `6a 30 AA AA AA AA OP B0`: a bit operation with 32-bit absolute
        // addressing. OP selects the operation; the high nibble of the final
        // byte is the bit index and the low nibble is zero.
        if body[at] == 0x6a && body[at + 1] == 0x30 {
            let address =
                u32::from_be_bytes([body[at + 2], body[at + 3], body[at + 4], body[at + 5]]);
            let op = body[at + 6];
            let bit_byte = body[at + 7];
            if (PORT_LO..PORT_HI).contains(&address)
                && reads_input(op)
                && bit_byte & 0x0f == 0
                && bit_byte >> 4 <= 7
            {
                set.insert((address, op, bit_byte >> 4));
            }
        }
        at += 2;
    }
    set.into_iter()
        .map(|(address, op, bit)| {
            Value::Sequence(vec![Value::U32(address), Value::U8(op), Value::U8(bit)])
        })
        .collect()
}

impl Filter for Sat1LoadingInput {
    fn id(&self) -> &'static str {
        ID
    }
    fn name(&self) -> &'static str {
        "SAT1 loading input"
    }
    fn rules(&self) -> Option<&'static super::Rules> {
        Some(&RULES)
    }
    fn inspect(&self, context: &Context<'_>) -> Assessment {
        // Only SAT 1xxx uses the inline loading-input reader. Every other
        // platform's loading inputs belong to initialization/loading; report a
        // positive exclusion so the owner's role is stable across platforms
        // without asserting a SAT1 value elsewhere.
        if Domain::from_hardware(context.firmware.hardware) != Some(Domain::Sat1) {
            return Assessment {
                id: ID,
                role: Role::Hardware,
                finding: Finding::NotApplicable {
                    proof: NON_SAT1_PROOF,
                    evidence: String::from(
                        "Loading inputs on non-SAT1 platforms are owned by the initialization and loading filters",
                    ),
                },
                evidence: String::from("non-SAT1 platform; loading inputs owned elsewhere"),
            };
        }
        // An empty set is a positive observation (no loading-port read in this
        // Normal), not a reader miss: it keeps the image's family identity and
        // still differs from any image that does read loading pins.
        let pins = loading_input_pins(context.firmware.normal);
        let count = pins.len();
        Assessment::known(
            ID,
            Role::Hardware,
            Value::Sequence(pins),
            format!(
                "{count} native SAT1 loading-port input bit-read(s) on FF4140xx-FF4142xx, as the sorted (address, operation, bit) set"
            ),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filters::{Comparison, Firmware};

    /// Emit `6a 30 <addr:BE32> <op> <bit<<4>` at `out`'s end.
    fn bitop(out: &mut Vec<u8>, address: u32, op: u8, bit: u8) {
        out.extend([0x6a, 0x30]);
        out.extend(address.to_be_bytes());
        out.extend([op, bit << 4]);
    }

    fn sat1(normal: &[u8]) -> Context<'_> {
        Context::new(Firmware {
            hardware: "SAT 1014",
            normal,
            kernel: None,
        })
    }

    #[test]
    fn extracts_sorted_distinct_loading_input_pins() {
        let mut body = vec![0u8; 16];
        bitop(&mut body, 0xff41_4100, 0x77, 3); // BLD #3,@FF414100
        bitop(&mut body, 0xff41_4000, 0x73, 4); // BTST #4,@FF414000
        bitop(&mut body, 0xff41_4000, 0x73, 4); // duplicate collapses
        let pins = loading_input_pins(&body);
        assert_eq!(
            pins,
            vec![
                Value::Sequence(vec![Value::U32(0xff41_4000), Value::U8(0x73), Value::U8(4)]),
                Value::Sequence(vec![Value::U32(0xff41_4100), Value::U8(0x77), Value::U8(3)]),
            ]
        );
    }

    #[test]
    fn ignores_writes_and_out_of_range_ports() {
        let mut body = vec![0u8; 8];
        bitop(&mut body, 0xff41_4000, 0x70, 1); // BSET (write) ignored
        bitop(&mut body, 0xff41_4000, 0x72, 1); // BCLR (write) ignored
        bitop(&mut body, 0xff40_0000, 0x73, 1); // out of port range ignored
        bitop(&mut body, 0xff41_4300, 0x73, 1); // above port range ignored
        assert!(loading_input_pins(&body).is_empty());
    }

    #[test]
    fn different_input_sets_refuse_same_set_matches() {
        // BDR-206-like: FF414000 only. BDR-205-like: adds FF414100.
        let mut a = vec![0u8; 8];
        bitop(&mut a, 0xff41_4000, 0x73, 4);
        bitop(&mut a, 0xff41_4000, 0x77, 3);
        let mut b = a.clone();
        bitop(&mut b, 0xff41_4100, 0x77, 3);

        let ia = FILTER.inspect(&sat1(&a));
        let ib = FILTER.inspect(&sat1(&b));
        assert!(matches!(ia.finding, Finding::Known(_)));
        assert_eq!(FILTER.compare(&ia, &ia), Comparison::Match);
        assert_eq!(FILTER.compare(&ia, &ib), Comparison::Different);
    }

    #[test]
    fn sat1_without_loading_reads_is_the_empty_set() {
        let empty = FILTER.inspect(&sat1(&[0u8; 64]));
        assert_eq!(empty.role, Role::Hardware);
        assert_eq!(empty.finding, Finding::Known(Value::Sequence(vec![])));
        let mut body = vec![0u8; 8];
        bitop(&mut body, 0xff41_4000, 0x73, 4);
        let read = FILTER.inspect(&sat1(&body));
        assert_eq!(FILTER.compare(&empty, &read), Comparison::Different);
    }

    #[test]
    fn non_sat1_is_not_applicable_with_stable_hardware_role() {
        let body = vec![0u8; 8];
        let assessment = FILTER.inspect(&Context::new(Firmware {
            hardware: "SAT 8600",
            normal: &body,
            kernel: None,
        }));
        assert_eq!(assessment.role, Role::Hardware);
        assert!(matches!(
            assessment.finding,
            Finding::NotApplicable {
                proof: NON_SAT1_PROOF,
                ..
            }
        ));
    }
}
