//! Register observations and independently selectable family criteria.
//!
//! Observations describe recognized code, not measured hardware state. The
//! current family policy excludes movement-command bytes from identity.

use super::*;

/// One independently comparable field. Only [`FAMILY_CRITERIA`] define identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum FamilyCriterion {
    /// ASIC/DSP initialization; physical field meaning remains unresolved.
    E436,
    /// ASIC/DSP initialization; physical field meaning remains unresolved.
    E43a,
    /// ASIC/DSP initialization; physical field meaning remains unresolved.
    E43b,
    /// ASIC/DSP initialization; physical field meaning remains unresolved.
    E45b,
    /// ASIC/DSP initialization; physical field meaning remains unresolved.
    E463,
    /// ASIC/DSP initialization; physical field meaning remains unresolved.
    E46a,
    /// ASIC/DSP initialization; not a proven tray/slot selector.
    E46b,
    /// Interrupt configuration; not a proven board identifier.
    Ffc5,
    /// Collimator movement-command high byte; diagnostic only.
    Edcc,
    /// Collimator movement-command low byte; diagnostic only.
    Edcd,
    /// Host-interface initialization; exact bit meanings remain unresolved.
    Fe94,
    /// Host/link configuration; current policy ignores bit 6 only.
    Fec0,
    /// Existing coefficient-row signature and missing-evidence policy.
    Servo,
}

/// All current criteria, in the order used by diagnostic comparisons.
pub const FAMILY_CRITERIA: &[FamilyCriterion] = &[
    FamilyCriterion::E436,
    FamilyCriterion::E43a,
    FamilyCriterion::E43b,
    FamilyCriterion::E45b,
    FamilyCriterion::E463,
    FamilyCriterion::E46a,
    FamilyCriterion::E46b,
    FamilyCriterion::Ffc5,
    FamilyCriterion::Fe94,
    FamilyCriterion::Fec0,
    FamilyCriterion::Servo,
];

impl FamilyCriterion {
    /// Register address, or `None` for the coefficient-row criterion.
    pub fn address(self) -> Option<u16> {
        Some(match self {
            Self::E436 => 0xe436,
            Self::E43a => 0xe43a,
            Self::E43b => 0xe43b,
            Self::E45b => 0xe45b,
            Self::E463 => 0xe463,
            Self::E46a => 0xe46a,
            Self::E46b => 0xe46b,
            Self::Ffc5 => 0xffc5,
            Self::Edcc => 0xedcc,
            Self::Edcd => 0xedcd,
            Self::Fe94 => 0xfe94,
            Self::Fec0 => 0xfec0,
            Self::Servo => return None,
        })
    }

    /// Mask applied to immediate byte values by the current family policy.
    pub fn value_mask(self) -> u8 {
        if self == Self::Fec0 {
            0xbf
        } else {
            0xff
        }
    }
}

/// A recognized operation, without inferring its resulting hardware state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegisterOperation {
    /// Known byte store and the region-relative instruction which supplied it.
    Write {
        /// Recovered byte constant, without applying the family policy mask.
        value: u8,
        /// Region-relative offset of the immediate load or self-zeroing.
        loaded_at: usize,
    },
    /// An immediate bit set; other bits retain their unknown hardware values.
    SetBit(u8),
    /// An immediate bit clear.
    ClearBit(u8),
    /// An immediate bit toggle.
    ToggleBit(u8),
}

/// Source of an observed operation in the decoded logical regions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisterObservation {
    /// Index in stored gaps followed by expanded streams, never joined.
    pub region: usize,
    /// Byte offset within that region, including its initial alignment byte.
    pub offset: usize,
    /// Recognized operation. This does not prove runtime reachability.
    pub operation: RegisterOperation,
}

/// Collected evidence, independently of whether the family policy uses it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisterEvidence {
    /// Register's low 16-bit address in the firmware's MMIO window.
    pub address: u16,
    /// Recognized stores and bit operations, with code provenance.
    pub observations: Vec<RegisterObservation>,
}

impl RegisterEvidence {
    /// Recovered byte constants. Empty means unrecognized, not unwritten.
    pub fn values(&self) -> BTreeSet<u8> {
        self.observations
            .iter()
            .filter_map(|o| match o.operation {
                RegisterOperation::Write { value, .. } => Some(value),
                _ => None,
            })
            .collect()
    }
}

/// One current-policy comparison; absent evidence is exposed separately.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CriterionComparison {
    /// Criterion evaluated, including criteria selected by the caller.
    pub criterion: FamilyCriterion,
    /// Canonical policy value, which can differ from richer observations.
    pub left: String,
    /// Canonical policy value for the other image.
    pub right: String,
    /// Equality under the selected policy, including its missing-value rules.
    pub matches: bool,
    /// Both policy values have recognized evidence. Two missing values can
    /// match under the current policy without establishing physical equivalence.
    pub evidence_known: bool,
}

/// Family-only result; startup, settings and transfer admission stay separate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FamilyComparison {
    /// All selected criteria match. An empty selection deliberately matches.
    pub matches: bool,
    /// Individual reasons, retaining the caller's criterion order.
    pub criteria: Vec<CriterionComparison>,
}

/// Rich observations alongside the explicit family projection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FamilyEvidence {
    pub(super) fingerprint: FamilyFingerprint,
    pub(super) registers: Vec<RegisterEvidence>,
}

impl FamilyEvidence {
    /// Current family identifier and its canonical policy inputs.
    pub fn fingerprint(&self) -> &FamilyFingerprint {
        &self.fingerprint
    }

    /// Unmasked observations, including recovered shared CPU-register values.
    pub fn registers(&self) -> &[RegisterEvidence] {
        &self.registers
    }

    /// Apply every current criterion, preserving existing family relationships.
    pub fn compare(&self, other: &Self) -> FamilyComparison {
        self.compare_with(other, FAMILY_CRITERIA)
    }

    /// Compare selected fields, including diagnostic-only movement commands.
    /// This does not change stored IDs and is not a crossflash permit.
    pub fn compare_with(&self, other: &Self, selected: &[FamilyCriterion]) -> FamilyComparison {
        let criteria: Vec<_> = selected
            .iter()
            .map(|&criterion| {
                let left = self.policy_value(criterion);
                let right = other.policy_value(criterion);
                CriterionComparison {
                    criterion,
                    matches: left == right,
                    evidence_known: !matches!(left.as_str(), "-" | "none")
                        && !matches!(right.as_str(), "-" | "none"),
                    left,
                    right,
                }
            })
            .collect();
        FamilyComparison {
            matches: criteria.iter().all(|c| c.matches),
            criteria,
        }
    }

    fn policy_value(&self, criterion: FamilyCriterion) -> String {
        if matches!(criterion, FamilyCriterion::Edcc | FamilyCriterion::Edcd) {
            let register = self
                .registers
                .iter()
                .find(|r| Some(r.address) == criterion.address())
                .expect("diagnostic command registers are collected");
            let values = register.values();
            let operations = register
                .observations
                .iter()
                .filter_map(|o| match o.operation {
                    RegisterOperation::SetBit(bit) => Some(format!("BSET{bit}")),
                    RegisterOperation::ClearBit(bit) => Some(format!("BCLR{bit}")),
                    RegisterOperation::ToggleBit(bit) => Some(format!("BNOT{bit}")),
                    RegisterOperation::Write { .. } => None,
                })
                .collect();
            return fmt_board(Some(&values), Some(&operations));
        }
        let f = &self.fingerprint;
        if criterion == FamilyCriterion::Servo {
            return f.servo.clone();
        }
        let source = match criterion {
            FamilyCriterion::Ffc5 => &f.board,
            FamilyCriterion::Fe94 | FamilyCriterion::Fec0 => &f.pins,
            _ => &f.asic,
        };
        let prefix = format!("{:04x}=", criterion.address().unwrap());
        source
            .split_whitespace()
            .find_map(|part| part.strip_prefix(&prefix))
            .expect("all identity criteria are serialized")
            .to_owned()
    }
}

/// Collect short straight-line byte initialization forms. Unknown operations
/// discard all constants; constants never cross regions, calls or branches.
pub(super) fn register_observations(regions: &[&[u8]], body: &[u8]) -> Vec<RegisterEvidence> {
    let mut registers: Vec<_> = FAMILY_CRITERIA
        .iter()
        .chain([FamilyCriterion::Edcc, FamilyCriterion::Edcd].iter())
        .filter_map(|c| c.address())
        .map(|address| RegisterEvidence {
            address,
            observations: Vec::new(),
        })
        .collect();
    for (region_index, full_region) in regions.iter().enumerate() {
        let code = aligned_code_region(full_region, body);
        let alignment = full_region.len() - code.len();
        let mut known: [Option<(u8, usize)>; 16] = [None; 16];
        let mut i = 0;
        while i + 1 < code.len() {
            let a = code[i];
            let b = code[i + 1];
            let mut len = 2;
            let mut operation = None;
            let mut address = None;
            if a >= 0xf0 {
                known[(a & 15) as usize] = Some((b, i + alignment));
            } else if matches!(a, 0x18 | 0x15) && b >> 4 == b & 15 {
                known[(b & 15) as usize] = Some((0, i + alignment));
            } else if (0x30..=0x3f).contains(&a)
                || (a == 0x6a && (0x80..=0x8f).contains(&b) && i + 3 < code.len())
            {
                let register = if a == 0x6a { b & 15 } else { a & 15 };
                address = Some(if a == 0x6a {
                    len = 4;
                    u16::from_be_bytes([code[i + 2], code[i + 3]])
                } else {
                    0xff00 | b as u16
                });
                if let Some((value, loaded_at)) = known[register as usize] {
                    if i + alignment - loaded_at <= 256 {
                        operation = Some(RegisterOperation::Write { value, loaded_at });
                    }
                }
            } else if (a == 0x7f && i + 3 < code.len())
                || (a == 0x6a && b == 0x18 && i + 5 < code.len())
            {
                let (op, bit) = if a == 0x7f {
                    len = 4;
                    address = Some(0xff00 | b as u16);
                    (code[i + 2], code[i + 3])
                } else {
                    len = 6;
                    address = Some(u16::from_be_bytes([code[i + 2], code[i + 3]]));
                    (code[i + 4], code[i + 5])
                };
                operation = match (op, bit & 0x8f) {
                    (0x70, 0) => Some(RegisterOperation::SetBit(bit >> 4)),
                    (0x71, 0) => Some(RegisterOperation::ToggleBit(bit >> 4)),
                    (0x72, 0) => Some(RegisterOperation::ClearBit(bit >> 4)),
                    _ => {
                        known.fill(None);
                        None
                    }
                };
            } else if a != 0 || b != 0 {
                // Do not reinterpret operands of an unknown multiword
                // instruction as another immediate load after a clobber.
                len = h8::ilen(code, i);
                known.fill(None);
            }
            if let (Some(address), Some(operation)) = (address, operation) {
                if let Some(register) = registers.iter_mut().find(|r| r.address == address) {
                    register.observations.push(RegisterObservation {
                        region: region_index,
                        offset: i + alignment,
                        operation,
                    });
                }
            }
            i += len;
        }
    }
    registers
}
