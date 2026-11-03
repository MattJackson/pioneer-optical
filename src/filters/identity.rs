//! Canonical identities assembled from every registered hardware contract.
//! Owner identifiers and typed native values are the complete field inventory.
//! Registry order, presentation text and operational requirements are excluded.
use super::{Assessment, Context, Filter, Finding, Role, Value};
use alloc::{collections::BTreeSet, vec::Vec};
use sha2::{Digest, Sha256};

/// Broad firmware domain established by an exact structured hardware tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Domain {
    /// SAT 1xxx hardware.
    Sat1 = 1,
    /// SAT 8xxx hardware.
    Sat8 = 2,
    /// SAT 9xxx hardware.
    Sat9 = 3,
    /// ATA hardware; native architecture remains a registered observation.
    Ata = 4,
    /// SCSI hardware; required native observations must still be established.
    Scsi = 5,
}
impl Domain {
    /// Parse a complete hardware header, never a model or partial tag.
    pub fn from_hardware(hardware: &str) -> Option<Self> {
        let bytes = hardware.as_bytes();
        if bytes.len() != 8 || !bytes[4..].iter().all(u8::is_ascii_hexdigit) {
            return None;
        }
        match &bytes[..4] {
            b"SAT " => match bytes[4] {
                b'1' => Some(Self::Sat1),
                b'8' => Some(Self::Sat8),
                b'9' => Some(Self::Sat9),
                _ => None,
            },
            b"ATA " => Some(Self::Ata),
            b"SCSI" => Some(Self::Scsi),
            _ => None,
        }
    }
}

/// The semantic identity contribution of one hardware owner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NativeValue {
    /// A known, explicitly typed native contract.
    Known(Value),
    /// Positive native exclusion, represented by its stable owner proof tag.
    NotApplicable {
        /// Owner-defined native proof tag; explanatory text remains evidence.
        proof: u16,
    },
}
impl NativeValue {
    fn from_finding(finding: Finding) -> Option<Self> {
        match finding {
            Finding::Known(value) => Some(Self::Known(value)),
            Finding::NotApplicable { proof, evidence } if !evidence.trim().is_empty() => {
                Some(Self::NotApplicable { proof })
            }
            _ => None,
        }
    }
}

/// One registered hardware field in canonical identifier order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// Stable owner identifier, never its presentation name.
    pub id: &'static str,
    /// Native value or positively established exclusion.
    pub value: NativeValue,
}

/// Version seven identity containing every registered hardware field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Key {
    domain: Domain,
    entries: Vec<Entry>,
}
impl Key {
    /// Broad structured-header domain retained alongside all native fields.
    pub fn domain(&self) -> Domain {
        self.domain
    }

    /// All hardware contributions in canonical identifier order.
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// Find the native contribution of an owner without interpreting its value.
    pub fn value(&self, id: &str) -> Option<&NativeValue> {
        self.entries
            .binary_search_by_key(&id, |entry| entry.id)
            .ok()
            .map(|index| &self.entries[index].value)
    }

    /// Versioned binary key. All identifiers are length-delimited UTF-8 bytes;
    /// typed values retain their native widths and owner proof discriminants.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = b"PIONEER-FAMILY\0\x07".to_vec();
        bytes.push(self.domain as u8);
        bytes.extend((self.entries.len() as u64).to_be_bytes());
        for entry in &self.entries {
            bytes.extend((entry.id.len() as u64).to_be_bytes());
            bytes.extend(entry.id.as_bytes());
            match &entry.value {
                NativeValue::Known(value) => {
                    bytes.push(1);
                    bytes.extend(value.canonical_bytes());
                }
                NativeValue::NotApplicable { proof } => {
                    bytes.push(2);
                    bytes.extend(proof.to_be_bytes());
                }
            }
        }
        bytes
    }

    /// SHA-256 prefix used by the existing opaque family identifier wrapper.
    pub fn fingerprint(&self) -> u64 {
        let digest = Sha256::digest(self.canonical_bytes());
        u64::from_be_bytes(digest[..8].try_into().expect("eight-byte digest prefix"))
    }
}

/// Native as-is identity and the candidate projection owned by each filter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    /// Every hardware value before applying a correction.
    pub as_is: Key,
    /// Each owner's explicitly supported grouping projection.
    pub candidate: Key,
}

/// Evaluate both projections using the complete production registry.
/// An unresolved required value never produces a partial family identifier.
pub fn discover(context: &Context<'_>) -> Option<Identity> {
    discover_with(context, super::filters())
}

/// Evaluate a supplied registry through the same generic identity path.
/// This also permits isolated owner and registration regression tests.
pub fn discover_with(context: &Context<'_>, registry: &[&dyn Filter]) -> Option<Identity> {
    let domain = Domain::from_hardware(context.firmware.hardware)?;
    let mut ids = BTreeSet::new();
    let mut raw = Vec::new();
    let mut candidate = Vec::new();
    for filter in registry {
        let id = filter.id();
        if id.is_empty() || !ids.insert(id) {
            return None;
        }
        let assessment: Assessment = filter.inspect(context);
        if assessment.id != id {
            return None;
        }
        if assessment.role == Role::Hardware {
            let value = NativeValue::from_finding(assessment.finding.clone())?;
            let projected = NativeValue::from_finding(filter.candidate(context, &assessment))?;
            raw.push(Entry { id, value });
            candidate.push(Entry {
                id,
                value: projected,
            });
        }
    }
    if raw.is_empty() {
        return None;
    }
    raw.sort_by_key(|entry| entry.id);
    candidate.sort_by_key(|entry| entry.id);
    Some(Identity {
        as_is: Key {
            domain,
            entries: raw,
        },
        candidate: Key {
            domain,
            entries: candidate,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compatibility::Firmware;

    struct Fake {
        id: &'static str,
        role: Role,
        finding: Finding,
        projected: Option<Finding>,
    }
    impl Fake {
        fn known(id: &'static str, value: Value) -> Self {
            Self {
                id,
                role: Role::Hardware,
                finding: Finding::Known(value),
                projected: None,
            }
        }
    }
    impl Filter for Fake {
        fn id(&self) -> &'static str {
            self.id
        }
        fn name(&self) -> &'static str {
            "Presentation label, never a key"
        }
        fn inspect(&self, _context: &Context<'_>) -> Assessment {
            Assessment {
                id: self.id,
                role: self.role,
                finding: self.finding.clone(),
                evidence: "relocated native evidence".into(),
            }
        }
        fn candidate(&self, _context: &Context<'_>, assessment: &Assessment) -> Finding {
            self.projected
                .clone()
                .unwrap_or_else(|| assessment.finding.clone())
        }
    }
    fn context(hardware: &str) -> Context<'_> {
        Context::new(Firmware {
            hardware,
            normal: &[],
            kernel: None,
        })
    }

    #[test]
    fn v7_encoding_and_fingerprint_have_a_fixed_native_golden() {
        let a = Fake::known("a", Value::U8(0x56));
        let b = Fake::known("b", Value::U16(0x1234));
        let key = discover_with(&context("SAT 8000"), &[&b, &a])
            .unwrap()
            .as_is;
        let mut expected = b"PIONEER-FAMILY\0\x07\x02".to_vec();
        expected.extend(2u64.to_be_bytes());
        expected.extend(1u64.to_be_bytes());
        expected.extend(b"a");
        expected.extend([1, 1, 0x56]);
        expected.extend(1u64.to_be_bytes());
        expected.extend(b"b");
        expected.extend([1, 2, 0x12, 0x34]);
        assert_eq!(key.canonical_bytes(), expected);
        assert_eq!(key.fingerprint(), 0x0f5e_d2bd_7174_1e72);
    }

    #[test]
    fn canonical_native_widths_and_proof_states_are_unambiguous() {
        let context = context("SAT 8000");
        let mut bytes = Vec::new();
        for value in [
            Value::U8(0),
            Value::Bool(false),
            Value::U16(0),
            Value::U32(0),
            Value::Bytes(vec![0]),
            Value::Sequence(vec![Value::U8(0)]),
        ] {
            let fake = Fake::known("field", value);
            let key = discover_with(&context, &[&fake]).unwrap().as_is;
            assert!(!bytes.contains(&key.canonical_bytes()));
            bytes.push(key.canonical_bytes());
        }
        let excluded = Fake {
            id: "field",
            role: Role::Hardware,
            finding: Finding::NotApplicable {
                proof: 0,
                evidence: "complete native contract excludes this input".into(),
            },
            projected: None,
        };
        let key = discover_with(&context, &[&excluded]).unwrap().as_is;
        assert!(!bytes.contains(&key.canonical_bytes()));
        assert!(key.canonical_bytes().starts_with(b"PIONEER-FAMILY\0\x07"));
        assert_eq!(
            key.value("field"),
            Some(&NativeValue::NotApplicable { proof: 0 })
        );
    }

    #[test]
    fn one_registration_automatically_changes_both_keys_and_hashes() {
        let context = context("SAT 8000");
        let original = Fake::known("original", Value::U8(7));
        let new = Fake::known("new-constant-field", Value::U8(0));
        let changed = Fake::known("new-constant-field", Value::U8(1));
        let before = discover_with(&context, &[&original]).unwrap();
        let after = discover_with(&context, &[&original, &new]).unwrap();
        let other = discover_with(&context, &[&original, &changed]).unwrap();
        assert_eq!(after.as_is.entries().len(), 2);
        assert_ne!(before.as_is, after.as_is);
        assert_ne!(before.candidate, after.candidate);
        assert_ne!(before.as_is.fingerprint(), after.as_is.fingerprint());
        assert_ne!(after.as_is, other.as_is);
        assert_ne!(after.candidate, other.candidate);
    }

    #[test]
    fn sixteen_owner_orders_have_identical_bytes_and_duplicate_ids_refuse() {
        let context = context("SAT 9000");
        let ids = [
            "f00", "f01", "f02", "f03", "f04", "f05", "f06", "f07", "f08", "f09", "f10", "f11",
            "f12", "f13", "f14", "f15",
        ];
        let definitions: Vec<_> = ids
            .into_iter()
            .enumerate()
            .map(|(i, id)| Fake::known(id, Value::U8(i as u8)))
            .collect();
        let mut registry: Vec<&dyn Filter> = definitions.iter().map(|f| f as &dyn Filter).collect();
        let baseline = discover_with(&context, &registry).unwrap();
        for _ in 0..16 {
            registry.rotate_left(1);
            let reordered = discover_with(&context, &registry).unwrap();
            assert_eq!(reordered, baseline);
            assert_eq!(
                reordered.as_is.canonical_bytes(),
                baseline.as_is.canonical_bytes()
            );
            assert_eq!(reordered.as_is.fingerprint(), baseline.as_is.fingerprint());
        }
        registry.reverse();
        assert_eq!(discover_with(&context, &registry), Some(baseline));
        registry.push(&definitions[0]);
        assert!(discover_with(&context, &registry).is_none());
        let mut duplicate = Fake::known("f00", Value::U8(99));
        duplicate.role = Role::Operational;
        assert!(discover_with(&context, &[&definitions[0], &duplicate]).is_none());
    }

    #[test]
    fn unknown_conflicting_and_unproved_exclusions_never_form_a_key() {
        let context = context("SAT 1000");
        for finding in [
            Finding::Unresolved("missing reader".into()),
            Finding::Conflicting("two readers".into()),
            Finding::NotApplicable {
                proof: 9,
                evidence: String::new(),
            },
        ] {
            let fake = Fake {
                id: "required",
                role: Role::Hardware,
                finding,
                projected: Some(Finding::Known(Value::U8(0))),
            };
            assert!(discover_with(&context, &[&fake]).is_none());
        }
        assert!(discover_with(&context, &[]).is_none());
    }

    #[test]
    fn operational_unknown_is_retained_by_assessment_but_not_hardware_identity() {
        let context = context("ATA 0005");
        let hardware = Fake::known("hardware", Value::U16(0x1234));
        let operational = Fake {
            id: "startup",
            role: Role::Operational,
            finding: Finding::Unresolved("requires an explicit startup policy".into()),
            projected: None,
        };
        assert!(matches!(
            operational.inspect(&context).finding,
            Finding::Unresolved(_)
        ));
        assert_eq!(
            discover_with(&context, &[&hardware, &operational]),
            discover_with(&context, &[&hardware])
        );
        assert!(discover_with(&context, &[&operational]).is_none());
    }

    #[test]
    fn candidate_projection_is_explicit_and_evidence_text_never_rekeys() {
        let context = context("SAT 8000");
        let direct = Fake {
            id: "phase",
            role: Role::Hardware,
            finding: Finding::Known(Value::U8(0)),
            projected: Some(Finding::Known(Value::U8(0))),
        };
        let swapped = Fake {
            id: "phase",
            role: Role::Hardware,
            finding: Finding::Known(Value::U8(1)),
            projected: Some(Finding::Known(Value::U8(0))),
        };
        let a = discover_with(&context, &[&direct]).unwrap();
        let b = discover_with(&context, &[&swapped]).unwrap();
        assert_ne!(a.as_is, b.as_is);
        assert_eq!(a.candidate, b.candidate);
        let a = Fake {
            id: "irrelevant",
            role: Role::Hardware,
            finding: Finding::NotApplicable {
                proof: 5,
                evidence: "native proof at offset100".into(),
            },
            projected: None,
        };
        let b = Fake {
            id: "irrelevant",
            role: Role::Hardware,
            finding: Finding::NotApplicable {
                proof: 5,
                evidence: "same proof relocated to900".into(),
            },
            projected: None,
        };
        assert_eq!(
            discover_with(&context, &[&a]),
            discover_with(&context, &[&b])
        );
    }

    #[test]
    fn structured_domains_are_distinct_and_partial_or_model_tags_refuse() {
        let filter = Fake::known("native", Value::U8(0));
        let mut keys = Vec::new();
        for hardware in ["SAT 1000", "SAT 8000", "SAT 9000", "ATA 0000", "SCSI0001"] {
            let key = discover_with(&context(hardware), &[&filter]).unwrap().as_is;
            assert!(!keys.contains(&key));
            keys.push(key);
        }
        for hardware in [
            "SAT 8000 ",
            "SAT 8xxx",
            "SAT 7000",
            "SAT 800Z",
            "ATA 000",
            "SCSI000Z",
            "BDR-UD04",
            "sat 8000",
            "",
        ] {
            assert!(
                discover_with(&context(hardware), &[&filter]).is_none(),
                "{hardware}"
            );
        }
    }
}
