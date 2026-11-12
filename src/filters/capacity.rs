//! Pair-aware capacity-discriminator relation, surfaced as a registered filter
//! so every filter-driven surface (the hardware-matrix site, `blocker_matrix`
//! and `compatibility::plan`) refuses exactly what the receiver's startup gate
//! refuses. The relation itself is owned once by
//! `startup::capacity::Evidence::relates`; this filter only carries the
//! per-image evidence and consults that one relation when comparing a pair.
//!
//! Two firmwares with matching capacity-bank address cases may still select
//! different banks if their discriminator programs differ, so matching cases
//! are not admission. This owner is Operational, not Hardware: it never joins
//! the family identity key; it gates the directed pair.
use super::{Assessment, Comparison, Context, Filter, Finding, Role, Value};
use crate::startup::bank::{Addresses, Storage};
use crate::startup::capacity::Evidence;
use alloc::string::ToString;

/// Registered capacity-discriminator owner.
pub struct Capacity;
/// Registered capacity-discriminator filter.
pub static FILTER: Capacity = Capacity;

const ID: &str = "capacity-discriminator";
/// Stable, filter-local tag for "no capacity-dependent bank selection".
const NOT_APPLICABLE: u16 = 0xca00;

static RULES: super::Rules = super::Rules {
    description: "Compares the capacity discriminator that selects persistent-bank addresses on a capacity-dependent contract. Matching the two address cases does not prove the two firmwares' discriminator programs choose the same bank. Not corrected: there is no bank migration.",
    role: super::Role::Operational,
    correctability: super::Correctability::Fixed,
    correction: "Never corrected. The discriminator relation must be proved, or the directed pair refuses with code pioneer.startup.capacity_relation_unproved.",
    policies: &[super::Policy {
        domains: &[],
        text: "A capacity-dependent contract relates only with an unchanged complete pair, an address expression independent of the discriminator, or the same discriminator over identical address cases: its query and its decision match exactly, and only link layout and side calls that cannot touch the query's hardware may differ. The proof is derived from the two images with h8-asm (no live query), so the offline and online compares are equal and the proof can only under-admit. Fixed, collapsed, or non-capacity contracts need no discriminator proof here and defer to the bank/geometry owner; a recognized capacity guard whose address calculation is unresolved stays Unresolved.",
    }],
};

impl Filter for Capacity {
    fn id(&self) -> &'static str {
        ID
    }
    fn name(&self) -> &'static str {
        "Capacity discriminator"
    }
    fn rules(&self) -> Option<&'static super::Rules> {
        Some(&RULES)
    }
    fn inspect(&self, context: &Context<'_>) -> Assessment {
        let firmware = context.firmware;
        let (evidence, banks) = Evidence::discover(firmware.normal, firmware.kernel);
        // The discriminator relation applies only to a versioned capacity
        // contract whose two address cases differ; everything else (fixed,
        // collapsed, state-header, kernel-sequence, or no contract) needs no
        // discriminator proof and the bank/geometry owner compares it.
        let needs_proof = matches!(
            banks.storage,
            Some(Storage::Versioned(contract))
                if matches!(
                    contract.addresses,
                    Addresses::Capacity { when_one, otherwise } if when_one != otherwise
                )
        );
        // A recognized capacity guard whose address calculation is unresolved
        // is missing evidence, not proof that no discriminator selects banks.
        if banks.capacity_guard && banks.capacity_query.is_none() {
            return Assessment::unresolved(
                ID,
                Role::Operational,
                "A versioned capacity guard is present but its persistent-bank address calculation is unresolved",
            );
        }
        if needs_proof {
            Assessment::known(
                ID,
                Role::Operational,
                Value::Bytes(evidence.encode()),
                "Capacity-dependent bank selection; relation proved by the relocated discriminator-program digest (h8-asm) or an unchanged complete pair identity",
            )
        } else {
            Assessment {
                id: ID,
                role: Role::Operational,
                finding: Finding::NotApplicable {
                    proof: NOT_APPLICABLE,
                    evidence: "No capacity-dependent bank selection: the bank address cases are fixed or collapsed, or no versioned capacity contract is present".to_string(),
                },
                evidence: "No capacity discriminator selects the persistent-bank addresses".to_string(),
            }
        }
    }
    /// Consult the one relation. Two capacity contracts relate only when their
    /// evidence does; a capacity contract never relates to a non-capacity image;
    /// two non-capacity images defer (match) to the bank/geometry owner.
    fn compare(&self, installed: &Assessment, target: &Assessment) -> Comparison {
        if installed.id != self.id() || target.id != self.id() || installed.role != target.role {
            return Comparison::Conflicting;
        }
        match (&installed.finding, &target.finding) {
            (Finding::Conflicting(_), _) | (_, Finding::Conflicting(_)) => Comparison::Conflicting,
            (Finding::Unresolved(_), _) | (_, Finding::Unresolved(_)) => Comparison::Unresolved,
            (Finding::NotApplicable { proof: a, .. }, Finding::NotApplicable { proof: b, .. })
                if a == b =>
            {
                Comparison::Match
            }
            (Finding::Known(Value::Bytes(a)), Finding::Known(Value::Bytes(b))) => {
                match (Evidence::decode(a), Evidence::decode(b)) {
                    (Some(installed), Some(target)) if installed.relates(target) => {
                        Comparison::Match
                    }
                    (Some(_), Some(_)) => Comparison::Different,
                    // Encoded evidence always decodes; a non-evidence byte value
                    // falls back to plain equality.
                    _ if a == b => Comparison::Match,
                    _ => Comparison::Different,
                }
            }
            // Any other known value (never produced by this owner's inspect)
            // uses ordinary fixed-value equality.
            (Finding::Known(a), Finding::Known(b)) if a == b => Comparison::Match,
            _ => Comparison::Different,
        }
    }
}

#[cfg(all(test, feature = "envelope"))]
mod tests {
    use super::*;
    use crate::compatibility::Firmware;
    use crate::filters::Context;
    use crate::startup::bank;

    fn inspect(normal: &[u8], kernel: Option<&[u8]>) -> Assessment {
        FILTER.inspect(&Context::new(Firmware {
            hardware: "SAT 8600",
            normal,
            kernel,
        }))
    }

    #[test]
    fn non_capacity_images_are_not_applicable_and_defer_to_each_other() {
        let mut fixed = alloc::vec![0u8; 0x2000];
        bank::fixture(&mut fixed);
        let a = inspect(&fixed, None);
        assert!(matches!(a.finding, Finding::NotApplicable { .. }));
        // Two non-capacity images defer (Match): the bank/geometry owner decides.
        let mut other = fixed.clone();
        other[0] ^= 1;
        assert_eq!(
            FILTER.compare(&a, &inspect(&other, None)),
            Comparison::Match
        );
    }

    #[test]
    fn distinct_capacity_cases_need_proof_and_refuse_when_unproved() {
        let normal = bank::versioned_fixture(0xfedc_4321, [0xfffa, 0x1_fffa]);
        let kernel = alloc::vec![0u8; 0x10000];
        let a = inspect(&normal, Some(&kernel));
        assert!(matches!(a.finding, Finding::Known(Value::Bytes(_))));
        // An identical complete pair relates through the unchanged-pair identity.
        assert_eq!(FILTER.compare(&a, &a), Comparison::Match);
        // A different image with no provable discriminator never relates.
        let mut changed = normal.clone();
        changed[0] ^= 1;
        assert_eq!(
            FILTER.compare(&a, &inspect(&changed, Some(&kernel))),
            Comparison::Different
        );
        // A missing Kernel is not an identity witness: it cannot relate to itself.
        let no_kernel = inspect(&normal, None);
        assert_eq!(
            FILTER.compare(&no_kernel, &no_kernel),
            Comparison::Different
        );
    }

    #[test]
    fn a_capacity_guard_with_an_unresolved_address_calculation_is_unresolved() {
        let mut normal = bank::versioned_fixture(0xfedc_4321, [0xfffa, 0x1_fffa]);
        // Break the base calculation's MOV.L #end,ER1: the guard is still
        // recognized, but its persistent-bank addresses are not.
        normal[0x1404..0x1406].copy_from_slice(&[0, 0]);
        assert!(bank::discover(&normal).is_some());
        assert_eq!(bank::analyze_pair(&normal, None), None);
        let a = inspect(&normal, None);
        assert!(
            matches!(a.finding, Finding::Unresolved(_)),
            "{:?}",
            a.finding
        );
        assert_eq!(FILTER.compare(&a, &a), Comparison::Unresolved);
    }

    #[test]
    fn two_capacity_guards_are_unresolved_not_absent() {
        let mut normal = bank::versioned_fixture(0xfedc_4321, [0xfffa, 0x1_fffa]);
        let copy = normal[0x1000..0x1092].to_vec();
        normal[0x2000..0x2092].copy_from_slice(&copy);
        assert_eq!(bank::discover(&normal), None);
        let a = inspect(&normal, None);
        assert!(
            matches!(a.finding, Finding::Unresolved(_)),
            "{:?}",
            a.finding
        );
        assert_eq!(FILTER.compare(&a, &a), Comparison::Unresolved);
    }

    #[test]
    fn a_capacity_contract_never_relates_to_a_non_capacity_image() {
        let normal = bank::versioned_fixture(0xfedc_4321, [0xfffa, 0x1_fffa]);
        let kernel = alloc::vec![0u8; 0x10000];
        let mut fixed = alloc::vec![0u8; 0x2000];
        bank::fixture(&mut fixed);
        assert_eq!(
            FILTER.compare(&inspect(&normal, Some(&kernel)), &inspect(&fixed, None)),
            Comparison::Different
        );
    }
}
