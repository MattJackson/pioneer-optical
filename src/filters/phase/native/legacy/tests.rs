use super::*;

const BASE: u32 = 0x410000;
const AT: usize = 0x2000;

fn install(raw: &mut [u8], t: &Template, at: usize) {
    raw[at..at + t.bytes.len()].copy_from_slice(t.bytes);
    for r in t.relocations {
        let target = match r.kind {
            RelocationKind::Call if t.requires_leaf => Some(BASE + at as u32 - 6),
            RelocationKind::Jump
                if (t.reference_cpu..t.reference_cpu + t.bytes.len() as u32)
                    .contains(&r.reference) =>
            {
                Some(BASE + at as u32 + r.reference - t.reference_cpu)
            }
            _ => None,
        };
        if let Some(value) = target {
            let encoded = value.to_be_bytes();
            let width = r.end - r.start;
            raw[at + r.start..at + r.end].copy_from_slice(&encoded[4 - width..]);
        }
    }
    if t.requires_leaf {
        raw[at - 6..at].copy_from_slice(&[0x6a, 0x88, 0xf9, 9, 0x54, 0x70]);
    }
}

fn fixture(t: &Template) -> Vec<u8> {
    let mut raw = alloc::vec![0xff; 0x200000];
    install(&mut raw, t, AT);
    raw
}

fn opposite(value: Assignment) -> Assignment {
    match value {
        Assignment::Direct => Assignment::Swapped,
        Assignment::Swapped => Assignment::Direct,
    }
}

fn fix_sum(raw: &mut [u8]) {
    raw[16..20].fill(0);
    let sum = raw.chunks_exact(4).fold(0u32, |s, w| {
        s.wrapping_add(u32::from_be_bytes(w.try_into().unwrap()))
    });
    raw[16..20].copy_from_slice(&sum.wrapping_neg().to_be_bytes());
}

#[test]
fn operand_only_legacy_forms_are_reversible_and_preserve_shared_leaf() {
    assert_eq!(templates::TEMPLATES.len(), 13);
    for t in templates::TEMPLATES {
        let raw = fixture(t);
        assert_eq!(correct(&raw, t.assignment).unwrap(), raw);
        if t.patches
            .iter()
            .any(|patch| matches!(patch, Patch::LeafCall(_)))
        {
            assert_eq!(
                correct(&raw, opposite(t.assignment)),
                Err(CorrectionError::Unresolved)
            );
            continue;
        }
        let corrected = correct(&raw, opposite(t.assignment)).unwrap();
        assert!(matches!(discover(&corrected), Observation::Known(p)
            if p.assignment == opposite(t.assignment) && p.interface == t.interface));
        assert_eq!(correct(&corrected, t.assignment).unwrap(), raw);
        assert_eq!(
            correct(&corrected, opposite(t.assignment)).unwrap(),
            corrected
        );
        if t.requires_leaf {
            assert_eq!(&corrected[AT - 6..AT], &raw[AT - 6..AT]);
        }
        assert_eq!(raw.len(), corrected.len());
        let mut complete = raw;
        complete[..16].copy_from_slice(b"PIONEER TEST    ");
        let length = complete.len() as u32;
        complete[20..24].copy_from_slice(&length.to_be_bytes());
        fix_sum(&mut complete);
        let complete_corrected = correct_normal(&complete, opposite(t.assignment)).unwrap();
        assert_eq!(
            correct_normal(&complete_corrected, t.assignment).unwrap(),
            complete
        );
    }
}

#[test]
fn a_partial_swap_is_never_a_supported_assignment() {
    for t in templates::TEMPLATES {
        let raw = fixture(t);
        let all = binding(t, &raw, AT).unwrap();
        assert!(all.changes.len() > 1);
        for one in &all.changes {
            let mut partial = raw.clone();
            partial[one.offset..one.offset + one.swapped.len()].copy_from_slice(&one.swapped);
            assert!(binding(t, &partial, AT).is_none());
            assert_eq!(
                correct(&partial, t.assignment),
                Err(CorrectionError::Unresolved)
            );
            assert_eq!(
                correct(&partial, opposite(t.assignment)),
                Err(CorrectionError::Unresolved)
            );
        }
    }
}

#[test]
fn duplicate_complete_programs_refuse_even_when_their_assignments_agree() {
    for t in templates::TEMPLATES {
        let mut raw = fixture(t);
        install(&mut raw, t, AT + 0x1000);
        assert!(matches!(discover(&raw), Observation::Known(p) if p.assignment == t.assignment));
        assert_eq!(
            correct(&raw, opposite(t.assignment)),
            Err(CorrectionError::Unresolved)
        );
    }
}

#[test]
fn nonadjacent_stored_leaf_is_observable_but_not_guessed_for_reversal() {
    for t in templates::TEMPLATES.iter().filter(|t| t.requires_leaf) {
        let mut raw = fixture(t);
        let distant = AT - 0x100;
        let leaf = raw[AT - 6..AT].to_vec();
        raw[distant..distant + 6].copy_from_slice(&leaf);
        raw[AT - 6..AT].fill(0xff);
        for r in t
            .relocations
            .iter()
            .filter(|r| matches!(r.kind, RelocationKind::Call))
        {
            raw[AT + r.start..AT + r.end]
                .copy_from_slice(&(BASE + distant as u32).to_be_bytes()[1..]);
        }
        assert!(observe(t, &raw, AT, &[&raw]).is_some());
        assert!(matches!(discover(&raw), Observation::Known(p) if p.assignment == t.assignment));
        assert_eq!(
            correct(&raw, opposite(t.assignment)),
            Err(CorrectionError::Unresolved)
        );
        // A raw byte match outside the supplied stored-code regions is not a
        // native helper binding, even though it contains the expected bytes.
        assert!(observe(t, &raw, AT, &[&raw[AT..AT + t.bytes.len()]]).is_none());
    }
}

#[test]
fn odd_calls_and_relocated_internal_jumps_are_rejected() {
    let mut calls = 0;
    let mut jumps = 0;
    for t in templates::TEMPLATES {
        let raw = fixture(t);
        for r in t.relocations {
            if !matches!(r.kind, RelocationKind::Call | RelocationKind::Jump) {
                continue;
            }
            let mut bad = raw.clone();
            bad[AT + r.end - 1] |= 1;
            assert!(!template_matches(t, &bad, AT));
            match r.kind {
                RelocationKind::Call => calls += 1,
                RelocationKind::Jump => {
                    jumps += 1;
                    if (t.reference_cpu..t.reference_cpu + t.bytes.len() as u32)
                        .contains(&r.reference)
                    {
                        let mut shifted = raw.clone();
                        let value = integer(&shifted[AT + r.start..AT + r.end]) + 2;
                        shifted[AT + r.start..AT + r.end]
                            .copy_from_slice(&value.to_be_bytes()[1..]);
                        assert!(!template_matches(t, &shifted, AT));
                    }
                }
                RelocationKind::Address => unreachable!(),
            }
        }
    }
    assert!(calls > 0 && jumps > 0);
}

#[test]
fn byte_pair_correction_uses_native_programs_across_platform_labels() {
    use crate::compatibility::Firmware;
    use crate::filters::{phase::FILTER, Context, Filter, Transition};
    for t in templates::TEMPLATES
        .iter()
        .filter(|t| t.interface == Interface::BytePair && !t.requires_leaf)
    {
        let raw = fixture(t);
        let corrected = correct(&raw, opposite(t.assignment)).unwrap();
        for hardware in ["SAT 1046", "SAT 8000"] {
            let context = |normal| {
                Context::new(Firmware {
                    hardware,
                    normal,
                    kernel: None,
                })
            };
            let (installed, target) = (context(&corrected), context(&raw));
            let plan = FILTER.plan(
                &Transition {
                    installed: &installed,
                    target: &target,
                },
                &FILTER.inspect(&installed),
                &FILTER.inspect(&target),
            );
            let operation = plan.unwrap().expect("bound native output correction");
            assert!(operation.required_words().is_empty(), "{hardware}");
        }
    }
}
