//! Component-tagged byte composition against one immutable original.
//!
//! Callers establish original authority, native integrity agreement and semantic
//! proofs. Component tags here do not admit any new native correction.
use crate::{compatibility::Error, Role};
use alloc::{vec, vec::Vec};
use core::ops::Range;

pub(super) struct ComponentEffect<'a> {
    pub(super) component: Role,
    pub(super) basis: &'a [u8],
    pub(super) image: &'a [u8],
}

pub(super) fn compose_component<F>(
    component: Role,
    original: &[u8],
    effects: &[ComponentEffect<'_>],
    integrity_fields: &[Range<usize>],
    repair: F,
) -> Result<Vec<u8>, Error>
where
    F: FnOnce(&[u8]) -> Result<Vec<u8>, Error>,
{
    compose_component_with_extent(
        component,
        original,
        original.len(),
        effects,
        integrity_fields,
        repair,
    )
}

/// Compose one explicitly owned tail and disjoint original-prefix effects.
/// Selecting a larger extent requires separate native and transfer authority;
/// production callers currently use only the same-length wrapper above.
pub(super) fn compose_component_with_extent<F>(
    component: Role,
    original: &[u8],
    final_len: usize,
    effects: &[ComponentEffect<'_>],
    integrity_fields: &[Range<usize>],
    repair: F,
) -> Result<Vec<u8>, Error>
where
    F: FnOnce(&[u8]) -> Result<Vec<u8>, Error>,
{
    if effects.is_empty() {
        return Err(Error::Unsupported);
    }
    if final_len < original.len() {
        return Err(Error::Representation);
    }
    for effect in effects {
        if effect.component != component || effect.basis != original {
            return Err(Error::ComponentMismatch);
        }
        if effect.image.len() != original.len() && effect.image.len() != final_len {
            return Err(Error::Representation);
        }
    }
    let grower = if final_len > original.len() {
        let mut growers = effects
            .iter()
            .filter(|effect| effect.image.len() == final_len);
        let grower = growers.next().ok_or(Error::Representation)?;
        if growers.next().is_some() {
            return Err(Error::Representation);
        }
        Some(grower)
    } else {
        None
    };
    let mut checksum = vec![false; final_len];
    for field in integrity_fields {
        let bytes = checksum
            .get_mut(field.clone())
            .ok_or(Error::Representation)?;
        if bytes.is_empty() || bytes.iter().any(|&used| used) {
            return Err(Error::Representation);
        }
        bytes.fill(true);
    }
    let mut claimed = vec![false; original.len()];
    let mut prepared = original.to_vec();
    prepared.resize(final_len, 0);
    for effect in effects {
        for (at, (&before, &after)) in original.iter().zip(effect.image).enumerate() {
            if before == after || checksum[at] {
                continue;
            }
            if claimed[at] {
                return Err(Error::Unsupported);
            }
            claimed[at] = true;
            prepared[at] = after;
        }
    }
    if let Some(grower) = grower {
        for at in original.len()..final_len {
            if !checksum[at] {
                prepared[at] = grower.image[at];
            }
        }
    }
    let repaired = repair(&prepared)?;
    if repaired.len() != final_len
        || repaired
            .iter()
            .zip(&prepared)
            .enumerate()
            .any(|(at, (a, b))| !checksum[at] && a != b)
    {
        return Err(Error::VerificationFailed);
    }
    Ok(repaired)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    fn effect<'a>(component: Role, basis: &'a [u8], image: &'a [u8]) -> ComponentEffect<'a> {
        ComponentEffect {
            component,
            basis,
            image,
        }
    }

    fn refuse_before_repair(
        original: &[u8],
        effects: &[ComponentEffect<'_>],
        fields: &[Range<usize>],
        expected: Error,
    ) {
        assert_eq!(
            compose_component(Role::Normal, original, effects, fields, |_| {
                panic!("invalid premise must refuse before repair")
            }),
            Err(expected)
        );
    }

    #[test]
    fn disjoint_edits_use_immutable_basis_and_repair_once_for_either_component() {
        let original = [0, 0, 0, 0];
        for component in [Role::Normal, Role::Kernel] {
            // Synthetic integrity byte only; no native Kernel checksum claim.
            let effects = [
                effect(component, &original, &[1, 0, 0, 8]),
                effect(component, &original, &[0, 2, 0, 9]),
            ];
            let calls = Cell::new(0);
            let output = compose_component(
                component,
                &original,
                &effects,
                &core::iter::once(3..4).collect::<Vec<_>>(),
                |merged| {
                    calls.set(calls.get() + 1);
                    // Owner checksum writes are ignored; both edits reach repair.
                    assert_eq!(merged, &[1, 2, 0, 0]);
                    let mut repaired = merged.to_vec();
                    repaired[3] = 3;
                    Ok(repaired)
                },
            )
            .unwrap();
            assert_eq!(output, [1, 2, 0, 3]);
            assert_eq!(calls.get(), 1);
            assert_eq!(original, [0, 0, 0, 0]);
        }
    }

    #[test]
    fn no_effects_refuse() {
        refuse_before_repair(&[0], &[], &[], Error::Unsupported);
    }

    #[test]
    fn equal_overlapping_writes_refuse() {
        let effects = [
            effect(Role::Normal, &[0, 0], &[1, 0]),
            effect(Role::Normal, &[0, 0], &[1, 0]),
        ];
        refuse_before_repair(&[0, 0], &effects, &[], Error::Unsupported);
    }

    #[test]
    fn component_tags_cannot_mix_even_for_identical_bytes() {
        for (component, foreign) in [(Role::Kernel, Role::Normal), (Role::Normal, Role::Kernel)] {
            assert_eq!(
                compose_component(component, &[0], &[effect(foreign, &[0], &[0])], &[], |_| {
                    panic!("foreign component must refuse before repair")
                }),
                Err(Error::ComponentMismatch)
            );
        }
    }

    #[test]
    fn wrong_same_length_basis_refuses() {
        refuse_before_repair(
            &[0, 0],
            &[effect(Role::Normal, &[0, 1], &[1, 1])],
            &[],
            Error::ComponentMismatch,
        );
    }

    #[test]
    fn short_and_long_outputs_refuse_before_repair() {
        for image in [&[1][..], &[1, 0, 0][..]] {
            refuse_before_repair(
                &[0, 0],
                &[effect(Role::Normal, &[0, 0], image)],
                &[],
                Error::Representation,
            );
        }
    }

    #[test]
    fn every_effect_is_validated_before_merging() {
        // The first two effects overlap, but the invalid last effect must be
        // detected before merging can report that overlap.
        let original = [0, 0];
        for (last, expected) in [
            (
                effect(Role::Kernel, &original, &[0, 0]),
                Error::ComponentMismatch,
            ),
            (
                effect(Role::Normal, &[9, 0], &[0, 0]),
                Error::ComponentMismatch,
            ),
            (effect(Role::Normal, &original, &[0]), Error::Representation),
        ] {
            let effects = [
                effect(Role::Normal, &original, &[1, 0]),
                effect(Role::Normal, &original, &[1, 0]),
                last,
            ];
            refuse_before_repair(&original, &effects, &[], expected);
        }
    }

    #[test]
    fn malformed_and_overlapping_integrity_fields_refuse() {
        let reversed = Range { start: 2, end: 1 };
        for fields in [
            vec![1..1],
            vec![0..4],
            vec![4..5],
            vec![reversed],
            vec![0..2, 1..3],
            vec![0..1, 0..1],
        ] {
            refuse_before_repair(
                &[0, 0, 0],
                &[effect(Role::Normal, &[0, 0, 0], &[1, 0, 0])],
                &fields,
                Error::Representation,
            );
        }
    }

    #[test]
    fn empty_fields_allow_composition_but_no_repair_changes() {
        let effects = [effect(Role::Normal, &[0, 0], &[1, 0])];
        assert_eq!(
            compose_component(Role::Normal, &[0, 0], &effects, &[], |merged| Ok(
                merged.to_vec()
            )),
            Ok(vec![1, 0])
        );
        assert_eq!(
            compose_component(Role::Normal, &[0, 0], &effects, &[], |_| Ok(vec![1, 2])),
            Err(Error::VerificationFailed)
        );
    }

    #[test]
    fn repair_cannot_modify_other_bytes_or_change_length() {
        let effects = [effect(Role::Normal, &[0, 0], &[1, 0])];
        for repaired in [vec![2, 9], vec![1], vec![1, 9, 0]] {
            assert_eq!(
                compose_component(
                    Role::Normal,
                    &[0, 0],
                    &effects,
                    &core::iter::once(1..2).collect::<Vec<_>>(),
                    |_| Ok(repaired),
                ),
                Err(Error::VerificationFailed)
            );
        }
    }

    #[test]
    fn repair_error_propagates() {
        assert_eq!(
            compose_component(
                Role::Normal,
                &[0],
                &[effect(Role::Normal, &[0], &[1])],
                &[],
                |_| Err(Error::Authentication),
            ),
            Err(Error::Authentication)
        );
    }

    fn refuse_extent_before_repair(
        original: &[u8],
        final_len: usize,
        effects: &[ComponentEffect<'_>],
        fields: &[Range<usize>],
        expected: Error,
    ) {
        assert_eq!(
            compose_component_with_extent(
                Role::Normal,
                original,
                final_len,
                effects,
                fields,
                |_| { panic!("invalid extent premise must refuse before repair") }
            ),
            Err(expected)
        );
    }

    #[test]
    fn one_grower_and_prefix_editor_compose_in_either_order_for_either_component() {
        let original = [10, 20, 30];
        for component in [Role::Normal, Role::Kernel] {
            for reverse in [false, true] {
                // Only a synthetic repair field, with no native growth claim.
                let mut effects = [
                    effect(component, &original, &[11, 20, 30, 0, 7, 0, 99]),
                    effect(component, &original, &[10, 21, 30]),
                ];
                if reverse {
                    effects.reverse();
                }
                let calls = Cell::new(0);
                let output = compose_component_with_extent(
                    component,
                    &original,
                    7,
                    &effects,
                    &core::iter::once(6..7).collect::<Vec<_>>(),
                    |merged| {
                        calls.set(calls.get() + 1);
                        // Every tail byte is owned, including both zero bytes.
                        // The owner's integrity byte is replaced by central repair.
                        assert_eq!(merged, &[11, 21, 30, 0, 7, 0, 0]);
                        let mut result = merged.to_vec();
                        result[6] = 69;
                        Ok(result)
                    },
                )
                .unwrap();
                assert_eq!(output, [11, 21, 30, 0, 7, 0, 69]);
                assert_eq!(calls.get(), 1);
                assert_eq!(original, [10, 20, 30]);
            }
        }
    }

    #[test]
    fn equal_growers_cannot_share_even_a_zero_tail() {
        let original = [0, 0];
        let effects = [
            effect(Role::Normal, &original, &[0, 0, 0, 0]),
            effect(Role::Normal, &original, &[0, 0, 0, 0]),
        ];
        refuse_extent_before_repair(&original, 4, &effects, &[], Error::Representation);
    }

    #[test]
    fn extent_requires_effects_exactly_one_grower_and_no_shrink() {
        refuse_extent_before_repair(&[0, 0], 4, &[], &[], Error::Unsupported);
        refuse_extent_before_repair(
            &[0, 0],
            4,
            &[effect(Role::Normal, &[0, 0], &[1, 0])],
            &[],
            Error::Representation,
        );
        refuse_extent_before_repair(
            &[0, 0],
            1,
            &[effect(Role::Normal, &[0, 0], &[1])],
            &[],
            Error::Representation,
        );
        for image in [&[1][..], &[1, 0, 0][..], &[1, 0, 0, 0, 0][..]] {
            refuse_extent_before_repair(
                &[0, 0],
                4,
                &[effect(Role::Normal, &[0, 0], image)],
                &[],
                Error::Representation,
            );
        }
    }

    #[test]
    fn all_extent_tags_bases_and_lengths_are_checked_before_prefix_merge() {
        let original = [0, 0];
        for (last, expected) in [
            (
                effect(Role::Kernel, &original, &[0, 0]),
                Error::ComponentMismatch,
            ),
            (
                effect(Role::Normal, &[0, 1], &[0, 0]),
                Error::ComponentMismatch,
            ),
            (
                effect(Role::Normal, &original, &[0, 0, 0]),
                Error::Representation,
            ),
        ] {
            let effects = [
                effect(Role::Normal, &original, &[1, 0, 0, 0]),
                effect(Role::Normal, &original, &[1, 0]),
                last,
            ];
            refuse_extent_before_repair(&original, 4, &effects, &[], expected);
        }
    }

    #[test]
    fn grower_and_prefix_editor_cannot_make_equal_overlapping_writes() {
        let original = [0, 0];
        let effects = [
            effect(Role::Normal, &original, &[1, 0, 0, 7]),
            effect(Role::Normal, &original, &[1, 0]),
        ];
        refuse_extent_before_repair(&original, 4, &effects, &[], Error::Unsupported);
    }

    #[test]
    fn integrity_can_straddle_original_end_only_through_supplied_repair() {
        let original = [0, 0, 9];
        let effects = [
            effect(Role::Normal, &original, &[1, 0, 99, 88, 7]),
            effect(Role::Normal, &original, &[0, 2, 77]),
        ];
        let calls = Cell::new(0);
        let output = compose_component_with_extent(
            Role::Normal,
            &original,
            5,
            &effects,
            &core::iter::once(2..4).collect::<Vec<_>>(),
            |merged| {
                calls.set(calls.get() + 1);
                assert_eq!(merged, &[1, 2, 9, 0, 7]);
                let mut result = merged.to_vec();
                result[2..4].copy_from_slice(&[3, 4]);
                Ok(result)
            },
        )
        .unwrap();
        assert_eq!(output, [1, 2, 3, 4, 7]);
        assert_eq!(calls.get(), 1);
        assert_eq!(original, [0, 0, 9]);
    }

    #[test]
    fn extent_integrity_ranges_must_be_nonempty_disjoint_and_within_final_bounds() {
        let original = [0, 0];
        let reversed = Range { start: 3, end: 2 };
        for fields in [
            vec![2..2],
            vec![reversed],
            vec![1..3, 2..4],
            vec![3..5],
            vec![5..6],
        ] {
            refuse_extent_before_repair(
                &original,
                4,
                &[effect(Role::Normal, &original, &[1, 0, 0, 7])],
                &fields,
                Error::Representation,
            );
        }
    }

    #[test]
    fn extent_repair_cannot_change_protected_prefix_tail_or_final_length() {
        let original = [0, 0];
        let effects = [effect(Role::Normal, &original, &[1, 0, 0, 0, 99])];
        for output in [
            vec![1, 1, 0, 0, 4], // Protected original prefix.
            vec![1, 0, 1, 0, 4], // Protected zero-valued tail.
            vec![1, 0, 0, 0],
            vec![1, 0, 0, 0, 4, 0],
        ] {
            assert_eq!(
                compose_component_with_extent(
                    Role::Normal,
                    &original,
                    5,
                    &effects,
                    &core::iter::once(4..5).collect::<Vec<_>>(),
                    |_| Ok(output),
                ),
                Err(Error::VerificationFailed)
            );
        }
        assert_eq!(
            compose_component_with_extent(Role::Normal, &original, 5, &effects, &[], |_| Err(
                Error::Authentication
            )),
            Err(Error::Authentication)
        );
    }

    #[test]
    fn same_length_wrapper_refuses_growth_while_explicit_extent_preserves_zero_tail() {
        let original = [0, 0];
        let effects = [effect(Role::Normal, &original, &[1, 0, 0, 7])];
        refuse_before_repair(&original, &effects, &[], Error::Representation);
        assert_eq!(
            compose_component_with_extent(Role::Normal, &original, 4, &effects, &[], |merged| Ok(
                merged.to_vec()
            )),
            Ok(vec![1, 0, 0, 7])
        );
    }

    #[test]
    fn explicit_unchanged_extent_matches_same_length_acceptance_and_refusals() {
        let original = [0, 0];
        for effects in [
            vec![],
            vec![effect(Role::Normal, &original, &[1, 0])],
            vec![effect(Role::Normal, &original, &[1])],
            vec![effect(Role::Normal, &original, &[1, 0, 0])],
            vec![effect(Role::Normal, &[0, 1], &[1, 0])],
            vec![effect(Role::Kernel, &original, &[1, 0])],
            vec![
                effect(Role::Normal, &original, &[1, 0]),
                effect(Role::Normal, &original, &[1, 0]),
            ],
            vec![
                effect(Role::Normal, &original, &[1, 0]),
                effect(Role::Normal, &original, &[0, 2]),
            ],
        ] {
            for fields in [vec![], vec![0..1], vec![0..0], vec![0..3], vec![0..1, 0..1]] {
                assert_eq!(
                    compose_component(Role::Normal, &original, &effects, &fields, |image| Ok(
                        image.to_vec()
                    )),
                    compose_component_with_extent(
                        Role::Normal,
                        &original,
                        original.len(),
                        &effects,
                        &fields,
                        |image| Ok(image.to_vec())
                    )
                );
            }
        }
    }
}
