use super::*;

/// Which native template set the synthetic mechanism uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Convention {
    /// XD08/UD02D-type code: ascending loader, plain conversions.
    Direct,
    /// XS08U/UD04-type code: descending loader, mirrored conversions.
    Mirrored,
}

fn emit(template: Template) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(template.len() + 1);
    for (i, byte) in template.iter().enumerate() {
        let after_call = |n: usize| i >= n && template[i - n] == Some(0x5e);
        bytes.push(match byte {
            Some(b) => *b,
            // Call-target holes name 0x410000; other holes are registers.
            None if after_call(1) => 0x41,
            None if after_call(2) || after_call(3) => 0x00,
            None => 0xc8,
        });
    }
    if bytes.len() % 2 == 1 {
        bytes.push(0);
    }
    bytes
}

fn call(target: usize) -> [u8; 4] {
    let address = u32::try_from(target + BASE_ADDRESS).unwrap().to_be_bytes();
    [0x5e, address[1], address[2], address[3]]
}

/// Element sites written by [`install`], in [`Element`] order after the coil.
pub(crate) struct Sites {
    pub(crate) step: [usize; 2],
    pub(crate) loader: usize,
    pub(crate) base: usize,
    pub(crate) offset: usize,
    pub(crate) step_conversion: usize,
    pub(crate) mode: usize,
    pub(crate) controller: usize,
}

/// Install a complete synthetic mechanism bundle. `functions` are the decoded
/// offsets of the source-word-zero and source-word-one coil functions; the
/// rest of the bundle needs 320 bytes at `rest` and the step block 48 at `step`.
pub(crate) fn install(
    body: &mut [u8],
    rest: usize,
    step: usize,
    functions: [usize; 2],
    convention: Convention,
) -> Sites {
    let index = usize::from(convention == Convention::Mirrored);
    // Direct code gives the negative offset to source word zero (XD08 and
    // XS08U alike); the mirrored synthetic set moves it to word one.
    let (minus, plus) = (functions[index], functions[1 - index]);
    let mut at = step;
    let mut step_sites = [0; 2];
    for (n, (template, callee)) in [(STEP_MINUS, minus), (STEP_PLUS, plus)]
        .into_iter()
        .enumerate()
    {
        step_sites[n] = at;
        let mut block = emit(template);
        block.extend_from_slice(&[0x01, 0x00, 0x69, 0x51]);
        block.extend_from_slice(&call(callee));
        body[at..at + block.len()].copy_from_slice(&block);
        at += block.len();
    }
    assert!(at <= step + 48);
    let loader = if index == 0 {
        LOADER_ASCENDING
    } else {
        LOADER_DESCENDING
    };
    let mut at = rest;
    let mut place = |template: Template| {
        let bytes = emit(template);
        let site = at;
        body[at..at + bytes.len()].copy_from_slice(&bytes);
        at += bytes.len();
        site
    };
    let sites = Sites {
        step: step_sites,
        loader: place(loader),
        base: place(BASE[index]),
        offset: place(OFFSET[index]),
        step_conversion: place(STEP[index]),
        mode: place(MODE[index]),
        controller: place(CONTROLLER[index]),
    };
    assert!(at <= rest + 320, "{}", at - rest);
    sites
}

fn fixture(convention: Convention) -> (Vec<u8>, Sites) {
    let mut raw = crate::image::phase::tests::fixture(false);
    raw.resize(0x500, 0xff);
    let sites = install(&mut raw, 0x200, 0x380, [32, 160], convention);
    (raw, sites)
}

#[test]
fn direct_and_mirrored_template_sets_bind_to_distinct_conventions() {
    let (direct, _) = fixture(Convention::Direct);
    let (mirrored, _) = fixture(Convention::Mirrored);
    let a = bind(&direct).unwrap();
    let b = bind(&mirrored).unwrap();
    assert_eq!(a.coil, Assignment::Direct);
    assert_eq!(a.without_coil(), [0, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(b.without_coil(), [1, 2, 1, 1, 1, 1, 1, 0]);
}

#[test]
fn coil_operand_exchange_preserves_every_other_element() {
    for convention in [Convention::Direct, Convention::Mirrored] {
        let (raw, _) = fixture(convention);
        let swapped = native::correct_pair(&raw, Assignment::Swapped).unwrap();
        let (a, b) = (bind(&raw).unwrap(), bind(&swapped).unwrap());
        assert_eq!(b.coil, Assignment::Swapped);
        assert_eq!(a.without_coil(), b.without_coil());
    }
}

#[test]
fn every_missing_element_is_unbound_and_never_defaulted() {
    let (raw, sites) = fixture(Convention::Direct);
    let cases = [
        (sites.step[0], Element::StepOffsets),
        (sites.step[1], Element::StepOffsets),
        (sites.loader, Element::DspLoader),
        (sites.base, Element::CalibrationBase),
        (sites.offset, Element::CalibrationOffset),
        (sites.step_conversion, Element::CalibrationStep),
        (sites.mode, Element::ModeSign),
        (sites.controller, Element::ControllerMode),
    ];
    for (site, element) in cases {
        let mut broken = raw.clone();
        // Corrupt a fixed opcode byte inside the element (not a hole).
        let at = site
            + if element == Element::StepOffsets {
                2
            } else {
                0
            };
        broken[at] ^= 0x80;
        assert_eq!(bind(&broken), Err(Unbound::Missing(element)), "{element:?}");
    }
    let mut no_coil = raw.clone();
    no_coil[32] = 0xff;
    assert_eq!(bind(&no_coil), Err(Unbound::Missing(Element::Coil)));
}

#[test]
fn duplicate_or_mixed_element_sites_are_ambiguous() {
    let (raw, sites) = fixture(Convention::Direct);
    let (mirrored, mirror_sites) = fixture(Convention::Mirrored);
    let elements = [
        (
            mirror_sites.loader,
            emit(LOADER_DESCENDING).len(),
            Element::DspLoader,
        ),
        (
            mirror_sites.base,
            emit(BASE[1]).len(),
            Element::CalibrationBase,
        ),
        (
            mirror_sites.offset,
            emit(OFFSET[1]).len(),
            Element::CalibrationOffset,
        ),
        (
            mirror_sites.step_conversion,
            emit(STEP[1]).len(),
            Element::CalibrationStep,
        ),
        (mirror_sites.mode, emit(MODE[1]).len(), Element::ModeSign),
        (
            mirror_sites.controller,
            emit(CONTROLLER[1]).len(),
            Element::ControllerMode,
        ),
    ];
    for (mirror, len, element) in elements {
        // A second, differently mirrored copy of one element.
        let mut mixed = raw.clone();
        mixed[0x450..0x450 + len].copy_from_slice(&mirrored[mirror..mirror + len]);
        assert_eq!(
            bind(&mixed),
            Err(Unbound::Ambiguous(element)),
            "{element:?}"
        );
    }
    // Both step sub-blocks calling the same coil function.
    let mut same = raw.clone();
    let second_call = sites.step[1] + 20;
    assert_eq!(same[second_call], 0x5e);
    same[second_call..second_call + 4].copy_from_slice(&call(32));
    assert_eq!(bind(&same), Err(Unbound::Ambiguous(Element::StepOffsets)));
    // A step block calling an unrelated routine.
    let mut unrelated = raw.clone();
    unrelated[second_call..second_call + 4].copy_from_slice(&call(0x100));
    assert_eq!(
        bind(&unrelated),
        Err(Unbound::Missing(Element::StepOffsets))
    );
}

#[test]
fn step_block_follows_a_relocated_coil_entry_jump() {
    let (raw, sites) = fixture(Convention::Direct);
    let mut relocated = raw.clone();
    // Redirect the minus sub-block to a native JMP @aa:24 stub at 0x3e0 that
    // reaches the original word-zero function.
    let stub = 0x3e0;
    let target = u32::try_from(32 + BASE_ADDRESS).unwrap().to_be_bytes();
    relocated[stub..stub + 4].copy_from_slice(&[0x5a, target[1], target[2], target[3]]);
    let first_call = sites.step[0] + 20;
    relocated[first_call..first_call + 4].copy_from_slice(&call(stub));
    assert_eq!(bind(&relocated).unwrap(), bind(&raw).unwrap());
}

#[test]
fn effective_mode_sign_binds_inverted_branch_without_moving_negation() {
    for convention in [Convention::Direct, Convention::Mirrored] {
        let (mut raw, sites) = fixture(convention);
        let original = bind(&raw).unwrap();
        assert_eq!(raw[sites.mode + 6], 0x46);
        raw[sites.mode + 6] = 0x47;
        let changed = bind(&raw).unwrap();
        assert_eq!(changed.mode_sign, original.mode_sign ^ 1);
        raw[sites.mode + 6] = 0x44;
        assert_eq!(bind(&raw), Err(Unbound::Missing(Element::ModeSign)));
    }
}

#[test]
fn padded_ascending_address_program_is_bound_as_ascending() {
    let (mut raw, sites) = fixture(Convention::Mirrored);
    assert_eq!(LOADER_ASCENDING_PADDED.len(), LOADER_DESCENDING.len());
    raw[sites.loader..sites.loader + LOADER_ASCENDING_PADDED.len()]
        .copy_from_slice(&emit(LOADER_ASCENDING_PADDED));
    assert_eq!(bind(&raw).unwrap().loader, Loader::Ascending);
    for i in 0..LOADER_ASCENDING_PADDED.len() {
        raw[sites.loader + i] ^= 1;
        assert_eq!(bind(&raw), Err(Unbound::Missing(Element::DspLoader)), "{i}");
        raw[sites.loader + i] ^= 1;
    }
}

#[test]
fn mode_binding_checks_both_branches_through_the_arithmetic_join() {
    for convention in [Convention::Direct, Convention::Mirrored] {
        let (mut raw, sites) = fixture(convention);
        let template = MODE[usize::from(convention == Convention::Mirrored)];
        for (i, byte) in template.iter().enumerate() {
            if byte.is_none() || i == 6 {
                continue;
            }
            raw[sites.mode + i] ^= 0x80;
            assert_eq!(
                bind(&raw),
                Err(Unbound::Missing(Element::ModeSign)),
                "{convention:?} +{i}"
            );
            raw[sites.mode + i] ^= 0x80;
        }
    }
}

#[test]
fn full_step_offsets_rewrite_both_bound_sources_and_round_trip() {
    for convention in [Convention::Direct, Convention::Mirrored] {
        let (raw, sites) = fixture(convention);
        let before = bind(&raw).unwrap();
        let changed = rewrite_step_offsets(&raw, before.step_minus_source ^ 1).unwrap();
        let after = bind(&changed).unwrap();
        assert_eq!(after.step_minus_source, before.step_minus_source ^ 1);
        assert_eq!(
            Bundle {
                step_minus_source: before.step_minus_source,
                ..after
            },
            before
        );
        assert_eq!(
            rewrite_step_offsets(&changed, before.step_minus_source).unwrap(),
            raw
        );
        for (i, (a, b)) in raw.iter().zip(&changed).enumerate() {
            assert!(
                a == b
                    || sites
                        .step
                        .iter()
                        .any(|at| (*at..*at + STEP_PLUS.len()).contains(&i))
            );
        }
        for at in sites.step {
            let mut missing_call = raw.clone();
            missing_call[at + 20] = 0;
            assert_eq!(
                rewrite_step_offsets(&missing_call, 0),
                Err(Unbound::Missing(Element::StepOffsets))
            );
        }
    }
}
