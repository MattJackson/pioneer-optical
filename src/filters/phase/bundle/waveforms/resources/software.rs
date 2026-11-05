//! Software-table roles differ from the slim dispatcher's two motion roles.
//! Runtime addresses remain unproved producers, never inferred image tables.
use super::*;

/// Native source of one software motion table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Source {
    /// Sixty-four paired words stored in the image.
    Image(Range<usize>),
    /// Address selected by native code; its runtime producer is not yet proved.
    Runtime(u32),
}

/// Complete dispatcher and selector, without a correction or generation claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding {
    /// Complete native dispatcher through both coil calls and return.
    pub dispatch: Range<usize>,
    /// Complete selector through its pointer store and return.
    pub selector: Range<usize>,
    /// Native pointer slot shared by selector and dispatcher.
    pub pointer: u32,
    /// Native mode predicates paired with sources; None is the default branch.
    pub choices: Vec<(Option<u8>, Source)>,
}

/// Observe the complete software-table consumer and its mode selector.
/// Three ROM choices and four generated-table choices are separate native
/// representations; neither is silently reduced to the slim table roles.
pub fn observe(normal: &[u8]) -> Result<Binding, Error> {
    let Observation::Known(coils) = native::discover_pair(normal) else {
        return Err(Error::Unresolved);
    };
    let regions = crate::image::regions(normal).ok_or(Error::Unresolved)?;
    bundle::step_source(normal, &regions.stored, &coils).map_err(|_| Error::Unresolved)?;
    let dispatchers = sites(normal, &regions.stored, shapes::SOFTWARE_DISPATCH);
    let [at] = dispatchers.as_slice() else {
        return Err(Error::Unresolved);
    };
    let bytes = &normal[*at..*at + shapes::SOFTWARE_DISPATCH.len()];
    let first = bundle::resolve_call(normal, call(bytes, 31)).ok_or(Error::ResourceMismatch)?;
    let last = bundle::resolve_call(normal, call(bytes, 87)).ok_or(Error::ResourceMismatch)?;
    if first == last
        || !coils.functions.contains(&first)
        || !coils.functions.contains(&last)
        || bundle::resolve_call(normal, call(bytes, 63)) != Some(first)
    {
        return Err(Error::ResourceMismatch);
    }
    let pointer = word(bytes, 6);
    if pointer == 0 || pointer & 1 != 0 {
        return Err(Error::ResourceMismatch);
    }
    let mut selected = None;
    for (runtime, template, store) in [
        (false, shapes::SOFTWARE_ROM_SELECTOR, 44),
        (true, shapes::SOFTWARE_RUNTIME_SELECTOR, 52),
    ] {
        for selector in sites(normal, &regions.stored, template) {
            let body = &normal[selector..selector + template.len()];
            if word(body, store) != pointer {
                continue;
            }
            if selected.is_some() {
                return Err(Error::Unresolved);
            }
            let fields = if runtime {
                let modes = [body[7], body[11], body[15]];
                if modes != [1, 3, 2] && modes != [1, 4, 3] {
                    return Err(Error::ResourceMismatch);
                }
                alloc::vec![
                    (Some(modes[0]), 44),
                    (Some(modes[1]), 36),
                    (Some(modes[2]), 20),
                    (None, 28)
                ]
            } else {
                alloc::vec![(Some(1), 36), (Some(3), 28), (Some(4), 28), (None, 20)]
            };
            let mut choices = Vec::new();
            for (mode, field) in fields {
                let address = word(body, field);
                let source = if runtime {
                    if address == 0 || address & 1 != 0 {
                        return Err(Error::ResourceMismatch);
                    }
                    Source::Runtime(address)
                } else {
                    Source::Image(table(normal, address, 256)?)
                };
                choices.push((mode, source));
            }
            selected = Some(Binding {
                dispatch: *at..*at + shapes::SOFTWARE_DISPATCH.len(),
                selector: selector..selector + template.len(),
                pointer,
                choices,
            });
        }
    }
    selected.ok_or(Error::Unresolved)
}

/// Native producer wiring for runtime tables. Evaluator arithmetic is separate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Producer {
    /// Complete producer, including its mode-zero reporting tail.
    pub program: Range<usize>,
    /// Startup sequence invoking the producer once for every selected mode.
    pub initializer: Range<usize>,
    /// Native evaluator entries for the first and second words of each row.
    pub evaluators: [u32; 2],
}

/// Bind runtime writes to the selector's four buffers and startup invocations.
/// This proves the generation loop and its resource relationships, not the
/// evaluator arithmetic or equivalence to a different phase convention.
pub fn observe_producer(normal: &[u8]) -> Result<Producer, Error> {
    let consumer = observe(normal)?;
    if consumer
        .choices
        .iter()
        .any(|(_, source)| !matches!(source, Source::Runtime(_)))
    {
        return Err(Error::ResourceMismatch);
    }
    let regions = crate::image::regions(normal).ok_or(Error::Unresolved)?;
    let mut found = None;
    for template in [shapes::GENERATED_LOG, shapes::GENERATED_REPORT] {
        for at in sites(normal, &regions.stored, template) {
            let bytes = &normal[at..at + template.len()];
            let roles = [
                (Some(1), 82),
                (Some(bytes[41]), 46),
                (Some(bytes[37]), 70),
                (None, 58),
            ];
            if roles
                .iter()
                .zip(&consumer.choices)
                .any(|((mode, offset), (selected, source))| {
                    mode != selected || *source != Source::Runtime(word(bytes, *offset))
                })
            {
                continue;
            }
            let buffers = roles.map(|(_, offset)| word(bytes, offset));
            for (i, left) in buffers.iter().enumerate() {
                let end = left.checked_add(256).ok_or(Error::ResourceMismatch)?;
                if buffers[i + 1..]
                    .iter()
                    .any(|right| *left < right.saturating_add(256) && *right < end)
                    || (*left < consumer.pointer.saturating_add(4) && consumer.pointer < end)
                {
                    return Err(Error::ResourceMismatch);
                }
            }
            let evaluators = [call(bytes, 97), call(bytes, 123)];
            if evaluators[0] == evaluators[1] {
                return Err(Error::ResourceMismatch);
            }
            for address in evaluators {
                table(normal, address, 2)?;
            }
            let initializers = sites(normal, &regions.stored, shapes::GENERATED_INITIALIZER)
                .into_iter()
                .filter(|start| {
                    let body = &normal[*start..*start + shapes::GENERATED_INITIALIZER.len()];
                    body[7] == 1
                        && body[13] == bytes[37]
                        && body[19] == bytes[41]
                        && [3, 9, 15, 21]
                            .into_iter()
                            .all(|field| call(body, field) == 0x410000 + at as u32)
                })
                .collect::<Vec<_>>();
            let [start] = initializers.as_slice() else {
                return Err(Error::Unresolved);
            };
            if found.is_some() {
                return Err(Error::Unresolved);
            }
            found = Some(Producer {
                program: at..at + template.len(),
                initializer: *start..*start + shapes::GENERATED_INITIALIZER.len(),
                evaluators,
            });
        }
    }
    found.ok_or(Error::Unresolved)
}
