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
