//! Complete additional static dispatcher/ROM-selector waveform roles.
//! Resource identity follows the complete native consumers, never address order
//! or a presumed default waveform. Aliased roles remain distinct observations.
use super::*;

/// Static waveform roles beyond the two special motion and coefficient pairs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding {
    /// Whole native dispatcher, already linked to the two output functions.
    pub dispatch: Range<usize>,
    /// Whole ROM selector linked to that dispatcher's state and pointer slot.
    pub selector: Range<usize>,
    /// Ordinary dispatcher table, then selector default, modes 3/4, and mode 1.
    pub tables: [Range<usize>; 4],
}

/// Bind every ordinary/selector role through complete native static programs.
pub fn observe(normal: &[u8]) -> Result<Binding, Error> {
    let resources = super::observe(normal)?;
    let regions = crate::image::regions(normal).ok_or(Error::Unresolved)?;
    let dispatch = resources.dispatch;
    let (ordinary, pointer, mode) = match dispatch.len() {
        n if n == shapes::STATIC_DISPATCH.len() => (40, 68, 20),
        n if n == shapes::POINTER_DISPATCH.len() => (78, 100, 22),
        _ => return Err(Error::Unresolved),
    };
    let body = &normal[dispatch.clone()];
    let mut selectors = sites(normal, &regions.stored, shapes::SOFTWARE_ROM_SELECTOR)
        .into_iter()
        .filter(|at| {
            word(normal, at + 44) == word(body, pointer) && word(normal, at + 2) == word(body, mode)
        });
    let at = selectors.next().ok_or(Error::Unresolved)?;
    if selectors.next().is_some() {
        return Err(Error::Unresolved);
    }
    let selector = at..at + shapes::SOFTWARE_ROM_SELECTOR.len();
    let tables = [
        table(normal, word(body, ordinary), 256)?,
        table(normal, word(normal, at + 20), 256)?,
        table(normal, word(normal, at + 28), 256)?,
        table(normal, word(normal, at + 36), 256)?,
    ];
    let loader = loader::observe(normal).map_err(|_| Error::Unresolved)?;
    for data in &tables {
        if core::iter::once(&dispatch)
            .chain(core::iter::once(&selector))
            .chain(&resources.initializer)
            .chain(&loader.spans)
            .any(|code| data.start < code.end && code.start < data.end)
        {
            return Err(Error::ResourceMismatch);
        }
    }
    Ok(Binding {
        dispatch,
        selector,
        tables,
    })
}

/// Compare every role, including repeated references to an aliased table.
pub fn equivalent(target: &[u8], donor: &[u8]) -> Result<bool, Error> {
    let a = observe(target)?;
    let b = observe(donor)?;
    Ok(a.tables
        .iter()
        .zip(&b.tables)
        .all(|(a, b)| target[a.clone()] == donor[b.clone()]))
}

type Writes = Vec<(Range<usize>, Vec<u8>)>;

/// Exact data effects to merge with the existing special-motion/coefficient
/// effects. The caller must reject conflicting aliases and overlaps with code.
pub(crate) fn writes(target: &[u8], donor: &[u8]) -> Result<Writes, Error> {
    let a = observe(target)?;
    let b = observe(donor)?;
    Ok(a.tables
        .into_iter()
        .zip(b.tables)
        .map(|(a, b)| (a, donor[b].to_vec()))
        .collect())
}
