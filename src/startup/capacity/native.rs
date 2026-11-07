//! Complete native identification transaction, including its finite entry cut.
//!
//! These are per-role instruction/data certificates, not image or product
//! fingerprints. Every instruction and initial-data byte used by the proved
//! prefix is bound. Only explicit pointers to another covered role are
//! normalized; each pointer must resolve to that role and checked offset.
//! An unknown constructor, changed bound, extra writer or altered call refuses.
//!
//! The installed resident query/copy interfaces and stable completed controller
//! identification result remain the OEM callers' existing external contracts.
//! No capture identity, ROM-medium assumption or global boot proof is required.
use sha2::{Digest, Sha256};

mod shapes;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Transaction {
    /// Command4290, related controller setup, masked observation and return0
    /// exactly for(EF,14)/(C2,24); return1 otherwise.
    Jedec4290,
}

#[derive(Clone, Copy)]
enum Component {
    Normal,
    Kernel,
}
impl Component {
    fn base(self) -> u32 {
        match self {
            Self::Normal => 0x410000,
            Self::Kernel => 0x400000,
        }
    }
    fn image<'a>(self, normal: &'a [u8], kernel: &'a [u8]) -> &'a [u8] {
        match self {
            Self::Normal => normal,
            Self::Kernel => kernel,
        }
    }
}

struct Relocation {
    /// Byte offset within the complete role, excluding any opcode.
    at: usize,
    /// Three-byte native call/address operand or four-byte pointer.
    width: usize,
    /// Another covered role, never an unbound wildcard.
    role: usize,
    /// Includes a checked one-past bound for native copy/table endpoints.
    offset: u32,
}

struct Span {
    component: Component,
    start: usize,
    len: usize,
    digest: [u8; 32],
    relocations: &'static [Relocation],
}
impl Span {
    fn matches(&self, spans: &[Span], normal: &[u8], kernel: &[u8]) -> Option<()> {
        let image = self.component.image(normal, kernel);
        let bytes = image.get(self.start..self.start.checked_add(self.len)?)?;
        let mut hash = Sha256::new();
        let mut at = 0;
        for relocation in self.relocations {
            let end = relocation.at.checked_add(relocation.width)?;
            if relocation.at < at || !matches!(relocation.width, 3 | 4) {
                return None;
            }
            let target = spans.get(relocation.role)?;
            if relocation.offset as usize > target.len {
                return None;
            }
            let expected = target
                .component
                .base()
                .checked_add(u32::try_from(target.start).ok()?)?
                .checked_add(relocation.offset)?;
            let operand = bytes.get(relocation.at..end)?;
            let actual = operand
                .iter()
                .fold(0u32, |word, byte| (word << 8) | u32::from(*byte));
            if actual != expected {
                return None;
            }
            hash.update(bytes.get(at..relocation.at)?);
            hash.update(&[0; 4][..relocation.width]);
            at = end;
        }
        hash.update(bytes.get(at..)?);
        let digest: [u8; 32] = hash.finalize().into();
        (digest == self.digest).then_some(())
    }
}

/// Two complete native entry grammars: one compares the generation byte before
/// entering Normal, one does not. The receiver owns any temporary marker bridge.
struct Form {
    spans: &'static [Span],
    kernel_descriptor: usize,
    compares_generation: bool,
}
impl Form {
    fn matches(&self, normal: &[u8], kernel: &[u8]) -> Option<()> {
        // Native Kernel length/header checks precede the Normal query. Branding
        // and version are compared between the supplied components, not against
        // the evidence images used to establish the instruction semantics.
        let length = u32::from_be_bytes(normal.get(0x14..0x18)?.try_into().ok()?);
        if usize::try_from(length).ok()? != normal.len() || length > 0x1d0000 {
            return None;
        }
        if normal.get(..16)? != kernel.get(self.kernel_descriptor..self.kernel_descriptor + 16)?
            || normal.get(0x18..0x20)? != kernel.get(0x1008..0x1010)?
            || (self.compares_generation && normal.get(0x28)? != kernel.get(0xfe)?)
        {
            return None;
        }
        for span in self.spans {
            span.matches(self.spans, normal, kernel)?;
        }
        Some(())
    }
}

pub(super) fn discover(normal: &[u8], kernel: &[u8]) -> Option<Transaction> {
    if kernel.len() != 0x10000 {
        return None;
    }
    let mut matching = shapes::FORMS
        .iter()
        .filter(|form| form.matches(normal, kernel).is_some());
    matching.next()?;
    matching.next().is_none().then_some(Transaction::Jedec4290)
}

#[cfg(test)]
mod tests;
