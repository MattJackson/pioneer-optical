//! Native loader-flag sink ownership. Host update-entry predicates are bound to
//! their opcode callback; image checks and persistent-bank checks retain their
//! separate owners. A missing comparison pattern is never an absence proof.
use crate::image::layout::Observation;
use alloc::{collections::BTreeSet, vec::Vec};
use core::ops::Range;
use h8_asm::{
    isa::{decode_insn, Ea, Operand},
    Mode, Target,
};

const BASE: u32 = 0x410000;
fn word(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}
fn offset(address: u32, normal: &[u8]) -> Option<usize> {
    let at = address.checked_sub(BASE)? as usize;
    (at & 1 == 0 && at < normal.len()).then_some(at)
}
fn stored(normal: &[u8], span: &Range<usize>) -> bool {
    crate::image::regions(normal).is_some_and(|regions| {
        regions.stored.iter().any(|bytes| {
            let at = bytes.as_ptr() as usize - normal.as_ptr() as usize;
            span.start >= at && span.end <= at + bytes.len()
        })
    })
}

/// Exact code/table spans establishing a host WRITE BUFFER callback's ownership.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostCommand {
    /// Opcode registry, initialized object pointer and complete callback table.
    pub tables: Vec<Range<usize>>,
    /// Every locally reachable callback instruction, including calls and returns.
    pub instructions: Vec<Range<usize>>,
}

/// Bind opcode 0x3b through its native object initializer to its main callback.
/// Call continuations here establish code ownership only: no callee return or
/// startup acceptance is inferred. Arbitrary indirect jumps and overlapping
/// instruction decodes refuse.
pub fn write_buffer(normal: &[u8], sink: usize) -> Option<HostCommand> {
    let regions = crate::image::regions(normal)?;
    let spans: Vec<_> = regions
        .stored
        .iter()
        .map(|bytes| {
            let at = bytes.as_ptr() as usize - normal.as_ptr() as usize;
            at..at + bytes.len()
        })
        .collect();
    let contains = |span: &Range<usize>| {
        spans
            .iter()
            .any(|stored| span.start >= stored.start && span.end <= stored.end)
    };
    let mut registries = Vec::new();
    for at in (0..normal.len().saturating_sub(256)).step_by(2) {
        if word(normal, at)? == 0 || word(normal, at)? >= 0x8000 || word(normal, at + 8)? != 0 {
            continue;
        }
        let slots: Vec<_> = (0..64).map(|i| word(normal, at + 4 * i).unwrap()).collect();
        if slots.iter().filter(|&&v| v == 0).count() >= 30
            && slots.iter().all(|&v| v < 0x8000)
            && [0, 1, 3, 4, 0x12, 0x3b, 0x3c]
                .iter()
                .all(|&i| slots[i] != 0)
            && contains(&(at..at + 256))
        {
            registries.push(at);
        }
    }
    let [registry] = registries.as_slice() else {
        return None;
    };
    let object = word(normal, registry + 0x3b * 4)?;
    if object & 1 != 0 {
        return None;
    }
    let mut initializers = Vec::new();
    for at in (0..normal.len().saturating_sub(14)).step_by(2) {
        if normal[at..at + 2] == [0x7a, 1]
            && normal[at + 6..at + 10] == [1, 0, 0x6b, 0xa1]
            && word(normal, at + 10)? == object
            && contains(&(at..at + 14))
        {
            initializers.push(at);
        }
    }
    let [initializer] = initializers.as_slice() else {
        return None;
    };
    let table = offset(word(normal, initializer + 2)?, normal)?;
    let bytes = normal.get(table..table + 40)?;
    if bytes[0x14..0x18] != [0; 4] || bytes[0x1e..0x22] != [0; 4] || !contains(&(table..table + 40))
    {
        return None;
    }
    for field in [0x10, 0x1a, 0x24] {
        offset(word(bytes, field)?, normal)?;
    }
    let entry = offset(word(bytes, 0x24)?, normal)?;
    // Native saved-register callback frame. Frame size and command-pointer
    // register allocation vary; ownership follows the actual registry edge.
    if normal.get(entry..entry + 10)? != [1, 0, 0x6d, 0xf3, 1, 0x20, 0x6d, 0xf4, 0x79, 0x37]
        || normal[entry + 11] & 1 != 0
    {
        return None;
    }
    let mut pending = alloc::vec![entry];
    let mut seen = BTreeSet::new();
    let mut instructions = Vec::new();
    let mut returns = 0;
    while let Some(at) = pending.pop() {
        if !seen.insert(at) {
            continue;
        }
        if seen.len() > 4096 || at < entry || at >= entry + 0x4000 {
            return None;
        }
        let decoded = decode_insn(normal.get(at..)?, Target::H8S2000, Mode::Advanced).ok()?;
        let next = at.checked_add(decoded.len)?;
        if !contains(&(at..next)) {
            return None;
        }
        instructions.push(at..next);
        let name = decoded.insn.mnemonic;
        match name {
            "RTS" => {
                returns += 1;
            }
            "RTE" | "TRAPA" => return None,
            "JSR" | "BSR" => pending.push(next),
            "JMP" => {
                let Operand::Address(Ea::Absolute { value, .. }) = decoded.insn.operands[0] else {
                    return None;
                };
                pending.push(offset(value, normal)?);
            }
            _ => {
                if let Operand::Address(Ea::PcRelative { value, .. }) = decoded.insn.operands[0] {
                    if !name.starts_with('B') {
                        return None;
                    }
                    pending.push(next.checked_add_signed(value as isize)?);
                    if name != "BRA" {
                        pending.push(next);
                    }
                } else {
                    pending.push(next);
                }
            }
        }
    }
    instructions.sort_by_key(|span| span.start);
    if returns != 1
        || !seen.contains(&sink)
        || instructions
            .windows(2)
            .any(|pair| pair[0].end > pair[1].start)
    {
        return None;
    }
    // The callback table is the only external literal entry. A new startup
    // call/alias into this command body cannot inherit command ownership.
    for span in &spans {
        for at in (span.start + (span.start & 1)..span.end.saturating_sub(3)).step_by(2) {
            let bytes = &normal[at..at + 4];
            let target = if bytes[0] == 0 {
                word(bytes, 0)
            } else if bytes[0] == 0x5e || bytes[0] == 0x5a {
                Some(address(&bytes[1..]))
            } else {
                None
            };
            if target
                .and_then(|value| offset(value, normal))
                .is_some_and(|value| seen.contains(&value))
                && !seen.contains(&at)
                && at != table + 0x24
            {
                return None;
            }
        }
    }
    Some(HostCommand {
        tables: alloc::vec![
            *registry..*registry + 256,
            *initializer..*initializer + 14,
            table..table + 40
        ],
        instructions,
    })
}

fn address(bytes: &[u8]) -> u32 {
    u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]])
}
fn shaped(bytes: &[u8], shape: &[u8], holes: &[(usize, usize)]) -> bool {
    bytes.len() == shape.len()
        && bytes
            .iter()
            .zip(shape)
            .enumerate()
            .all(|(i, (a, b))| a == b || holes.iter().any(|&(at, len)| (at..at + len).contains(&i)))
}

/// Every instruction-shaped direct/relative reference and aligned longword
/// address literal must have a classified owner. Address-taking and tails refuse.
fn calls(normal: &[u8], target: u32) -> Option<Vec<usize>> {
    let regions = crate::image::regions(normal)?;
    let mut found = Vec::new();
    for bytes in regions.stored {
        let start = bytes.as_ptr() as usize - normal.as_ptr() as usize;
        for (local, value) in bytes.windows(3).enumerate() {
            if value != &target.to_be_bytes()[1..] {
                continue;
            }
            let at = (start + local).checked_sub(1)?;
            if local == 0 || at & 1 != 0 {
                continue;
            }
            match normal[at] {
                0x5e => found.push(at),
                0 | 0x5a => return None,
                _ => {}
            }
        }
        for local in (start & 1..bytes.len()).step_by(2) {
            let at = start + local;
            let (length, delta) = if bytes.get(local) == Some(&0x55) {
                (2, i32::from(*bytes.get(local + 1)? as i8))
            } else if bytes.get(local..local + 2) == Some(&[0x5c, 0]) {
                (
                    4,
                    i32::from(i16::from_be_bytes(
                        bytes.get(local + 2..local + 4)?.try_into().ok()?,
                    )),
                )
            } else {
                continue;
            };
            if (BASE as i64 + at as i64 + length + i64::from(delta)) == i64::from(target) {
                // Current complete sink shapes use direct JSR. A relative
                // alias is evidence requiring another predicate, never ignored.
                return None;
            }
        }
    }
    Some(found)
}

// An instruction-shaped entry into a bound predicate must come from that
// predicate or its classified caller/table edge. This prevents a new branch
// from bypassing a comparison and entering an existing rejection tail.
fn closed_entries(normal: &[u8], scopes: &[(Range<usize>, Vec<usize>)]) -> Option<()> {
    for bytes in crate::image::regions(normal)?.stored {
        let start = bytes.as_ptr() as usize - normal.as_ptr() as usize;
        for local in (start & 1..bytes.len().saturating_sub(3)).step_by(2) {
            let at = start + local;
            let b = &bytes[local..];
            let target = match b[0] {
                0 => word(b, 0).and_then(|v| offset(v, normal)),
                0x5e | 0x5a => offset(address(&b[1..4]), normal),
                0x40..=0x4f | 0x55 => (at + 2).checked_add_signed(b[1] as i8 as isize),
                0x58 if b[1] & 15 == 0 => {
                    (at + 4).checked_add_signed(i16::from_be_bytes([b[2], b[3]]) as isize)
                }
                0x5c if b[1] == 0 => {
                    (at + 4).checked_add_signed(i16::from_be_bytes([b[2], b[3]]) as isize)
                }
                _ => None,
            };
            if target.is_some_and(|target| {
                scopes.iter().any(|(range, allowed)| {
                    range.contains(&target)
                        && !range.contains(&at)
                        && !allowed.contains(&at)
                        && !(target == range.start
                            && scopes.iter().any(|(owner, _)| owner.contains(&at)))
                })
            }) {
                return None;
            }
        }
    }
    Some(())
}

const CONSOLE: &[u8] = &[
    0x79, 0x37, 0, 0x10, 0x7a, 0x20, 0x19, 0x28, 0x37, 0x46, 0x46, 0x22, 0x0f, 0xf0, 0x19, 0x11,
    0x1a, 0xa2, 0xfa, 0x10, 0x5e, 0, 0, 0, 0x7a, 0, 0, 0x41, 0, 0, 0x7a, 0x30, 0, 0x40, 0, 0, 0x0f,
    0xf1, 0x79, 2, 0, 0x10, 0x5e, 0, 0, 0, 0x5e, 0, 0, 0, 0x18, 0x88, 0x79, 0x17, 0, 0x10, 0x54,
    0x70,
];
const CONSOLE_DISPATCH: &[u8] = &[
    1, 0, 0x6d, 0xf3, 1, 0x20, 0x6d, 0xf4, 0x1b, 0x97, 0x0f, 0xa6, 0x0f, 0x95, 0x0f, 0x83, 0x0a,
    0x93, 1, 0, 0x69, 0xf3, 0x68, 0x38, 0x55, 0xda, 0x0c, 0x8c, 0x0c, 0x84, 0x6e, 0x38, 0, 1, 0x55,
    0xd0, 0x0c, 0x8b, 0xac, 0x0d, 0x47, 0x6c, 0xab, 0x0d, 0x47, 0x68, 0x0c, 0x40, 0x18, 0x88, 0x0c,
    0xb9, 0x17, 0x51, 0x0d, 0x0c, 0x64, 0x1c, 0x1a, 0x91, 0xfc, 0x11, 0x7a, 2, 0, 0, 0, 0, 0x0f,
    0xa3, 0x69, 0x38, 0x1d, 0x8c, 0x47, 0x0a, 0x0b, 0x71, 0x0b, 0x83, 0x0b, 0x93, 0x1a, 0x0c, 0x46,
    0xf0, 0x7a, 0x21, 0, 0, 0, 0x11, 0x44, 0x1a, 0x0f, 0x90, 0x10, 0x30, 0x0a, 0x90, 0x10, 0x30,
    0x0a, 0xa0, 1, 0, 0x6f, 1, 0, 2, 0x0f, 0xe0, 0x5d, 0x10, 0x0c, 0x88, 0x47, 8, 0x40, 2, 0xf8, 5,
    0x5e, 0, 0, 0, 1, 0, 0x69, 0x71, 0x6e, 0x18, 0, 2, 0xa8, 0x0d, 0x46, 6, 0x1a, 0x91, 0xf9, 0x40,
    0x40, 0x10, 0x0b, 0xf5, 0x0f, 0xd1, 0x40, 0x0a, 0xf8, 5, 0x5e, 0, 0, 0, 0x1a, 0x91, 0xf9, 0x30,
    0x0f, 0x90, 0x0b, 0x97, 1, 0x20, 0x6d, 0x76, 1, 0, 0x6d, 0x73, 0x54, 0x70,
];

fn console(normal: &[u8], call: usize, reject: u32) -> Option<Vec<Range<usize>>> {
    let start = call.checked_sub(46)?;
    let body = normal.get(start..start + CONSOLE.len())?;
    if !shaped(body, CONSOLE, &[(21, 3), (43, 3), (47, 3)]) || address(&body[47..50]) != reject {
        return None;
    }
    let pointer = (BASE + start as u32).to_be_bytes();
    let entries: Vec<_> = normal
        .windows(6)
        .enumerate()
        .filter_map(|(at, b)| {
            (b[..2] == *b"KL" && b[2..] == pointer && stored(normal, &(at..at + 6))).then_some(at)
        })
        .collect();
    let [entry] = entries.as_slice() else {
        return None;
    };
    let mut table = *entry;
    while table >= 6 {
        let b = &normal[table - 6..table];
        if !b[..2].iter().all(|v| v.is_ascii_graphic()) || offset(word(b, 2)?, normal).is_none() {
            break;
        }
        table -= 6;
    }
    let mut dispatchers = Vec::new();
    for wide in [false, true] {
        let mut shape = CONSOLE_DISPATCH.to_vec();
        let shift = usize::from(wide) * 2;
        if wide {
            shape.splice(40..42, [0x58, 0x70, 0, 0x6c]);
        }
        for at in (0..normal.len().saturating_sub(shape.len())).step_by(2) {
            let b = &normal[at..at + shape.len()];
            let count = usize::from(b[61 + shift]);
            if !shaped(
                b,
                &shape,
                &[
                    (61 + shift, 1),
                    (91 + shift, 1),
                    (64 + shift, 4),
                    (123 + shift, 3),
                    (153 + shift, 3),
                ],
            ) || word(b, 64 + shift)? != BASE + table as u32
                || count == 0
                || b[91 + shift] as usize != count
                || *entry >= table + count * 6
            {
                continue;
            }
            let table_bytes = normal.get(table..table + count * 6)?;
            if !table_bytes.chunks_exact(6).all(|b| {
                b[..2].iter().all(|v| v.is_ascii_graphic())
                    && word(b, 2).and_then(|p| offset(p, normal)).is_some()
            }) {
                return None;
            }
            dispatchers.push((at..at + shape.len(), count));
        }
    }
    let [(dispatcher, count)] = dispatchers.as_slice() else {
        return None;
    };
    Some(alloc::vec![
        start..start + CONSOLE.len(),
        table..table + count * 6,
        dispatcher.clone()
    ])
}

/// Complete recognized Normal loader-flag predicate inventory. Independent
/// bank and image requirements are retained, never converted to startup words.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Certificate {
    /// Native spans which must remain unchanged through composed image edits.
    pub protected: Vec<Range<usize>>,
    /// Normal-owned rejection entry points; resident references need their own
    /// predicate binding and are never silently assigned to a Normal caller.
    pub entries: Vec<u32>,
}
impl Certificate {
    /// Refuse a resident direct call or literal alias to a Normal rejection
    /// entry. Its caller predicate is outside this Normal-owned certificate.
    pub fn accepts_kernel(&self, kernel: &[u8]) -> bool {
        !kernel.windows(4).enumerate().any(|(at, b)| {
            at & 1 == 0
                && self.entries.iter().any(|address| {
                    b == address.to_be_bytes()
                        || (b[0] == 0x5e || b[0] == 0x5a) && b[1..] == address.to_be_bytes()[1..]
                })
        })
    }
}

/// Bind all supported loader-flag references, refusing every unclassified one.
pub fn discover(normal: &[u8]) -> Option<Certificate> {
    let mut protected = Vec::new();
    let mut scopes = Vec::new();
    let Observation::Known(reader) = crate::image::layout::discover_h8_reader(normal, None) else {
        return None;
    };
    if reader.component != crate::image::layout::H8ReaderComponent::Normal {
        return None;
    }
    for function in reader.functions {
        let at = offset(function.address, normal)?;
        protected.push(at..at + function.bytes);
    }
    let service_calls = calls(normal, 0x400a1a)?;
    if service_calls.is_empty() {
        return None;
    }
    let bank = crate::startup::bank::discover(normal)?;
    let reject = offset(bank.reject_helper, normal)?;
    let mut entries = alloc::vec![bank.reject_helper];
    if normal.get(reject + 12..reject + 18)? != [0x18, 0x88, 0x55, 2, 0x54, 0x70] {
        return None;
    }
    let validator = offset(bank.validator, normal)?;
    if normal.get(validator + 0x92..validator + 0x9c)?
        != [1, 0x20, 0x6d, 0x76, 1, 0, 0x6d, 0x73, 0x54, 0x70]
    {
        return None;
    }
    protected.push(validator..validator + 0x9c);
    scopes.push((validator..validator + 0x9c, calls(normal, bank.validator)?));
    protected.push(reject..reject + 18);
    let mode_wrapper = offset(address(normal.get(reject + 3..reject + 6)?), normal)?;
    protected.push(mode_wrapper..mode_wrapper + 6);
    let reject_calls = calls(normal, bank.reject_helper)?;
    scopes.push((reject..reject + 18, reject_calls.clone()));
    for call in reject_calls {
        if call == validator + 0x8a {
            continue;
        }
        let console = console(normal, call, bank.reject_helper)?;
        let entry = BASE + console[0].start as u32;
        let table_call = (console[1].start..console[1].end)
            .step_by(6)
            .find(|&at| word(normal, at + 2) == Some(entry))?
            + 2;
        scopes.push((console[0].clone(), alloc::vec![table_call]));
        entries.push(entry);
        protected.extend(console);
    }
    let mut checksum_count = 0;
    let mut host_count = 0;
    for wrapper in service_calls {
        if normal.get(wrapper..wrapper + 6)? != [0x5e, 0x40, 0x0a, 0x1a, 0x54, 0x70] {
            return None;
        }
        protected.push(wrapper..wrapper + 6);
        entries.push(BASE + wrapper as u32);
        let wrapper_calls = calls(normal, BASE + wrapper as u32)?;
        scopes.push((wrapper..wrapper + 6, wrapper_calls.clone()));
        for call in wrapper_calls {
            if call == reject + 8 {
                continue;
            }
            if normal.get(call.checked_sub(2)?..call)? == [0x18, 0x88] {
                protected.push(call - 2..call + 4);
                scopes.push((call - 2..call + 4, Vec::new()));
                continue;
            }
            if let Some(at) = call.checked_sub(10) {
                if normal.get(at + 4..at + 10)? == [0x0f, 0x80, 0x47, 0x0c, 0xf8, 1]
                    && normal[at] == 0x5e
                    && normal.get(at + 14..at + 17)? == [0x18, 0x88, 0x5e]
                {
                    let entry = address(&normal[at + 1..at + 4]);
                    let Observation::Known(checksum) =
                        super::copied_checksum::discover(normal, entry)
                    else {
                        return None;
                    };
                    protected.extend([
                        at..at + 20,
                        0x2000..0x2004,
                        checksum.source,
                        checksum.initializer,
                    ]);
                    scopes.push((at..at + 20, Vec::new()));
                    protected.extend(checksum.helpers);
                    protected.extend(checksum.clear_helpers);
                    checksum_count += 1;
                    continue;
                }
            }
            if let Some(at) = call.checked_sub(18) {
                if normal.get(at..at + 18)?
                    == [
                        0x6a, 0x28, 0, 0x40, 0, 0xfe, 0x6a, 0x29, 0, 0x41, 0, 0x28, 0x1c, 0x89,
                        0x47, 0x0c, 0xf8, 1,
                    ]
                    && normal.get(at + 22..at + 25)? == [0x18, 0x88, 0x5e]
                {
                    protected.push(at..at + 28);
                    scopes.push((at..at + 28, Vec::new()));
                    continue;
                }
            }
            let host = write_buffer(normal, call)?;
            entries.push(BASE + host.instructions.first()?.start as u32);
            scopes.push((
                host.instructions.first()?.start..host.instructions.last()?.end,
                alloc::vec![host.tables.last()?.start + 0x24],
            ));
            protected.extend(host.tables);
            protected.extend(host.instructions);
            host_count += 1;
        }
    }
    if checksum_count != 1 || host_count != 1 {
        return None;
    }
    closed_entries(normal, &scopes)?;
    protected.sort_by_key(|span| (span.start, span.end));
    protected.dedup();
    entries.sort_unstable();
    entries.dedup();
    Some(Certificate { protected, entries })
}
