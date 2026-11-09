//! Connected native method declarations. Calls have hypothetical continuations;
//! formal carriers here are syntax, never a callee preservation/runtime theorem.
use super::sink_boundaries::OwnedBody;
use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec,
    vec::Vec,
};
use core::ops::Range;
use h8_asm::{
    isa::{decode_insn, Decoded, Ea, Operand as O, Reg as R, Size},
    Mode, Target,
};
const BASE: u32 = 0x410000;
const WINDOW: usize = 4096;
#[derive(Clone)]
struct Node {
    span: Range<usize>,
    d: Decoded,
    next: Vec<usize>,
}
#[derive(Clone)]
struct Body {
    nodes: Vec<Node>,
}
impl Body {
    fn span(&self) -> Range<usize> {
        self.nodes[0].span.start..self.nodes.last().unwrap().span.end
    }
    fn path(&self, from: usize, to: usize, carriers: &[u8]) -> bool {
        let mut todo = vec![from];
        let mut seen = BTreeSet::new();
        while let Some(pc) = todo.pop() {
            if pc == to {
                return true;
            }
            if !seen.insert(pc) {
                continue;
            }
            let Ok(i) = self.nodes.binary_search_by_key(&pc, |n| n.span.start) else {
                continue;
            };
            let n = &self.nodes[i];
            if !carriers.iter().any(|&r| writes(n, r)) {
                todo.extend(&n.next);
            }
        }
        false
    }
    fn valid_prefix(&self) -> bool {
        let span = self.span();
        let mut todo = vec![span.start];
        let mut seen = BTreeSet::new();
        while let Some(pc) = todo.pop() {
            if pc >= span.end {
                continue;
            }
            if pc < span.start {
                return false;
            }
            if !seen.insert(pc) {
                continue;
            }
            let Ok(i) = self.nodes.binary_search_by_key(&pc, |n| n.span.start) else {
                return false;
            };
            todo.extend(&self.nodes[i].next);
        }
        seen.len() == self.nodes.len()
    }
    fn formal(&self, source: u8) -> Option<(u8, usize)> {
        self.nodes.iter().take(8).find_map(|n| {
            let (a, b) = copy(n)?;
            (a == source
                && b != source
                && b < 7
                && self.path(self.span().start, n.span.start, &[source]))
            .then_some((b, n.span.end))
        })
    }
}
fn alias(r: R) -> Option<u8> {
    match r {
        R::Byte(i) | R::Word(i) => Some(i & 7),
        R::Long(i) => Some(i),
        _ => None,
    }
}
fn writes(n: &Node, r: u8) -> bool {
    let ins = &n.d.insn;
    // Native self-MOVs set flags without changing their declared carrier.
    if ins.mnemonic == "MOV"
        && matches!(ins.operands, [O::Register(a), O::Register(b), O::None] if a == b)
    {
        return false;
    }
    if ins.operands.iter().any(
        |o| matches!(o,O::Address(Ea::PreDecrement(a)|Ea::PostIncrement(a)) if alias(*a)==Some(r)),
    ) {
        return true;
    }
    if matches!(
        ins.mnemonic,
        "CMP" | "BTST" | "JSR" | "BSR" | "JMP" | "RTS" | "STM"
    ) || ins.mnemonic.starts_with('B')
        && ins
            .operands
            .iter()
            .any(|o| matches!(o, O::Address(Ea::PcRelative { .. })))
    {
        return false;
    }
    match ins.operands.iter().rev().find(|o| **o != O::None) {
        Some(O::Register(a)) => alias(*a) == Some(r),
        Some(O::Registers { first, last }) => *first <= r && r <= *last,
        _ => false,
    }
}
fn long(n: &Node) -> bool {
    n.d.insn.mnemonic == "MOV" && n.d.insn.size == Some(Size::Long)
}
fn copy(n: &Node) -> Option<(u8, u8)> {
    if !long(n) {
        return None;
    }
    match n.d.insn.operands {
        [O::Register(R::Long(a)), O::Register(R::Long(b)), O::None] => Some((a, b)),
        _ => None,
    }
}
fn immediate(n: &Node) -> Option<(u32, u8)> {
    if !long(n) {
        return None;
    }
    match n.d.insn.operands {
        [O::Immediate { value, bits: 32 }, O::Register(R::Long(r)), O::None] => Some((value, r)),
        _ => None,
    }
}
fn load(n: &Node) -> Option<(u8, i32, u8)> {
    if !long(n) {
        return None;
    }
    match n.d.insn.operands {
        [O::Address(Ea::Displacement {
            base: R::Long(a),
            value,
            bits: 16,
        }), O::Register(R::Long(b)), O::None] => Some((a, value, b)),
        _ => None,
    }
}
fn store(n: &Node) -> Option<(u8, u8, i32)> {
    if !long(n) {
        return None;
    }
    match n.d.insn.operands {
        [O::Register(R::Long(a)), O::Address(Ea::Displacement {
            base: R::Long(b),
            value,
            bits: 16,
        }), O::None] => Some((a, b, value)),
        _ => None,
    }
}
fn add(n: &Node, a: u8, b: u8) -> bool {
    n.d.insn.mnemonic == "ADD"
        && n.d.insn.size == Some(Size::Long)
        && n.d.insn.operands == [O::Register(R::Long(a)), O::Register(R::Long(b)), O::None]
}
fn indirect(n: &Node, r: u8) -> bool {
    n.d.insn.mnemonic == "JSR" && n.d.insn.operands[0] == O::Address(Ea::Indirect(R::Long(r)))
}
fn offset(address: u32, n: &[u8]) -> Option<usize> {
    let p = usize::try_from(address.checked_sub(BASE)?).ok()?;
    (p & 1 == 0 && p < n.len()).then_some(p)
}
fn call(n: &Node, normal: &[u8]) -> Option<usize> {
    if n.d.insn.mnemonic != "JSR" {
        return None;
    }
    match n.d.insn.operands[0] {
        O::Address(Ea::Absolute { value, .. }) => offset(value, normal),
        _ => None,
    }
}
fn prologue(n: &[u8]) -> bool {
    matches!(
        n,
        [1, 0 | 0x10 | 0x20, 0x6d, 0xf0..=0xf6, ..] | [0x79, 0x37, _, _, ..]
    )
}
struct Search<'a> {
    normal: &'a [u8],
    stored: Vec<Range<usize>>,
    cache: BTreeMap<usize, Option<Body>>,
    exhausted: bool,
}
impl Search<'_> {
    fn contains(&self, span: &Range<usize>) -> bool {
        span.start < span.end
            && self
                .stored
                .iter()
                .any(|s| s.start <= span.start && span.end <= s.end)
    }
    fn body(&mut self, entry: usize) -> Option<Body> {
        if let Some(b) = self.cache.get(&entry) {
            return b.clone();
        }
        if self.cache.len() >= 2048 {
            self.exhausted = true;
            return None;
        }
        let b = self.decode(entry);
        self.cache.insert(entry, b.clone());
        b
    }
    fn node(&self, pc: usize, end: usize) -> Option<Node> {
        let d = decode_insn(self.normal.get(pc..end)?, Target::H8S2000, Mode::Advanced).ok()?;
        let next = pc.checked_add(d.len)?;
        if d.len == 0 || d.len & 1 != 0 || !self.contains(&(pc..next)) || next > end {
            return None;
        }
        let mut edges = Vec::new();
        match d.insn.mnemonic {
            "RTS" => {}
            "RTE" | "TRAPA" | "SLEEP" => return None,
            "JSR" | "BSR" => edges.push(next),
            "JMP" => {
                let O::Address(Ea::Absolute { value, .. }) = d.insn.operands[0] else {
                    return None;
                };
                edges.push(offset(value, self.normal)?);
            }
            name => {
                if let O::Address(Ea::PcRelative { value, .. }) = d.insn.operands[0] {
                    if !name.starts_with('B') {
                        return None;
                    }
                    edges.push(next.checked_add_signed(value as isize)?);
                    if name != "BRA" {
                        edges.push(next);
                    }
                } else {
                    edges.push(next);
                }
            }
        }
        if edges
            .iter()
            .any(|pc| pc & 1 != 0 || *pc >= self.normal.len())
        {
            return None;
        }
        Some(Node {
            span: pc..next,
            d,
            next: edges,
        })
    }
    fn decode(&self, entry: usize) -> Option<Body> {
        if entry & 1 != 0 || !prologue(self.normal.get(entry..)?) {
            return None;
        }
        let end = entry.checked_add(WINDOW)?.min(self.normal.len());
        let mut todo = vec![entry];
        let mut nodes = BTreeMap::new();
        let mut returns = 0;
        while let Some(pc) = todo.pop() {
            if nodes.contains_key(&pc) {
                continue;
            }
            if nodes.len() >= 2048 || !(entry..end).contains(&pc) {
                return None;
            }
            let n = self.node(pc, end)?;
            if n.d.insn.mnemonic == "RTS" {
                returns += 1;
            }
            todo.extend(&n.next);
            nodes.insert(pc, n);
        }
        let nodes: Vec<_> = nodes.into_values().collect();
        if returns == 0 || nodes.windows(2).any(|p| p[0].span.end != p[1].span.start) {
            return None;
        }
        Some(Body { nodes })
    }
    // Only a support prefix: exits beyond this cut and its entire tail retain
    // raw-reference scanning. No worker byte receives instruction ownership.
    fn worker(&mut self, entry: usize, child: &Child, caller: &Body) -> Option<WorkerLink> {
        if entry & 1 != 0 || !prologue(self.normal.get(entry..)?) {
            return None;
        }
        let end = entry.checked_add(WINDOW)?.min(self.normal.len());
        let mut pc = entry;
        let mut prefix = Body { nodes: Vec::new() };
        while pc < end && prefix.nodes.len() < 2048 {
            let n = self.node(pc, end)?;
            pc = n.span.end;
            if n.d.insn.mnemonic == "RTS" {
                return None;
            }
            prefix.nodes.push(n);
            let Some((carrier, formal)) = prefix.formal(0) else {
                continue;
            };
            let Some(pair) = prefix.nodes.get(prefix.nodes.len().saturating_sub(2)..) else {
                continue;
            };
            if pair.len() != 2
                || copy(&pair[0]) != Some((carrier, 0))
                || !prefix.path(formal, pair[0].span.start, &[carrier])
            {
                continue;
            }
            let Some(invoker_at) = call(&pair[1], self.normal) else {
                continue;
            };
            let Some(invoker) = self.body(invoker_at) else {
                continue;
            };
            let mut candidates = Vec::new();
            for (slot, delta) in invocation(&invoker, child) {
                let (method_at, method) = self.word(child.table, slot)?;
                let (adjust_at, _) = self.word(child.table, delta)?;
                if offset(method, self.normal) == Some(caller.span().start) {
                    candidates.push((method_at, adjust_at));
                }
            }
            candidates.sort_unstable();
            candidates.dedup();
            if candidates.is_empty() {
                continue;
            }
            if candidates.len() != 1 || !prefix.valid_prefix() {
                return None;
            }
            let call_site = pair[1].span.start;
            return Some(WorkerLink {
                prefix,
                invoker,
                call_site,
                method_at: candidates[0].0,
                adjust_at: candidates[0].1,
            });
        }
        self.exhausted = true;
        None
    }
    fn containing(&mut self, at: usize) -> Vec<Body> {
        (at.saturating_sub(WINDOW) & !1..=at)
            .step_by(2)
            .filter(|&p| prologue(&self.normal[p..]))
            .collect::<Vec<_>>()
            .into_iter()
            .filter_map(|p| self.body(p))
            .filter(|b| b.span().contains(&at))
            .collect()
    }
    fn word(&self, table: u32, field: i32) -> Option<(usize, u32)> {
        let address = table.checked_add_signed(field)?;
        let at = offset(address, self.normal)?;
        let span = at..at.checked_add(4)?;
        self.contains(&span).then_some(())?;
        Some((
            at,
            u32::from_be_bytes(self.normal.get(span)?.try_into().ok()?),
        ))
    }
}
struct WorkerLink {
    prefix: Body,
    invoker: Body,
    call_site: usize,
    method_at: usize,
    adjust_at: usize,
}
#[derive(Clone)]
struct Child {
    body: Body,
    table: u32,
    vptr: i32,
    field: i32,
}
fn child(body: &Body) -> Vec<Child> {
    let Some((parent, formal)) = body.formal(0) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (i, pair) in body.nodes.windows(2).enumerate() {
        let Some((table, source)) = immediate(&pair[0]) else {
            continue;
        };
        let Some((value, object, vptr)) = store(&pair[1]) else {
            continue;
        };
        if source != value || source == parent || source == object || object == parent {
            continue;
        }
        for (j, n) in body.nodes[..i].iter().enumerate() {
            if copy(n) != Some((0, object))
                || j == 0
                || body.nodes[j - 1].d.insn.mnemonic != "JSR"
                || !body.path(formal, n.span.start, &[parent])
                || !body.path(n.span.end, pair[0].span.start, &[parent, object])
            {
                continue;
            }
            for publication in &body.nodes[i + 2..] {
                let Some((value, base, field)) = store(publication) else {
                    continue;
                };
                if value == object
                    && base == parent
                    && body.path(pair[1].span.end, publication.span.start, &[parent, object])
                {
                    out.push(Child {
                        body: body.clone(),
                        table,
                        vptr,
                        field,
                    });
                }
            }
        }
    }
    out
}
// A typed trampoline reads the worker through this receiver's own vptr.
fn trampoline(b: &Body) -> Option<(i32, i32, i32)> {
    let (parent, formal) = b.formal(0)?;
    b.nodes.windows(5).find_map(|w| {
        let (a, vptr, table) = load(&w[0])?;
        let (t, function, f) = load(&w[1])?;
        let (t2, adjust, r) = load(&w[2])?;
        (a == parent
            && [parent, table, f, r].iter().collect::<BTreeSet<_>>().len() == 4
            && t == table
            && t2 == table
            && r == 0
            && add(&w[3], parent, r)
            && indirect(&w[4], f)
            && b.path(formal, w[0].span.start, &[parent]))
        .then_some((vptr, function, adjust))
    })
}
// No unresolved control or explicit carrier rewrite may occur after the loads.
fn invocation(b: &Body, child: &Child) -> Vec<(i32, i32)> {
    let mut declarations = Vec::new();
    let Some((parent, formal)) = b.formal(0) else {
        return declarations;
    };
    for (i, w) in b.nodes.windows(5).enumerate() {
        let Some((p, field, object)) = load(&w[0]) else {
            continue;
        };
        let Some((o, vptr, table)) = load(&w[1]) else {
            continue;
        };
        let Some((t, function, f)) = load(&w[2]) else {
            continue;
        };
        let Some((t2, adjust, a)) = load(&w[3]) else {
            continue;
        };
        if [parent, object, table, f, a]
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            != 5
            || f == 0
        {
            continue;
        }
        if p != parent
            || field != child.field
            || o != object
            || vptr != child.vptr
            || t != table
            || t2 != table
            || !add(&w[4], object, a)
            || !b.path(formal, w[0].span.start, &[parent])
        {
            continue;
        }
        for tail in b.nodes[i + 5..].windows(2).take(16) {
            if tail[1].span.start - w[4].span.end > 80 {
                break;
            }
            if copy(&tail[0]) == Some((a, 0)) && indirect(&tail[1], f) {
                let segment = &b.nodes[i + 5..];
                if segment
                    .iter()
                    .take_while(|n| n.span.start < tail[0].span.start)
                    .all(|n| {
                        n.next == [n.span.end]
                            && !matches!(n.d.insn.mnemonic, "JSR" | "BSR")
                            && ![parent, object, a, f].iter().any(|&r| writes(n, r))
                    })
                {
                    declarations.push((function, adjust));
                }
            }
        }
    }
    declarations.sort_unstable();
    declarations.dedup();
    declarations
}
// Static getter: immediate parent carrier, a parent-constructor call, and a
// declared return of that carrier. Opaque calls do not establish runtime bits.
fn parents(b: &Body, normal: &[u8]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    for n in b.nodes.iter().take(8) {
        let Some((value, r)) = immediate(n) else {
            continue;
        };
        if r == 0 || r == 7 || value == 0 || value & 1 != 0 {
            continue;
        }
        if !b.nodes.iter().any(|ret| {
            copy(ret) == Some((r, 0))
                && b.path(n.span.end, ret.span.start, &[r])
                && b.nodes.iter().any(|end| {
                    end.d.insn.mnemonic == "RTS" && b.path(ret.span.end, end.span.start, &[0])
                })
        }) {
            continue;
        }
        for pair in b.nodes.windows(2) {
            if copy(&pair[0]) == Some((r, 0)) && b.path(n.span.end, pair[0].span.start, &[r]) {
                if let Some(target) = call(&pair[1], normal) {
                    out.push((pair[1].span.start, target));
                }
            }
        }
    }
    out
}
type GraphSupport = (Vec<Range<usize>>, Vec<(usize, usize)>);
fn parent_graph(s: &mut Search<'_>, parent: &Body, c: &Child, caller: &Body) -> Vec<GraphSupport> {
    let mut out = Vec::new();
    let Some((receiver, formal)) = parent.formal(0) else {
        return out;
    };
    if receiver == 1 {
        return out;
    }
    for call_window in parent.nodes.windows(4) {
        let Some((descriptor, 1)) = immediate(&call_window[0]) else {
            continue;
        };
        if call_window[1].d.insn.mnemonic != "SUB"
            || call_window[1].d.insn.size != Some(Size::Byte)
            || call_window[1].d.insn.operands
                != [O::Register(R::Byte(10)), O::Register(R::Byte(10)), O::None]
            || writes(&call_window[1], receiver)
            || copy(&call_window[2]) != Some((receiver, 0))
            || !parent.path(formal, call_window[0].span.start, &[receiver])
        {
            continue;
        }
        let Some(base_at) = call(&call_window[3], s.normal) else {
            continue;
        };
        let Some(base) = s.body(base_at) else {
            continue;
        };
        if base.formal(0).is_none() {
            continue;
        }
        let Some((descriptor_reg, descriptor_formal)) = base.formal(1) else {
            continue;
        };
        for entry in base.nodes.windows(10) {
            let Some((entry_address, reg)) = immediate(&entry[0]) else {
                continue;
            };
            let Some((v, stack, slot)) = store(&entry[1]) else {
                continue;
            };
            let ins = |i: usize, mnemonic, size, operands| {
                entry[i].d.insn.mnemonic == mnemonic
                    && entry[i].d.insn.size == size
                    && entry[i].d.insn.operands == operands
            };
            let word = |base, value| {
                O::Address(Ea::Displacement {
                    base: R::Long(base),
                    value,
                    bits: 16,
                })
            };
            let Some(record) = slot.checked_sub(6) else {
                continue;
            };
            if v != reg
                || stack != 7
                || reg != 0
                || !base.path(descriptor_formal, entry[0].span.start, &[descriptor_reg])
                || !ins(
                    2,
                    "MOV",
                    Some(Size::Word),
                    [word(descriptor_reg, 2), O::Register(R::Word(6)), O::None],
                )
                || !ins(
                    3,
                    "MOV",
                    Some(Size::Word),
                    [O::Register(R::Word(6)), word(7, slot + 4), O::None],
                )
                || load(&entry[4]) != Some((descriptor_reg, 4, 6))
                || store(&entry[5]) != Some((6, 7, slot + 6))
                || !ins(
                    6,
                    "MOV",
                    Some(Size::Word),
                    [
                        O::Address(Ea::Indirect(R::Long(descriptor_reg))),
                        O::Register(R::Word(0)),
                        O::None,
                    ],
                )
                || copy(&entry[7]) != Some((7, 1))
                || !ins(
                    8,
                    "ADDS",
                    Some(Size::Long),
                    [
                        O::Immediate {
                            value: record as u32,
                            bits: 0,
                        },
                        O::Register(R::Long(1)),
                        O::None,
                    ],
                )
                || entry[9].d.insn.mnemonic != "JSR"
                || !matches!(
                    entry[9].d.insn.operands,
                    [O::Address(Ea::Absolute { bits: 24, .. }), O::None, O::None]
                )
            {
                continue;
            }
            let Some(entry_at) = offset(entry_address, s.normal) else {
                continue;
            };
            let Some(tramp) = s.body(entry_at) else {
                continue;
            };
            let Some((vptr, function, adjust)) = trampoline(&tramp) else {
                continue;
            };
            let Some(descriptor_at) = offset(descriptor, s.normal) else {
                continue;
            };
            let descriptor_span = descriptor_at..descriptor_at + 8;
            if !s.contains(&descriptor_span) {
                continue;
            }
            let descriptor_spans = vec![descriptor_span];
            for table_store in parent.nodes.windows(2) {
                let Some((table, r)) = immediate(&table_store[0]) else {
                    continue;
                };
                if r == receiver
                    || store(&table_store[1]) != Some((r, receiver, vptr))
                    || !parent.path(
                        call_window[3].span.end,
                        table_store[0].span.start,
                        &[receiver],
                    )
                {
                    continue;
                }
                let Some((function_at, worker_address)) = s.word(table, function) else {
                    continue;
                };
                let Some((adjust_at, _)) = s.word(table, adjust) else {
                    continue;
                };
                let Some(worker_at) = offset(worker_address, s.normal) else {
                    continue;
                };
                let Some(link) = s.worker(worker_at, c, caller) else {
                    continue;
                };
                let mut spans = vec![
                    parent.span(),
                    base.span(),
                    tramp.span(),
                    link.prefix.span(),
                    link.invoker.span(),
                    function_at..function_at + 4,
                    adjust_at..adjust_at + 4,
                    link.method_at..link.method_at + 4,
                    link.adjust_at..link.adjust_at + 4,
                ];
                spans.extend(descriptor_spans.clone());
                out.push((
                    spans,
                    vec![
                        (call_window[3].span.start, base_at),
                        (entry[0].span.start, entry_at),
                        (function_at, worker_at),
                        (link.call_site, link.invoker.span().start),
                        (link.method_at, caller.span().start),
                    ],
                ));
            }
        }
    }
    out
}
/// No caller seed grants ownership: production supplies only the fresh sink
/// diagnostic. This private result still needs the existing paired certificate.
pub(super) fn bind(normal: &[u8], kernel: &[u8], seed: usize) -> Option<Vec<OwnedBody>> {
    if kernel.len() != 0x10000 || normal.get(seed) != Some(&0) {
        return None;
    }
    let regions = crate::image::regions(normal)?;
    let stored = regions
        .stored
        .iter()
        .map(|b| {
            let at = b.as_ptr() as usize - normal.as_ptr() as usize;
            at..at + b.len()
        })
        .collect();
    let mut s = Search {
        normal,
        stored,
        cache: BTreeMap::new(),
        exhausted: false,
    };
    let mut matches = Vec::new();
    let owners = s.containing(seed);
    for owner in owners {
        if !super::sink_boundaries::crosses(
            &owner
                .nodes
                .iter()
                .map(|n| n.span.clone())
                .collect::<Vec<_>>(),
            seed,
            4,
        ) {
            continue;
        }
        let target = BASE.checked_add(u32::try_from(owner.span().start).ok()?)?;
        let sites: Vec<_> = (0..normal.len().saturating_sub(3))
            .step_by(2)
            .filter(|&at| {
                normal[at] == 0x5e
                    && u32::from_be_bytes([0, normal[at + 1], normal[at + 2], normal[at + 3]])
                        == target
            })
            .collect();
        for site in sites {
            for caller in s.containing(site) {
                if !caller
                    .nodes
                    .iter()
                    .any(|n| n.span.start == site && call(n, normal) == Some(owner.span().start))
                {
                    continue;
                }
                // Restrict candidate decoding to an actual native allocation-result
                // carrier followed by an immediate vptr store. This is only a
                // search prefilter; the complete constructor/path is bound below.
                let stores: Vec<_> = (0..normal.len().saturating_sub(11))
                    .step_by(2)
                    .filter(|&at| {
                        if normal[at] != 0x7a
                            || normal[at + 1] > 6
                            || normal[at + 6..at + 9] != [1, 0, 0x6f]
                            || normal[at + 9] & 0x80 == 0
                            || normal[at + 9] & 7 != normal[at + 1]
                        {
                            return false;
                        }
                        let object = (normal[at + 9] >> 4) & 7;
                        [2usize, 4].into_iter().any(|gap| {
                            at.checked_sub(gap).is_some_and(|copy| {
                                copy >= 4
                                    && normal[copy..copy + 2] == [0x0f, 0x80 | object]
                                    && normal[copy - 4] == 0x5e
                                    && (gap == 2 || normal[copy + 2] == 0x47)
                            })
                        })
                    })
                    .collect();
                let mut children = Vec::new();
                let mut seen = BTreeSet::new();
                for at in stores {
                    for body in s.containing(at) {
                        if seen.insert(body.span().start) {
                            children.extend(child(&body));
                        }
                    }
                }
                for c in children {
                    let child_address =
                        BASE.checked_add(u32::try_from(c.body.span().start).ok()?)?;
                    for at in (0..normal.len().saturating_sub(7)).step_by(2) {
                        if normal[at] != 0x5e
                            || normal[at + 4] != 0x5e
                            || u32::from_be_bytes([
                                0,
                                normal[at + 5],
                                normal[at + 6],
                                normal[at + 7],
                            ]) != child_address
                            || !s.contains(&(at..at + 8))
                        {
                            continue;
                        }
                        let getter_address =
                            u32::from_be_bytes([0, normal[at + 1], normal[at + 2], normal[at + 3]]);
                        let Some(getter_at) = offset(getter_address, normal) else {
                            continue;
                        };
                        let Some(getter) = s.body(getter_at) else {
                            continue;
                        };
                        for (parent_call, parent_at) in parents(&getter, normal) {
                            let Some(parent) = s.body(parent_at) else {
                                continue;
                            };
                            for (mut spans, mut edges) in parent_graph(&mut s, &parent, &c, &caller)
                            {
                                spans.extend([
                                    owner.span(),
                                    caller.span(),
                                    c.body.span(),
                                    getter.span(),
                                    at..at + 8,
                                ]);
                                spans.sort_by_key(|r| (r.start, r.end));
                                spans.dedup();
                                edges.extend([
                                    (parent_call, parent_at),
                                    (site, owner.span().start),
                                    (at, getter_at),
                                    (at + 4, c.body.span().start),
                                ]);
                                matches.push(vec![
                                    OwnedBody {
                                        instructions: owner
                                            .nodes
                                            .iter()
                                            .map(|n| n.span.clone())
                                            .collect(),
                                        supporting_spans: spans,
                                        root_edges: edges,
                                    },
                                    OwnedBody {
                                        instructions: caller
                                            .nodes
                                            .iter()
                                            .map(|n| n.span.clone())
                                            .collect(),
                                        supporting_spans: Vec::new(),
                                        root_edges: Vec::new(),
                                    },
                                ]);
                                if matches.len() > 1 {
                                    return None;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    if s.exhausted {
        None
    } else {
        matches.pop()
    }
}
