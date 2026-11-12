//! Link-layout-independent fingerprint of the capacity discriminator, proved
//! from the image alone with `h8-asm` (no live query, no hand-rolled decoding).
//!
//! The discriminator does not run in place: the C initializer copies a block
//! out of Normal into low RAM, and the versioned contract calls it there.
//! `coverage::copied_checksum::relocated` resolves that copy, so each routine
//! decodes where it executes. `h8-asm` bounds every routine by control-flow
//! reachability; a gap (embedded data) refuses.
//!
//! Two builds of one discriminator differ only in link layout: where routines
//! sit, the addresses of the routines they call, and the addresses of their own
//! data and log handles. The fingerprint therefore orders routines by discovery
//! from the entry, replaces each call target with the callee's discovery index,
//! and renames link-time addresses one-to-one in first-use order. Everything
//! else is kept exactly: every instruction, every constant, every hardware
//! address and every call into resident code outside Normal.
//!
//! Renaming is allowed only where it cannot reach the bank decision:
//! - The query (everything up to the last call that is not into Normal code)
//!   is kept exactly, so the drive is asked the same question.
//! - Calls into Normal code (such as a diagnostic log) may only follow the
//!   query. Their argument setup may store only into the stack frame. The
//!   called code is not compared (each call hashes as one side token);
//!   instead each image's side closure is verified: it decodes completely,
//!   makes no indirect call or jump, never calls a resident service the query
//!   uses, and never names, as an address-sized immediate or absolute
//!   operand, a page the query or the decision uses outside the firmware's
//!   own code and data.
//! - The decision after the last call is kept exactly, is straight-line or
//!   forward-branching, and reads only registers it sets itself, so its result
//!   depends only on the hardware bytes the query produced.
//!
//! Anything outside this shape refuses: the proof can under-accept, never admit
//! two programs that could select differently on the same drive.
use crate::image::layout::Observation;
use crate::startup::coverage::copied_checksum;
use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::{vec, vec::Vec};
use core::ops::Range;
use h8_asm::isa::{decode_insn, Decoded, Ea, Encoding, Operand, Reg, Size};
use sha2::{Digest, Sha256};

const TARGET: h8_asm::Target = h8_asm::Target::H8S2000;
const MODE: h8_asm::Mode = h8_asm::Mode::Advanced;
const NORMAL_BASE: u32 = crate::image::KERNEL_BASE + crate::image::KERNEL_LEN as u32;
const SP: u8 = 7;
/// Bounds on the fingerprinted closure; a larger closure refuses.
const MAX_ROUTINES: usize = 32;
const MAX_BYTES: usize = 8 * 1024;

/// Bound one routine entered at `at`: require fully contiguous control-flow
/// coverage from the entry (a gap would be data we cannot equate), returning
/// the `[at, end)` byte range it occupies.
fn routine(image: &[u8], at: u32) -> Option<Range<usize>> {
    let starts = h8_asm::analysis::reachable(image, at, TARGET, MODE).ok()?;
    let mut next = at;
    for &start in &starts {
        if start != next {
            return None;
        }
        let len = h8_asm::isa::insn_len(image.get(start as usize..)?, TARGET, MODE)?;
        next = start.checked_add(len as u32)?;
    }
    Some(at as usize..next as usize)
}

/// Fingerprint the capacity discriminator called at `entry` (a RAM address).
/// `None` — refuse — unless the copy into RAM is recognized and the whole
/// closure has the shape described in the module documentation.
pub(super) fn digest(normal: &[u8], entry: u32) -> Option<[u8; 32]> {
    let Observation::Known(relocation) = copied_checksum::relocated(normal, entry, 1) else {
        return None;
    };
    let source = normal.get(relocation.source.clone())?;
    let block = relocation.destination..relocation.destination.checked_add(source.len() as u32)?;
    let space = Space {
        ram: source,
        block,
        normal,
        sections: &relocation.sections,
    };
    space.digest(entry)
}

/// The addresses one discriminator can execute or name.
struct Space<'a> {
    /// The verbatim copied block; its first byte executes at `block.start`.
    ram: &'a [u8],
    block: Range<u32>,
    /// Decoded Normal, executing at `NORMAL_BASE`.
    normal: &'a [u8],
    /// RAM the C initializer copies or clears: the firmware's own data.
    sections: &'a [Range<u32>],
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Place {
    /// Inside the copied block.
    Block,
    /// Inside Normal.
    Normal,
}

/// One decoded instruction at its executing address.
struct Insn {
    at: u32,
    d: Decoded,
}

impl Space<'_> {
    fn place(&self, address: u32) -> Option<Place> {
        if self.block.contains(&address) {
            Some(Place::Block)
        } else if (NORMAL_BASE..NORMAL_BASE.saturating_add(self.normal.len() as u32))
            .contains(&address)
        {
            Some(Place::Normal)
        } else {
            None
        }
    }

    /// A link-time address the firmware itself owns: its code or initialized
    /// data. Hardware and resident-service addresses are never in this set.
    fn owned(&self, address: u32) -> bool {
        self.place(address).is_some() || self.sections.iter().any(|s| s.contains(&address))
    }

    /// Decode the contiguous routine entered at `at`, in executing addresses.
    fn decode(&self, at: u32, place: Place) -> Option<Vec<Insn>> {
        let (image, base) = match place {
            Place::Block => (self.ram.get(..self.block.len())?, self.block.start),
            Place::Normal => (self.normal, NORMAL_BASE),
        };
        let span = routine(image, at.checked_sub(base)?)?;
        let mut out = Vec::new();
        let mut offset = span.start;
        while offset < span.end {
            let d = decode_insn(image.get(offset..span.end)?, TARGET, MODE).ok()?;
            out.push(Insn {
                at: base + offset as u32,
                d,
            });
            offset += d.len;
        }
        Some(out)
    }

    fn digest(&self, entry: u32) -> Option<[u8; 32]> {
        // The block is decoded at offsets from its destination, so those
        // offsets keep the executing addresses' parity (H8S fetches only
        // even addresses) only for an even destination, and the block must
        // lie inside the 24-bit address space it executes in.
        if self.block.start % 2 != 0 || self.block.end > 1 << 24 {
            return None;
        }
        if self.place(entry) != Some(Place::Block) {
            return None;
        }
        let fixed = self.fixed_interface(entry)?;
        let mut ordinals = BTreeMap::from([(entry, 0u32)]);
        let mut queue = VecDeque::from([entry]);
        let mut names = BTreeMap::new();
        let mut verified = BTreeSet::new();
        let mut hash = Sha256::new();
        let (mut routines, mut bytes) = (0usize, 0usize);
        while let Some(at) = queue.pop_front() {
            routines += 1;
            let insns = self.decode(at, Place::Block)?;
            bytes += insns.iter().map(|i| i.d.len).sum::<usize>();
            if routines > MAX_ROUTINES || bytes > MAX_BYTES {
                return None;
            }
            let side = if at == entry {
                self.entry_side_segment(&insns)?
            } else {
                0..0
            };
            hash.update(b"R");
            hash.update((insns.len() as u32).to_be_bytes());
            for (index, insn) in insns.iter().enumerate() {
                let renamed = side.contains(&index);
                let call = match call_target(insn) {
                    Call::None => None,
                    Call::Unsupported => return None,
                    Call::Direct(target) => Some(target),
                };
                if let Some(target) = call.filter(|&t| self.place(t) == Some(Place::Normal)) {
                    // Normal code runs only as a side call after the query.
                    if !renamed {
                        return None;
                    }
                    if verified.insert(target) {
                        self.verify_side(target, &fixed)?;
                    }
                }
                // The query and the decision are kept exactly, but their operands
                // are hashed by value only, never the bytes they point at. A read
                // of firmware-owned memory (Normal ROM or a copied data section)
                // would make the result depend on content the fingerprint does not
                // cover: two builds with identical code but differing owned bytes
                // could select different banks on one drive. Refuse when a
                // non-side instruction names an owned address as data. A direct
                // call target is the routine graph (handled above), so exclude it.
                if !renamed
                    && fixed_constants(insn)
                        .into_iter()
                        .filter(|&v| Some(v) != call)
                        .any(|v| self.owned(v))
                {
                    return None;
                }
                put_insn(&mut hash, insn, |operand_index, value, kind| {
                    if call.is_some() && operand_index == 0 {
                        return match self.place(value) {
                            Some(Place::Block) => {
                                let next = ordinals.len() as u32;
                                Token::Routine(*ordinals.entry(value).or_insert_with(|| {
                                    queue.push_back(value);
                                    next
                                }))
                            }
                            Some(Place::Normal) => Token::Side,
                            None => Token::Exact(value),
                        };
                    }
                    // A side-call argument is a link-time handle unless it lies
                    // on a page the query or the decision addresses.
                    let link_time = renamed
                        && matches!(kind, Kind::Immediate32 | Kind::Absolute)
                        && (self.owned(value) || !fixed.pages.contains(&page(value)));
                    if link_time {
                        let next = names.len() as u32;
                        Token::Name(*names.entry(value).or_insert(next))
                    } else {
                        Token::Exact(value)
                    }
                });
            }
        }
        Some(hash.finalize().into())
    }

    /// The fixed addresses the query and the decision use: the entry outside
    /// its side segment and every block routine it calls. Side code may not
    /// name these 64 KiB pages or call these resident services.
    fn fixed_interface(&self, entry: u32) -> Option<Fixed> {
        let mut fixed = Fixed {
            pages: BTreeSet::new(),
            services: BTreeSet::new(),
        };
        let mut seen = BTreeSet::from([entry]);
        let mut queue = VecDeque::from([entry]);
        let mut bytes = 0usize;
        while let Some(at) = queue.pop_front() {
            let insns = self.decode(at, Place::Block)?;
            // This closure is a subset of the one `digest` fingerprints, so
            // the same caps refuse here before decoding any further routine.
            bytes += insns.iter().map(|i| i.d.len).sum::<usize>();
            if seen.len() > MAX_ROUTINES || bytes > MAX_BYTES {
                return None;
            }
            let side = if at == entry {
                self.entry_side_segment(&insns)?
            } else {
                0..0
            };
            for (index, insn) in insns.iter().enumerate() {
                if side.contains(&index) {
                    continue;
                }
                if let Call::Direct(target) = call_target(insn) {
                    match self.place(target) {
                        Some(Place::Block) => {
                            if seen.insert(target) {
                                queue.push_back(target);
                            }
                        }
                        // Block routines may not call Normal code at all.
                        Some(Place::Normal) if at != entry => return None,
                        Some(Place::Normal) => {}
                        None => {
                            fixed.pages.insert(page(target));
                            fixed.services.insert(target);
                        }
                    }
                    continue;
                }
                for value in fixed_constants(insn) {
                    if !self.owned(value) {
                        fixed.pages.insert(page(value));
                    }
                }
            }
        }
        Some(fixed)
    }

    /// Split the entry routine and return the side-segment instruction range
    /// in which link-time addresses may be renamed. `None` refuses.
    fn entry_side_segment(&self, insns: &[Insn]) -> Option<Range<usize>> {
        let calls: Vec<(usize, Option<Place>)> = insns
            .iter()
            .enumerate()
            .filter_map(|(i, insn)| match call_target(insn) {
                Call::Direct(target) => Some((i, self.place(target))),
                _ => None,
            })
            .collect();
        let last_call = calls.last().map(|c| c.0);
        let query_end = calls
            .iter()
            .rev()
            .find(|c| c.1 != Some(Place::Normal))
            .map(|c| c.0);
        let side_calls: Vec<usize> = calls
            .iter()
            .filter(|c| c.1 == Some(Place::Normal))
            .map(|c| c.0)
            .collect();
        // Everything before the decision is straight-line, so the query, the
        // side calls and the decision run once each, in address order.
        let tail_start = last_call.map_or(0, |i| i + 1);
        if insns[..tail_start]
            .iter()
            .any(|i| branch_target(i).is_some())
        {
            return None;
        }
        check_decision(&insns[tail_start..])?;
        let side = match (query_end, side_calls.first(), side_calls.last()) {
            (_, None, _) => 0..0,
            (Some(query), Some(&first), Some(&last)) if first > query => query + 1..last + 1,
            _ => return None,
        };
        for insn in &insns[side.clone()] {
            if call_target(insn) == Call::None && !stores_only_to_stack(insn) {
                return None;
            }
        }
        Some(side)
    }

    /// Verify a side call's whole Normal closure without comparing it: it must
    /// decode completely, call only Normal code or resident services other than
    /// the query's, and never name or write a page the query or the decision
    /// uses. It therefore cannot change the hardware bytes the decision reads.
    fn verify_side(&self, entry: u32, fixed: &Fixed) -> Option<()> {
        let mut seen = BTreeSet::from([entry]);
        let mut queue = VecDeque::from([entry]);
        let mut bytes = 0usize;
        while let Some(at) = queue.pop_front() {
            let insns = self.decode(at, Place::Normal)?;
            bytes += insns.iter().map(|i| i.d.len).sum::<usize>();
            if seen.len() > MAX_ROUTINES || bytes > MAX_BYTES {
                return None;
            }
            for insn in &insns {
                match call_target(insn) {
                    Call::Unsupported => return None,
                    Call::Direct(target) => {
                        match self.place(target) {
                            Some(Place::Normal) => {
                                if seen.insert(target) {
                                    queue.push_back(target);
                                }
                            }
                            Some(Place::Block) => return None,
                            None if fixed.services.contains(&target) => return None,
                            None => {}
                        }
                        continue;
                    }
                    Call::None => {}
                }
                let named =
                    fixed_constants(insn)
                        .into_iter()
                        .chain(match store_destination(insn) {
                            Some(Ea::Absolute { value, .. }) => Some(value),
                            _ => None,
                        });
                for value in named {
                    if !self.owned(value) && fixed.pages.contains(&page(value)) {
                        return None;
                    }
                }
            }
        }
        Some(())
    }
}

/// Pages and resident services the query and the decision rely on.
struct Fixed {
    pages: BTreeSet<u8>,
    services: BTreeSet<u32>,
}

/// The 64 KiB page of an address in the 24-bit H8S advanced address space.
fn page(address: u32) -> u8 {
    (address >> 16) as u8
}

/// Address-sized constants an instruction names: 32-bit immediates, 24/32-bit
/// absolute addresses and 32-bit displacement bases.
fn fixed_constants(insn: &Insn) -> Vec<u32> {
    let ea = |ea: Ea| match ea {
        Ea::Absolute { value, bits } if bits >= 24 => Some(value),
        Ea::Displacement {
            value, bits: 32, ..
        } => Some(value as u32),
        _ => None,
    };
    insn.d
        .insn
        .operands
        .iter()
        .filter_map(|op| match *op {
            Operand::Immediate { value, bits: 32 } => Some(value),
            Operand::Address(e) => ea(e),
            Operand::IndexedMemory { address, .. } => ea(address),
            _ => None,
        })
        .collect()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Call {
    /// Not a call or jump.
    None,
    /// `JSR @aa` or `BSR` to a known target.
    Direct(u32),
    /// Any other `JSR`/`BSR`, and every `JMP` (including an absolute tail
    /// jump): outside the proven shape, so the proof refuses.
    Unsupported,
}

fn call_target(insn: &Insn) -> Call {
    match (insn.d.insn.mnemonic, insn.d.insn.operands[0]) {
        ("JSR", Operand::Address(Ea::Absolute { value, .. })) => Call::Direct(value),
        ("BSR", Operand::Address(Ea::PcRelative { value, .. })) => Call::Direct(
            insn.at
                .wrapping_add(insn.d.len as u32)
                .wrapping_add(value as u32),
        ),
        // A tail jump to another routine is outside the proven shape.
        ("JSR" | "BSR" | "JMP", _) => Call::Unsupported,
        _ => Call::None,
    }
}

const BRANCHES: &[&str] = &[
    "BRA", "BRN", "BT", "BF", "BHI", "BLS", "BCC", "BHS", "BCS", "BLO", "BNE", "BEQ", "BVC", "BVS",
    "BPL", "BMI", "BGE", "BLT", "BGT", "BLE",
];

/// The target of a conditional or unconditional branch, `None` for any other
/// instruction. A branch whose target is not PC-relative yields `u32::MAX`,
/// which is never an instruction address in a decoded tail, so it refuses.
fn branch_target(insn: &Insn) -> Option<u32> {
    if !BRANCHES.contains(&insn.d.insn.mnemonic) {
        return None;
    }
    match insn.d.insn.operands[0] {
        Operand::Address(Ea::PcRelative { value, .. }) => Some(
            insn.at
                .wrapping_add(insn.d.len as u32)
                .wrapping_add(value as u32),
        ),
        _ => Some(u32::MAX),
    }
}

fn sp_based(ea: Ea) -> bool {
    matches!(
        ea,
        Ea::Indirect(Reg::Long(SP))
            | Ea::PreDecrement(Reg::Long(SP))
            | Ea::PostIncrement(Reg::Long(SP))
            | Ea::Displacement {
                base: Reg::Long(SP),
                ..
            }
    )
}

/// The memory destination an instruction writes, if any is visible.
fn store_destination(insn: &Insn) -> Option<Ea> {
    match (insn.d.insn.mnemonic, insn.d.insn.operands[1]) {
        ("MOV", Operand::Address(ea)) => Some(ea),
        _ => None,
    }
}

/// Side-call argument setup: register moves, loads from memory, and stores
/// only into the stack frame. Any other memory operand refuses.
fn stores_only_to_stack(insn: &Insn) -> bool {
    let i = insn.d.insn;
    i.operands.iter().enumerate().all(|(n, op)| match op {
        Operand::Address(ea) => sp_based(*ea) || (i.mnemonic == "MOV" && n == 0),
        Operand::IndexedMemory { .. } => false,
        _ => true,
    })
}

/// Register parts: `E` (bits 31-16), `H` (15-8), `L` (7-0); index 8 is CCR.
const E: u8 = 1;
const H: u8 = 2;
const L: u8 = 4;
const CCR: usize = 8;

fn parts(reg: Reg) -> Option<(usize, u8)> {
    match reg {
        Reg::Byte(n) if n < 8 => Some((n as usize, H)),
        Reg::Byte(n) if n < 16 => Some((n as usize - 8, L)),
        Reg::Word(n) if n < 8 => Some((n as usize, H | L)),
        Reg::Word(n) if n < 16 => Some((n as usize - 8, E)),
        Reg::Long(n) if n < 8 => Some((n as usize, E | H | L)),
        Reg::Ccr => Some((CCR, 1)),
        _ => None,
    }
}

/// Registers an addressing mode reads (its base or index), as full longs.
fn ea_uses(ea: Ea, uses: &mut Parts) -> Option<()> {
    match ea {
        Ea::Indirect(r)
        | Ea::PreDecrement(r)
        | Ea::PostIncrement(r)
        | Ea::PostDecrement(r)
        | Ea::PreIncrement(r)
        | Ea::Displacement { base: r, .. }
        | Ea::Indexed { index: r, .. }
        | Ea::PcIndexed(r) => {
            let (n, _) = parts(r)?;
            uses.push((n, E | H | L));
        }
        Ea::Absolute { .. } | Ea::PcRelative { .. } => {}
        Ea::MemoryIndirect(_) | Ea::ExtendedIndirect(_) => return None,
    }
    Some(())
}

fn operand_uses(op: Operand, uses: &mut Parts) -> Option<()> {
    match op {
        Operand::None | Operand::Immediate { .. } => {}
        Operand::Register(r) => uses.push(parts(r)?),
        Operand::Address(ea) => ea_uses(ea, uses)?,
        Operand::IndexedMemory { .. } | Operand::Registers { .. } => return None,
    }
    Some(())
}

/// Register parts `(register, mask)` an instruction reads or writes.
type Parts = Vec<(usize, u8)>;

/// Conservative register reads and writes of one decision instruction.
/// `None` for any instruction outside the modeled set.
fn effects(insn: &Insn) -> Option<(Parts, Parts)> {
    let i = insn.d.insn;
    let (a, b) = (i.operands[0], i.operands[1]);
    let mut uses = Vec::new();
    let mut defs = Vec::new();
    let register = |op: Operand| match op {
        Operand::Register(r) => parts(r),
        _ => None,
    };
    match i.mnemonic {
        "MOV" => {
            operand_uses(a, &mut uses)?;
            match b {
                Operand::Register(r) => defs.push(parts(r)?),
                Operand::Address(ea) => ea_uses(ea, &mut uses)?,
                _ => return None,
            }
            defs.push((CCR, 1));
        }
        "SUB" | "XOR" if a == b && register(a).is_some() => {
            defs.push(register(a)?);
            defs.push((CCR, 1));
        }
        "ADD" | "SUB" | "AND" | "OR" | "XOR" | "CMP" | "ADDS" | "SUBS" | "INC" | "DEC" => {
            operand_uses(a, &mut uses)?;
            let target = register(b)?;
            uses.push(target);
            if i.mnemonic != "CMP" {
                defs.push(target);
            }
            if !matches!(i.mnemonic, "ADDS" | "SUBS") {
                defs.push((CCR, 1));
            }
        }
        "RTS" | "NOP" => {}
        m if BRANCHES.contains(&m) => {
            if !matches!(m, "BRA" | "BT" | "BRN" | "BF") {
                uses.push((CCR, 1));
            }
        }
        _ => return None,
    }
    Some((uses, defs))
}

/// The decision after the last call: forward branches stay inside it, and
/// every register it reads is written earlier on every path through it.
fn check_decision(tail: &[Insn]) -> Option<()> {
    let index_of = |address: u32| tail.iter().position(|i| i.at == address);
    let mut defined: Vec<Option<[u8; 9]>> = vec![None; tail.len() + 1];
    if !tail.is_empty() {
        defined[0] = Some([0; 9]);
    }
    for (index, insn) in tail.iter().enumerate() {
        let mut state = defined[index]?;
        let (uses, defs) = effects(insn)?;
        for (reg, mask) in uses {
            if reg != SP as usize && state[reg] & mask != mask {
                return None;
            }
        }
        for (reg, mask) in defs {
            state[reg] |= mask;
        }
        let merge = |slot: &mut Option<[u8; 9]>| {
            *slot = Some(match *slot {
                None => state,
                Some(old) => core::array::from_fn(|r| old[r] & state[r]),
            });
        };
        if let Some(target) = branch_target(insn) {
            let to = index_of(target).filter(|&t| t > index)?;
            merge(&mut defined[to]);
        }
        let falls_through = !matches!(insn.d.insn.mnemonic, "BRA" | "BT" | "RTS");
        if falls_through {
            if index + 1 == tail.len() {
                return None;
            }
            merge(&mut defined[index + 1]);
        }
    }
    Some(())
}

enum Kind {
    Immediate32,
    Absolute,
    Other,
}

enum Token {
    Exact(u32),
    Routine(u32),
    Name(u32),
    /// A verified side call into Normal code.
    Side,
}

fn put_token(hash: &mut Sha256, token: Token) {
    let (tag, value) = match token {
        Token::Exact(v) => (0u8, v),
        Token::Routine(v) => (1, v),
        Token::Name(v) => (2, v),
        Token::Side => (3, 0),
    };
    hash.update([tag]);
    hash.update(value.to_be_bytes());
}

fn put_reg(hash: &mut Sha256, reg: Reg) {
    let (tag, n) = match reg {
        Reg::Byte(n) => (0u8, n),
        Reg::Word(n) => (1, n),
        Reg::Long(n) => (2, n),
        Reg::Ccr => (3, 0),
        Reg::Exr => (4, 0),
        Reg::Mach => (5, 0),
        Reg::Macl => (6, 0),
        Reg::Vbr => (7, 0),
        Reg::Sbr => (8, 0),
    };
    hash.update([tag, n]);
}

/// Hash one instruction. `operand` maps each address-like value (call target,
/// 32-bit immediate, absolute address) to its canonical token.
fn put_insn(hash: &mut Sha256, insn: &Insn, mut operand: impl FnMut(usize, u32, Kind) -> Token) {
    let i = insn.d.insn;
    hash.update(i.mnemonic.as_bytes());
    hash.update([
        0,
        match i.size {
            None => 0,
            Some(Size::Byte) => 1,
            Some(Size::Word) => 2,
            Some(Size::Long) => 3,
        },
    ]);
    match i.encoding {
        Encoding::Standard => hash.update([0]),
        Encoding::DisplacementStoreAlias => hash.update([1]),
        Encoding::SxAlternative(v) => {
            hash.update([2]);
            hash.update(v.to_be_bytes());
        }
    }
    for (n, op) in i.operands.iter().enumerate() {
        match *op {
            Operand::None => hash.update([0]),
            Operand::Register(r) => {
                hash.update([1]);
                put_reg(hash, r);
            }
            Operand::Immediate { value, bits } => {
                hash.update([2, bits]);
                let kind = if bits == 32 {
                    Kind::Immediate32
                } else {
                    Kind::Other
                };
                put_token(
                    hash,
                    match kind {
                        Kind::Immediate32 => operand(n, value, kind),
                        _ => Token::Exact(value),
                    },
                );
            }
            Operand::Address(ea) => {
                hash.update([3]);
                put_ea(hash, insn, n, ea, &mut operand);
            }
            Operand::IndexedMemory {
                address,
                index_size,
                value,
                bits,
            } => {
                hash.update([4, index_size as u8, bits]);
                hash.update(value.to_be_bytes());
                put_ea(hash, insn, n, address, &mut operand);
            }
            Operand::Registers { first, last } => hash.update([5, first, last]),
        }
    }
}

fn put_ea(
    hash: &mut Sha256,
    insn: &Insn,
    n: usize,
    ea: Ea,
    operand: &mut dyn FnMut(usize, u32, Kind) -> Token,
) {
    let i = insn.d.insn;
    match ea {
        Ea::Absolute { value, bits } => {
            hash.update([7, bits]);
            let token = if bits >= 24 {
                operand(n, value, Kind::Absolute)
            } else {
                Token::Exact(value)
            };
            put_token(hash, token);
        }
        Ea::Indirect(r) => {
            hash.update([0]);
            put_reg(hash, r);
        }
        Ea::PostIncrement(r) => {
            hash.update([1]);
            put_reg(hash, r);
        }
        Ea::PreDecrement(r) => {
            hash.update([2]);
            put_reg(hash, r);
        }
        Ea::PostDecrement(r) => {
            hash.update([3]);
            put_reg(hash, r);
        }
        Ea::PreIncrement(r) => {
            hash.update([4]);
            put_reg(hash, r);
        }
        Ea::Displacement { base, value, bits } => {
            hash.update([5, bits]);
            put_reg(hash, base);
            // A 32-bit displacement is an array base address, not an offset.
            if bits == 32 {
                put_token(hash, operand(n, value as u32, Kind::Absolute));
            } else {
                hash.update(value.to_be_bytes());
            }
        }
        Ea::Indexed { index, value, bits } => {
            hash.update([6, bits]);
            put_reg(hash, index);
            hash.update(value.to_be_bytes());
        }
        Ea::PcRelative { value, bits } => {
            // A relative call target is a routine, not a displacement.
            if n == 0 && i.mnemonic == "BSR" {
                hash.update([8]);
                let target = insn
                    .at
                    .wrapping_add(insn.d.len as u32)
                    .wrapping_add(value as u32);
                put_token(hash, operand(n, target, Kind::Other));
            } else {
                hash.update([9, bits]);
                hash.update(value.to_be_bytes());
            }
        }
        Ea::PcIndexed(r) => {
            hash.update([10]);
            put_reg(hash, r);
        }
        Ea::MemoryIndirect(v) => hash.update([11, v]),
        Ea::ExtendedIndirect(v) => hash.update([12, v]),
    }
}

#[cfg(test)]
mod tests;
