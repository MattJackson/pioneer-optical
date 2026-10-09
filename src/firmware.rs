//! Generic H8 firmware facts. Does not allocate drive RAM or construct payloads.

mod error;
pub mod settings;
pub use error::Error;
/// Result of a read-only firmware inspection.
pub type Result<T> = core::result::Result<T, Error>;

/// Bounded symbolic analysis of memory-helper calling conventions.
pub mod abi {
    // Bounded symbolic tracing of OEM argument construction. Unknown instructions
    // are rejected. No model names, firmware revisions, or firmware addresses occur here.
    use super::{
        error::{ensure, Context},
        Error, Result,
    };
    use std::collections::BTreeMap;
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Byte {
        Unknown,
        Constant(u8),
        Object(u8),
        CdbPointer(u8),
        Cdb(u8),
    }
    type Value = [Byte; 4];
    const UNKNOWN: Value = [Byte::Unknown; 4];
    fn object() -> Value {
        std::array::from_fn(|i| Byte::Object(i as u8))
    }
    fn cdb_pointer() -> Value {
        std::array::from_fn(|i| Byte::CdbPointer(i as u8))
    }
    fn cdb24(first: u8) -> Value {
        [
            Byte::Constant(0),
            Byte::Cdb(first),
            Byte::Cdb(first + 1),
            Byte::Cdb(first + 2),
        ]
    }
    fn byte_location(r: u8) -> (usize, usize) {
        ((r & 7) as usize, if r & 8 == 0 { 2 } else { 3 })
    }
    fn word_location(r: u8) -> (usize, usize) {
        ((r & 7) as usize, if r & 8 == 0 { 2 } else { 0 })
    }
    fn u32be(b: &[u8]) -> u32 {
        u32::from_be_bytes(b[..4].try_into().unwrap())
    }
    fn offset(image: &[u8], base: u32, address: u32, n: usize) -> Result<&[u8]> {
        ensure!(address % 2 == 0, "unaligned H8 code target");
        let at = address
            .checked_sub(base)
            .context("code target below image")? as usize;
        image
            .get(at..at.checked_add(n).context("code range overflow")?)
            .context("code target outside image")
    }
    struct State {
        er: [Value; 8],
        stack: BTreeMap<i32, Byte>,
        sp: i32,
    }
    impl State {
        fn new() -> Self {
            let mut s = Self {
                er: [UNKNOWN; 8],
                stack: BTreeMap::new(),
                sp: 0,
            };
            s.er[0] = object();
            s.er[1] = cdb_pointer();
            s
        }
        fn get_byte(&self, r: u8) -> Byte {
            let (r, b) = byte_location(r);
            self.er[r][b]
        }
        fn set_byte(&mut self, r: u8, v: Byte) {
            let (r, b) = byte_location(r);
            self.er[r][b] = v;
        }
        fn load(&self, at: i32) -> Value {
            std::array::from_fn(|i| *self.stack.get(&(at + i as i32)).unwrap_or(&Byte::Unknown))
        }
        fn store(&mut self, at: i32, v: Value) {
            for (i, b) in v.into_iter().enumerate() {
                self.stack.insert(at + i as i32, b);
            }
        }
        fn push(&mut self, v: Value) {
            self.sp -= 4;
            self.store(self.sp, v);
        }
    }

    /// Follow `CDB[2]`'s dispatch and prove the helper arguments at the first call.
    /// ER0=object, R1L=direction, ER2=BE24(CDB[3..6]), stack=BE24(CDB[6..9]).
    /// Resolve a memory helper by tracing address, length and direction arguments.
    pub fn memory_call(
        image: &[u8],
        base: u32,
        main: u32,
        selector: u8,
        write: bool,
    ) -> Result<u32> {
        let mut state = State::new();
        let mut pc = main;
        let mut compare = None;
        let mut selected = false;
        use h8_asm::isa::{decode_insn, Ea, Operand as O, Reg as R, Size as S};
        for _ in 0..160 {
            offset(image, base, pc, 2)?;
            let decoded = decode_insn(
                &image[(pc - base) as usize..],
                h8_asm::Target::H8S2000,
                h8_asm::Mode::Advanced,
            )
            .map_err(|_| Error::Instruction { address: pc })?;
            let [first, second, third] = decoded.insn.operands;
            ensure!(third == O::None, "unsupported third ABI operand");
            match (decoded.insn.mnemonic, decoded.insn.size, first, second) {
                (
                    "STM",
                    Some(S::Long),
                    O::Registers { first, last },
                    O::Address(Ea::PreDecrement(R::Long(7))),
                ) => {
                    ensure!(last < 7 && last - first == 2, "unsupported saved registers");
                    for r in (first..=last).rev() {
                        state.push(state.er[r as usize]);
                    }
                }
                (
                    "MOV",
                    Some(S::Long),
                    O::Register(R::Long(r)),
                    O::Address(Ea::PreDecrement(R::Long(7))),
                ) => state.push(state.er[r as usize]),
                (
                    "MOV",
                    Some(S::Long),
                    O::Register(R::Long(r)),
                    O::Address(Ea::Indirect(R::Long(7))),
                ) => state.store(state.sp, state.er[r as usize]),
                (
                    "MOV",
                    Some(S::Long),
                    O::Register(R::Long(r)),
                    O::Address(Ea::Displacement {
                        base: R::Long(7),
                        value,
                        ..
                    }),
                ) => state.store(state.sp + value, state.er[r as usize]),
                (
                    "MOV",
                    Some(S::Long),
                    O::Address(Ea::Displacement {
                        base: R::Long(7),
                        value,
                        ..
                    }),
                    O::Register(R::Long(r)),
                ) => state.er[r as usize] = state.load(state.sp + value),
                ("SUB", Some(S::Word), O::Immediate { value, .. }, O::Register(R::Word(7))) => {
                    ensure!(
                        value > 0 && value < 4096 && state.sp >= -32,
                        "unsupported stack frame"
                    );
                    state.sp -= value as i32;
                }
                (
                    "MOV",
                    Some(S::Long),
                    O::Register(R::Long(source)),
                    O::Register(R::Long(destination)),
                ) => state.er[destination as usize] = state.er[source as usize],
                (
                    "MOV",
                    Some(S::Word),
                    O::Register(R::Word(source)),
                    O::Register(R::Word(destination)),
                ) => {
                    let (sr, sb) = word_location(source);
                    let (dr, db) = word_location(destination);
                    let value = [state.er[sr][sb], state.er[sr][sb + 1]];
                    state.er[dr][db..db + 2].copy_from_slice(&value);
                }
                (
                    "MOV",
                    Some(S::Byte),
                    O::Register(R::Byte(source)),
                    O::Register(R::Byte(destination)),
                ) => state.set_byte(destination, state.get_byte(source)),
                (
                    "SUB",
                    Some(S::Byte),
                    O::Register(R::Byte(source)),
                    O::Register(R::Byte(destination)),
                ) => {
                    ensure!(source == destination, "unsupported byte subtraction");
                    state.set_byte(destination, Byte::Constant(0));
                }
                ("AND", Some(S::Byte), O::Immediate { value, .. }, O::Register(R::Byte(r))) => {
                    let value = match state.get_byte(r) {
                        Byte::Constant(v) => Byte::Constant(v & value as u8),
                        _ => Byte::Unknown,
                    };
                    state.set_byte(r, value);
                }
                ("MOV", Some(S::Byte), O::Immediate { value, .. }, O::Register(R::Byte(r))) => {
                    state.set_byte(r, Byte::Constant(value as u8))
                }
                (
                    "MOV",
                    Some(S::Byte),
                    O::Register(R::Byte(r)),
                    O::Address(Ea::Displacement {
                        base: R::Long(7),
                        value,
                        ..
                    }),
                ) => {
                    state.stack.insert(state.sp + value, state.get_byte(r));
                }
                (
                    "MOV",
                    Some(S::Byte),
                    O::Address(Ea::Displacement {
                        base: R::Long(base_reg),
                        value,
                        ..
                    }),
                    O::Register(R::Byte(r)),
                ) => {
                    let value = if base_reg == 7 {
                        *state
                            .stack
                            .get(&(state.sp + value))
                            .unwrap_or(&Byte::Unknown)
                    } else {
                        ensure!(
                            state.er[base_reg as usize] == cdb_pointer()
                                && (0..16).contains(&value),
                            "unproven CDB byte load"
                        );
                        Byte::Cdb(value as u8)
                    };
                    state.set_byte(r, value);
                }
                ("CMP", Some(S::Byte), O::Immediate { value, .. }, O::Register(R::Byte(r))) => {
                    ensure!(
                        state.get_byte(r) == Byte::Cdb(2),
                        "dispatch comparison is not CDB selector"
                    );
                    compare = Some(value == u32::from(selector));
                }
                ("BEQ", None, O::Address(Ea::PcRelative { value, .. }), O::None) => {
                    let taken = compare.take().ok_or(Error::Unsupported {
                        context: "conditional branch without selector comparison",
                    })?;
                    if taken {
                        ensure!(!selected, "multiple selected dispatch branches");
                        selected = true;
                        pc = (i64::from(pc) + decoded.len as i64 + i64::from(value))
                            .try_into()
                            .context("branch target overflow")?;
                        continue;
                    }
                }
                ("JSR", None, O::Address(Ea::Absolute { value, bits: 24 }), O::None) => {
                    ensure!(selected, "helper call before selecting memory command");
                    ensure!(
                        state.er[0] == object(),
                        "helper object argument is not the original object"
                    );
                    ensure!(
                        state.get_byte(9) == Byte::Constant(u8::from(write)),
                        "helper direction argument differs"
                    );
                    ensure!(
                        state.er[2] == cdb24(3),
                        "helper address is not the CDB 24-bit address"
                    );
                    ensure!(
                        state.load(state.sp) == cdb24(6),
                        "helper stack length is not the CDB 24-bit length"
                    );
                    offset(image, base, value, 2)?;
                    return Ok(value);
                }
                _ => return Err(Error::Instruction { address: pc }),
            }
            pc = pc
                .checked_add(decoded.len as u32)
                .context("instruction address overflow")?;
        }
        Err(Error::Limit {
            context: "memory helper instruction budget",
        })
    }

    /// Validate both observed stack-save encodings by their ABI, and derive the
    /// invalid-field helper from the controller end-bound failure edge.
    /// Resolve the controller error target from a recognized memory helper.
    pub fn controller_error(image: &[u8], base: u32, helper: u32) -> Result<u32> {
        let h = offset(image, base, helper, 40)?;
        let (save, stack, restore) = if h[..2] == [0x6d, 0xf3] {
            (2, 14, &[0x6d, 0x73][..])
        } else {
            ensure!(h[..4] == [1, 0, 0x6d, 0xf3], "unknown helper save ABI");
            (4, 16, &[1, 0, 0x6d, 0x73][..])
        };
        let p = &h[save..];
        ensure!(
            p[..4] == [1, 0x20, 0x6d, 0xf4],
            "helper callee-save set differs"
        );
        ensure!(
            p[4] == 0x0f && p[5] & 0xf8 == 0xa0 && (3..=6).contains(&(p[5] & 7)),
            "helper address not saved in callee register"
        );
        ensure!(
            p[6] == 0x0c && p[7] >> 4 == 9 && (3..=6).contains(&(p[7] & 7)),
            "helper direction not saved in callee register"
        );
        ensure!(
            p[8..16] == [0x0f, 0x85, 0x0f, 0xa1, 1, 0, 0x6f, 0x76]
                && u16::from_be_bytes([p[16], p[17]]) == stack + 4,
            "helper stack argument ABI differs"
        );
        ensure!(
            p[18..28] == [0x0a, 0xe2, 0x0f, 0xa0, 0x7a, 0x22, 0, 0x40, 0, 0],
            "helper end-bound calculation differs"
        );
        let branch = helper + save as u32 + 28;
        let b = offset(image, base, branch, 4)?;
        let error = if b[..2] == [0x43, 8] {
            branch + 2
        } else {
            ensure!(b[..2] == [0x58, 0x20], "unsupported end-bound branch");
            (branch as i64 + 4 + i16::from_be_bytes([b[2], b[3]]) as i64)
                .try_into()
                .context("error branch overflow")?
        };
        let e = offset(image, base, error, 8)?;
        ensure!(e[0] == 0x5e, "bound failure does not call error helper");
        let invalid = u32be(e) & 0xffffff;
        let thunk = offset(image, base, invalid, 8)?;
        ensure!(
            thunk[..3] == [0xf8, 0xcc, 0x5e] && thunk[6..] == [0x54, 0x70],
            "invalid-field thunk differs"
        );
        offset(image, base, u32be(&thunk[2..6]) & 0xffffff, 2)?;
        let failure = if e[4] == 0x5a {
            u32be(&e[4..8]) & 0xffffff
        } else {
            error + 4
        };
        let tail = offset(image, base, failure, 2 + 4 + restore.len() + 2)?;
        ensure!(
            tail[..6] == [0xf8, 1, 1, 0x20, 0x6d, 0x76]
                && tail[6..6 + restore.len()] == *restore
                && tail[6 + restore.len()..] == [0x54, 0x70],
            "helper error return does not restore its ABI frame"
        );
        Ok(invalid)
    }

    #[cfg(test)]
    mod tests {
        include!("firmware_abi_tests.rs");
    }
}

/// Structural memory layout inspection.
pub mod layout {
    use super::{error::ensure, Error, Result};
    use serde::{Deserialize, Serialize};

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    /// Half-open CPU address interval.
    #[serde(try_from = "RangeBounds")]
    pub struct Range {
        /// Inclusive CPU start address.
        start: u32,
        /// Exclusive CPU end address.
        end: u32,
    }

    #[derive(Deserialize)]
    struct RangeBounds {
        start: u32,
        end: u32,
    }
    impl TryFrom<RangeBounds> for Range {
        type Error = Error;
        fn try_from(value: RangeBounds) -> Result<Self> {
            Self::from_bounds(value.start, value.end)
        }
    }

    impl Range {
        /// Construct a nonempty interval with checked arithmetic.
        pub fn new(start: u32, length: u32) -> Result<Self> {
            if length == 0 {
                return Err(Error::Malformed {
                    context: "empty interval",
                });
            }
            let end = start.checked_add(length).ok_or(Error::OutOfRange {
                context: "range overflow",
            })?;
            Ok(Self { start, end })
        }

        /// Construct a nonempty interval from its inclusive start and exclusive end.
        pub fn from_bounds(start: u32, end: u32) -> Result<Self> {
            let length = end.checked_sub(start).ok_or(Error::Malformed {
                context: "reversed interval",
            })?;
            Self::new(start, length)
        }
        /// Inclusive CPU start address.
        pub fn start(&self) -> u32 {
            self.start
        }
        /// Exclusive CPU end address.
        pub fn end(&self) -> u32 {
            self.end
        }
        /// Number of bytes in this nonempty interval.
        pub fn length(&self) -> u32 {
            self.end - self.start
        }

        /// Whether two intervals intersect.
        pub fn overlaps(&self, other: &Self) -> bool {
            self.start < other.end && other.start < self.end
        }

        /// Whether this interval contains the other.
        pub fn contains(&self, other: &Self) -> bool {
            self.start <= other.start && other.end <= self.end
        }
    }

    #[derive(Clone, Debug, Serialize)]
    /// One recognized OEM buffer descriptor.
    pub struct BufferEntry {
        /// OEM buffer identifier.
        pub id: u8,
        /// Controller-relative start; None represents the OEM unspecified sentinel.
        pub controller_start: Option<u32>,
        /// Length in bytes; None represents the OEM unspecified sentinel.
        pub length: Option<u32>,
    }

    #[derive(Clone, Debug, Serialize)]
    /// An OEM buffer table and the code references supporting its identification.
    pub struct BufferTable {
        /// Byte offset in the decoded image.
        pub image_offset: usize,
        /// Instruction offsets referencing this table.
        pub reference_offsets: Vec<usize>,
        /// Decoded descriptors.
        pub entries: Vec<BufferEntry>,
    }

    #[derive(Clone, Debug, Serialize)]
    /// Structural firmware memory facts; gaps are not runtime allocation guarantees.
    pub struct Layout {
        /// Whether the image has a recognized UHD layout.
        pub is_uhd: bool,
        /// Decoded image CPU base.
        pub image_base: Option<u32>,
        /// Recognized overlay destination intervals.
        pub overlay_ranges: Vec<Range>,
        /// Recognized OEM buffer maps.
        pub buffer_tables: Vec<BufferTable>,
        /// Aligned end of recognized overlays.
        pub overlay_tail: Option<u32>,
        /// Limitations of the structural findings.
        pub limitations: Vec<LayoutLimitation>,
        /// Global-data canary addresses initialized by firmware.
        pub global_canaries: Vec<u32>,
        /// Intervals between recognized global data and OEM buffers.
        pub structural_gaps: Vec<Range>,
        /// End address of the corroborated global-data copy.
        pub global_copy_end: Option<u32>,
    }

    /// A structural inspection limitation, independent of display wording.
    #[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
    #[non_exhaustive]
    pub enum LayoutLimitation {
        /// No COMP directory was present to establish the image base.
        NoCompDirectory,
        /// Static gaps do not prove freedom from runtime or DMA accesses.
        RuntimeOwnershipUnproven,
    }
    impl crate::CodedError for LayoutLimitation {
        fn code(&self) -> &'static str {
            match self {
                Self::NoCompDirectory => "pioneer.layout.no_comp_directory",
                Self::RuntimeOwnershipUnproven => "pioneer.layout.runtime_ownership_unproven",
            }
        }
    }
    impl BufferEntry {
        /// Resolve this descriptor within a caller-supplied controller window.
        /// An unspecified length conservatively extends to the window end.
        /// An unspecified start has no known interval and returns None.
        pub fn range(&self, controller_base: u32, controller_length: u32) -> Result<Option<Range>> {
            let Some(start) = self.controller_start else {
                return Ok(None);
            };
            let available = controller_length
                .checked_sub(start)
                .ok_or(Error::OutOfRange {
                    context: "buffer start",
                })?;
            let length = self.length.unwrap_or(available);
            if length > available {
                return Err(Error::OutOfRange {
                    context: "buffer length",
                });
            }
            let start = controller_base
                .checked_add(start)
                .ok_or(Error::OutOfRange {
                    context: "controller address",
                })?;
            Ok(Some(Range::new(start, length)?))
        }
    }
    impl Layout {
        /// Return known OEM buffer intervals intersecting the caller's candidate.
        /// Descriptors with unspecified starts cannot establish an interval and
        /// remain available in buffer_tables for the caller's uncertainty policy.
        pub fn buffer_conflicts(
            &self,
            candidate: &Range,
            controller_base: u32,
            controller_length: u32,
        ) -> Result<Vec<Range>> {
            let mut conflicts = Vec::new();
            for entry in self.buffer_tables.iter().flat_map(|t| &t.entries) {
                if let Some(range) = entry.range(controller_base, controller_length)? {
                    if range.overlaps(candidate) && !conflicts.contains(&range) {
                        conflicts.push(range);
                    }
                }
            }
            Ok(conflicts)
        }
    }

    fn be32(b: &[u8]) -> u32 {
        u32::from_be_bytes(b[..4].try_into().expect("bounded slice"))
    }

    fn table(image: &[u8], offset: usize) -> Option<Vec<BufferEntry>> {
        let mut rows = Vec::new();
        let mut ids = std::collections::BTreeSet::new();
        for n in 0..128 {
            let row = image.get(offset.checked_add(n * 12)?..offset.checked_add((n + 1) * 12)?)?;
            if row
                == [
                    0xff, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                ]
            {
                return (rows.len() >= 2).then_some(rows);
            }
            if row[0] > 0x7f || row[1] != 0 || !ids.insert(row[0]) {
                return None;
            }
            let start = be32(&row[4..]);
            let length = be32(&row[8..]);
            if start != u32::MAX && start >= 0x400000 {
                return None;
            }
            if length != u32::MAX && (length == 0 || length > 0x400000) {
                return None;
            }
            if start != u32::MAX && length != u32::MAX && start.checked_add(length)? > 0x400000 {
                return None;
            }
            rows.push(BufferEntry {
                id: row[0],
                controller_start: (start != u32::MAX).then_some(start),
                length: (length != u32::MAX).then_some(length),
            });
        }
        None
    }

    /// Recognize layout evidence in a decoded body. This does not prove free RAM.
    pub fn inspect(image: &[u8]) -> Result<Layout> {
        let mut out = Layout {
            is_uhd: crate::image::is_uhd(image),
            image_base: None,
            overlay_ranges: vec![],
            buffer_tables: vec![],
            overlay_tail: None,
            limitations: vec![],
            global_canaries: vec![],
            structural_gaps: vec![],
            global_copy_end: None,
        };
        let Some((base, streams)) =
            crate::comp_streams::read(image, crate::comp::MAX_TOTAL_EXPANDED, &mut || true)
                .map_err(Error::from)?
        else {
            out.limitations.push(LayoutLimitation::NoCompDirectory);
            return Ok(out);
        };
        out.image_base = Some(base);
        let sizes: Vec<_> = streams
            .iter()
            .enumerate()
            .map(|(i, s)| (i, s.expanded.len()))
            .collect();
        for destination in
            crate::comp_runtime::discover(image, base, &sizes).map_err(|_| Error::Ambiguous {
                context: "COMP runtime destination",
                candidates: 2,
            })?
        {
            out.overlay_ranges.push(Range::new(
                destination.address,
                streams[destination.stream].expanded.len().try_into()?,
            )?);
        }
        out.overlay_ranges.sort_by_key(|r| r.start);
        out.overlay_ranges.dedup();
        if let Some(end) = out.overlay_ranges.iter().map(|r| r.end).max() {
            out.overlay_tail = end.checked_add(31).map(|n| n & !31);
        }
        let mut found = std::collections::BTreeMap::<usize, BufferTable>::new();
        for (off, w) in image.windows(6).enumerate() {
            if off % 2 != 0 || w[0] != 0x7a || ![0x00, 0x10, 0x11].contains(&w[1]) {
                continue;
            }
            let Some(relative) = be32(&w[2..]).checked_sub(base) else {
                continue;
            };
            let relative = relative as usize;
            if let Some(entries) = table(image, relative) {
                found
                    .entry(relative)
                    .or_insert_with(|| BufferTable {
                        image_offset: relative,
                        reference_offsets: vec![],
                        entries,
                    })
                    .reference_offsets
                    .push(off);
            }
        }
        out.buffer_tables = found.into_values().collect();
        let mut canary_groups = Vec::new();
        for (off, w) in image.windows(4).enumerate() {
            if off % 2 != 0 || w != [0x79, 1, 0xa5, 0xa5] {
                continue;
            }
            let mut at = off + 4;
            let mut group = Vec::new();
            while let Some(store) = image.get(at..at + 6) {
                if store[..2] != [0x6b, 0xa1] {
                    break;
                }
                let addr = be32(&store[2..]);
                if (0xa00000..0xa10000).contains(&addr) {
                    group.push(addr);
                }
                at += 6;
            }
            if !group.is_empty() {
                canary_groups.push(group);
            }
        }
        if canary_groups.len() == 1 {
            out.global_canaries = canary_groups.remove(0);
            let last = *out.global_canaries.iter().max().expect("nonempty group");
            for (off, w) in image.windows(18).enumerate() {
                if off % 2 != 0
                    || w[..2] != [0x7a, 0]
                    || w[6..8] != [0x7a, 1]
                    || w[12..14] != [0x7a, 2]
                {
                    continue;
                }
                let source = be32(&w[2..]);
                let stop = be32(&w[8..]);
                let dest = be32(&w[14..]);
                if source >= base
                    && stop > source
                    && stop <= base + image.len() as u32
                    && (0xa00000..0xa10000).contains(&dest)
                    && dest.checked_add(stop - source) == Some(last)
                {
                    out.global_copy_end = Some(last);
                }
            }
            let first_buffer = out
                .buffer_tables
                .iter()
                .flat_map(|t| &t.entries)
                .filter_map(|e| {
                    e.controller_start
                        .zip(e.length)
                        .map(|(start, _)| 0xa00000 + start)
                })
                .min();
            if let Some(end) = first_buffer {
                let start = (last + 2 + 31) & !31;
                if start < end && out.global_copy_end == Some(last) {
                    out.structural_gaps.push(Range { start, end });
                }
            }
        }
        out.limitations
            .push(LayoutLimitation::RuntimeOwnershipUnproven);
        Ok(out)
    }

    /// Subtract occupied intervals and align the resulting structural gaps.
    pub fn free_ranges(
        windows: &[Range],
        occupied: &[Range],
        alignment: u32,
    ) -> Result<Vec<Range>> {
        ensure!(
            alignment.is_power_of_two() && alignment >= 2,
            "invalid alignment"
        );
        ensure!(
            windows.iter().chain(occupied).all(|r| r.start < r.end),
            "invalid map interval"
        );
        let mut windows = windows.to_vec();
        windows.sort_by_key(|r| r.start);
        let mut merged: Vec<Range> = vec![];
        for window in windows {
            if let Some(last) = merged.last_mut() {
                if window.start <= last.end {
                    last.end = last.end.max(window.end);
                    continue;
                }
            }
            merged.push(window);
        }
        let mut blocks = occupied.to_vec();
        blocks.sort_by_key(|r| r.start);
        let mut result = Vec::new();
        for window in merged {
            let mut cursor = window.start;
            for block in blocks.iter().filter(|b| b.overlaps(&window)) {
                if let Some(start) = cursor
                    .checked_add(alignment - 1)
                    .map(|v| v & !(alignment - 1))
                    .filter(|start| *start < block.start.min(window.end))
                {
                    result.push(Range {
                        start,
                        end: block.start.min(window.end),
                    });
                }
                cursor = cursor.max(block.end);
            }
            if let Some(start) = cursor
                .checked_add(alignment - 1)
                .map(|v| v & !(alignment - 1))
                .filter(|start| *start < window.end)
            {
                result.push(Range {
                    start,
                    end: window.end,
                });
            }
        }
        Ok(result)
    }
}

#[cfg(test)]
#[path = "firmware/layout_tests.rs"]
mod layout_tests;

/// Opcode registry and callback initialization inspection.
pub mod callbacks {
    use super::{
        error::{ensure, unique, Context},
        Error, Result,
    };
    use serde::Serialize;
    fn word(bytes: &[u8]) -> u32 {
        u32::from_be_bytes(bytes[..4].try_into().expect("bounded slice"))
    }

    #[derive(Debug, Clone, Serialize)]
    /// Dispatch registry, object and callback facts recovered from initialization code.
    pub struct OpcodeSite {
        /// Opcode registry CPU address.
        pub registry_address: u32,
        /// Dispatch object CPU address.
        pub object_address: u32,
        /// Initialized callback table CPU address.
        pub table_address: u32,
        /// Command validation callback code address.
        pub check_address: u32,
        /// Command preparation callback code address.
        pub prepare_address: u32,
        /// Main callback code address.
        pub main_address: u32,
    }

    /// Locate the opcode registry, then follow the READ BUFFER object's initializer.
    pub fn read_buffer_site(image: &[u8], base: u32) -> Result<OpcodeSite> {
        opcode_site(image, base, 0x3c)
    }

    /// Locate an opcode object and its initialized callback table.
    pub fn opcode_site(image: &[u8], base: u32, opcode: u8) -> Result<OpcodeSite> {
        let opcode = usize::from(opcode);
        let mut registries = Vec::new();
        for (off, window) in image.windows(256).enumerate() {
            if off % 2 != 0
                || word(window) == 0
                || word(window) >= 0x8000
                || word(&window[8..]) != 0
            {
                continue;
            }
            let slots: Vec<u32> = window.chunks_exact(4).map(word).collect();
            if slots.iter().filter(|v| **v == 0).count() < 30
                || slots.iter().any(|v| *v >= 0x8000)
                || [0, 1, 3, 4, 0x12, 0x3b, 0x3c]
                    .iter()
                    .any(|i| slots[*i] == 0)
            {
                continue;
            }
            registries.push(off);
        }
        let registry = unique(registries, "opcode registry")?;
        let entry = image
            .get(registry + opcode * 4..registry + opcode * 4 + 4)
            .context("opcode entry outside image")?;
        let object = word(entry);
        if object == 0 || object > 0x7ffc || object % 2 != 0 {
            return Err(Error::Malformed {
                context: "opcode object",
            });
        }
        let mut tables = Vec::new();
        for (off, w) in image.windows(14).enumerate() {
            if off % 2 == 0
                && w[..2] == [0x7a, 1]
                && w[6..10] == [1, 0, 0x6b, 0xa1]
                && word(&w[10..]) == object
            {
                tables.push(word(&w[2..]));
            }
        }
        let table = unique(tables, "object initializer")?;
        if table % 2 != 0 {
            return Err(Error::Malformed {
                context: "unaligned callback table",
            });
        }
        let offset = table.checked_sub(base).context("table outside image")? as usize;
        let bytes = image
            .get(offset..offset + 40)
            .context("truncated callback table")?;
        ensure!(
            bytes[0x14..0x18] == [0; 4] && bytes[0x1e..0x22] == [0; 4],
            "unsupported object adjustments"
        );
        let callback = |offset: usize| -> Result<u32> {
            let address = word(&bytes[offset..]);
            let relative = address
                .checked_sub(base)
                .context("callback outside image")? as usize;
            if address % 2 != 0 {
                return Err(Error::Malformed {
                    context: "unaligned callback",
                });
            }
            if image.get(relative..relative + 2).is_none() {
                return Err(Error::OutOfRange {
                    context: "callback",
                });
            }
            Ok(address)
        };
        let check = callback(0x10)?;
        let prepare = callback(0x1a)?;
        let main = callback(0x24)?;
        Ok(OpcodeSite {
            registry_address: base
                .checked_add(registry.try_into()?)
                .context("registry address overflow")?,
            object_address: object,
            table_address: table,
            check_address: check,
            prepare_address: prepare,
            main_address: main,
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn high_opcode_uses_the_full_registry_and_checks_object_bounds() {
            let base = 0x510000u32;
            let mut image = vec![0; 4096];
            for opcode in [0, 1, 3, 4, 0x12, 0x3b, 0x3c, 0xad] {
                image[opcode * 4..opcode * 4 + 4].copy_from_slice(&0x1234u32.to_be_bytes());
            }
            let mut init = vec![0x7a, 1];
            init.extend((base + 2048).to_be_bytes());
            init.extend([1, 0, 0x6b, 0xa1]);
            init.extend(0x1234u32.to_be_bytes());
            image[1200..1214].copy_from_slice(&init);
            for (offset, target) in [(0x10, 2900), (0x1a, 2910), (0x24, 3000)] {
                image[2048 + offset..2052 + offset].copy_from_slice(&(base + target).to_be_bytes());
            }
            image[2900..2902].copy_from_slice(&[0x54, 0x70]);
            image[2910..2914].copy_from_slice(&[0x18, 0x88, 0x54, 0x70]);
            for opcode in [0x3c, 0xad] {
                let site = opcode_site(&image, base, opcode).unwrap();
                assert_eq!(
                    (site.object_address, site.table_address, site.main_address),
                    (0x1234, base + 2048, base + 3000)
                );
            }
            // Discovery reports substantive OEM callbacks without applying hook policy.
            image[2900..2902].copy_from_slice(&[0x18, 0x88]);
            image[2910..2912].copy_from_slice(&[0x19, 0x00]);
            let site = read_buffer_site(&image, base).unwrap();
            assert_eq!(
                (site.check_address, site.prepare_address),
                (base + 2900, base + 2910)
            );
            for offset in [0x10, 0x1a, 0x24] {
                let original = image[2048 + offset..2052 + offset].to_vec();
                for address in [base - 2, base + 1, base + 4096, u32::MAX] {
                    image[2048 + offset..2052 + offset].copy_from_slice(&address.to_be_bytes());
                    for opcode in [0x3c, 0xad] {
                        assert!(opcode_site(&image, base, opcode).is_err());
                    }
                }
                image[2048 + offset..2052 + offset].copy_from_slice(&original);
            }
            for slot in [0u32, 1, 0x7ffe, 0x8000] {
                image[0xad * 4..0xad * 4 + 4].copy_from_slice(&slot.to_be_bytes());
                assert!(opcode_site(&image, base, 0xad).is_err());
            }
        }
    }
}
