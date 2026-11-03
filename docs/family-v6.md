# Matrix family identity, version 6

The matrix identity includes persistent parameter layout on every platform. An unresolved or conflicting required observation produces no key. Matching candidate keys do not authorize flashing, settings migration, or a phase patch.

`image::matrix::discover(hardware, normal, kernel)` accepts the structured eight-byte hardware tag and decoded components. It never infers a platform from a model name. Supply the exact associated Kernel where a native reader or V850 register base requires it. ATA architecture and load base are recognized from complete native consumers. SCSI and older M7900 firmware remain without an ID where the audited required evidence is incomplete.

`Identity.as_is` includes source assignment. `Identity.candidate` omits assignment only for SAT8/SAT9, where a separate bounded two-way Normal-code phase correction exists. ATA and SAT1 retain phase. All identities retain layout.

## Canonical binary format

The prefix is the 16 bytes `50494f4e4545522d46414d494c590006` (ASCII `PIONEER-FAMILY`, NUL, version 6). Every integer is unsigned big endian. Booleans are u8 0/1. Vectors begin with a u32 element count; fixed arrays have no count. Unknown values are never encoded as zero. An optional allocation size uses a u8 presence flag, followed by u32 only when present.

The family identifier is the first eight SHA-256 digest bytes, interpreted as a big-endian u64. Existing `Family` hex formatting applies. Display labels, Debug formatting, source offsets, firmware hashes and model strings are not serialized.

Platform tags and field order:

| Tag | Fields |
| --- | --- |
| 1 (SAT1) | geometry, IRQ, assignment, layout |
| 8 (SAT8) | input flags u8, masked host u8, IRQ, assignment, layout |
| 9 (SAT9) | geometry, masked host u8, assignment, layout |
| A0 (ATA) | peripheral geometry, layout, five host u32 coordinates, architecture/input, assignment, output interface |

Assignment tags: 0 means omitted in a supported candidate key, 1 direct, 2 swapped. Missing assignment evidence cannot produce tag 0.

SAT geometry tags: 1 followed by marker u32 and stride u32; 2 followed by two bank bases u32 and stride u32. IRQ tags: 1 followed by AND/OR masks u8; 2 followed by native address encoding (1 absolute16, 2 absolute32), address u32, bit u8 and active bool; 3 identifies the fully recognized tray-close vector route.

Layout tags:

- 1: word encoding, region vector, logical-domain vector. Each region contains address u32, basis u8 (1 absolute, 2 selected bank), optional allocation u32, record bytes u32, record count u16, header bytes u16, header test u8 (1 byte FF, 2 word FFFF). Each domain contains first/last logical words u16 and region index u32.
- 2: serial address bits u8, first word u16, word count u16, word encoding.
- 3: serial address bits u8, two base words u16, eight slot offsets u8, word encoding, selection tag (1 header word u16; 2 eight ordered fallback words u16).

Word encoding tags: 1 little endian, 2 runtime direct-or-bus-permuted little endian, 3 serial high byte first. Region and domain order is native order; sorting would change semantics.

Peripheral geometry tags: 1 followed by a vector of address/payload-size u32 pairs; 2 followed by first/last serial words u16; 3 followed by two serial bases u16 and eight slot offsets u8.

ATA host coordinates are the interface coordinate, signature-low address, signature-high address, then the two reset-01 write addresses. Split-byte interfaces retain their actual addresses.

ATA input starts with architecture tag 1 M32C or 2 V850. M32C input tag 1 carries address u32, closed bit u8, open bit u8, active bool, open-first bool; tag 2 carries event address u32, mask u8 and required value u8. V850 carries a key-algorithm tag: 1 counter-low, 2 timer-low, 3 high/falling/selected, 4 low/rising/selected, 5 low/rising/mode. The five fixed native programs, their physical operands, threshold 45 and software gates are defined by `peripheral::KeyAlgorithm` and the HTML value contracts. They are not interchangeable single-bit predicates.

Output interface tags: 1 followed by two direct byte addresses u32; 2 followed by indexed window u32 and two channel indices u32.

## Planning and execution

`MATRIX_FAMILY_SCHEME` labels v6 keys emitted by context-aware image, Envelope,
analysis and receiver APIs. `FAMILY_SCHEME` retains v5 for historical mechanism
registries and the deprecated context-free APIs. Use `legacy_family` and
`legacy_family_fingerprint` for those historical lookups, never for current
update admission.

`compatibility::plan` compares the complete typed installed and requested
identities. It plans only recognized differences with a supported native proof;
every unrelated required field must match. The matrix-local correction API is a
forwarding alias. SAT1 and ATA phase-only transitions can be supported without
removing phase from their published candidate keys. A narrowly proven layout
transition likewise does not remove layout from any candidate key.

SAT8/SAT9 use complete native output-pair correction; SAT1 uses thirteen legacy
native forms with explicit operand descriptors. M32C and V850 retain their own
function, output-interface and checksum contracts. Codec-aware `prepare_image`
and `prepare_file` bind exact components, repair integrity, rebuild and
authenticate, then decode and re-extract the full required identity. BootKey and
V850 proofs require the associated Kernel; standalone TailKey does not. The raw
Normal API does not guess a codec's checksum rule. Prepared files do not grant
live receiver transfer support: unsupported DVR representations still refuse.

Mechanism conversions remain independently guarded under
`compatibility::mechanism`. All eleven reviewed dev 1.5 definitions and six
original-hardware rules are typed Rust contracts; production JSON recipes are
removed. Calibration conventions, exact firmware guards, pristine OEM returns
and live parameter prerequisites remain mandatory. Native phase recognition
alone does not authorize replacing a specialized mechanism correction. See
[mechanism contracts](settings-adaptation.md).

Startup selection is separate from family serialization. A bound native
comparison selects an accepted 0x009F value through its complete recognized
getter and correct R0/R1 convention. This proves a positive accepted value, not
that every other value is rejected or every other startup requirement absent.
The conditional gate accepts FE23 unconditionally and can also accept FE09 with
its native runtime predicate.

`StartupPolicy::NeutralSelection` deliberately selects 0x009F = 0xFFFF when no
comparison is recognized. Its `Evidence::NeutralSelection` retains the separate
bounded native assessment. Recognized but unbound or ambiguous comparisons
refuse selection. Strict `NativeEvidenceOnly` admission remains unresolved
without complete positive evidence. Neither neutral selection nor an unresolved
native observation is serialized as a guessed family value. The live settings
transaction reads, changes if necessary, verifies, and retains the actual
before-value for rollback.

Normal-only persistent-address correction is limited to whole-program-
equivalent address variants with the exact unchanged Kernel. After allowed
native address operands and independently proven phase normalization, every
program byte must match the installed program. Matching reader dimensions
alone is insufficient; read, write, erase, initialization and bank routes must
all be preserved. This subset moves no retained data and adds no Kernel edits.
No held SAT1/SAT9 layout groups become mutually correctable: SAT1 has a concrete
Normal-payload overlap, while SAT9 also differs in independent bank geometry and
secondary mapping. SAT8 record-format conversion remains blocked.

## Validation status

Independent corpus checks reproduce the canonical equality partitions for all
530 SAT and 170 M32C/V850 images and check digest collisions. The inventory has
723 package records, 722 distinct Normal images, 675 known v6 identities and
47 required deferrals. Fixed byte/digest vectors cover direct, swapped and
candidate encodings. Unsupported required observations remain unresolved.

The final frozen release all-target run passes 756 tests. Sixteen feature-test
configurations pass 7,119 test instances; documentation, MSRV, thumb, formatting,
warnings-denied Clippy, doctest and packaging checks pass. Explicit private
corpus and existing OEM/held-image/analysis regressions also pass. Complete
phase-file plans, neutral startup selection and rollback, all dev 1.5 mechanism
routes, mixed effects and receiver failure ordering are covered. See
[correction architecture and validation](correction-completion.md) for the exact
scope and remaining unsupported layouts and transfer representations.

The desktop Hardware Matrix and review copy have identical historical source
data, unchanged published grouping keys, all platform filters and verified
browser/PDF export. No new physical flash or media trials are claimed.
