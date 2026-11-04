# Historical matrix family identity, version 6

This is the deprecated v6 serialization reference retained for historical
comparison. Current discovery and update admission use
[registered family identity, version 7](family-v7.md). The platform-specific
field lists below describe v6 only and must not be reused as the current registry.

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
