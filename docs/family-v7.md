# Registered family identity, version 7

Every registered filter runs against every firmware context. Six owners supply
hardware identity; the startup prerequisite owner supplies an operational
requirement. A required hardware finding must be Known or positively
NotApplicable. Unresolved or Conflicting hardware evidence produces no family
ID. An unresolved operational finding is retained for stage planning and never
becomes a guessed hardware value.

| Stable owner ID | Role |
| --- | --- |
| `persistent-storage-geometry` | Hardware |
| `startup-inputs-initialization` | Hardware |
| `host-interface-setup` | Hardware |
| `loading-input-interrupt-setup` | Hardware |
| `persistent-parameter-layout` | Hardware |
| `phase` | Hardware |
| `startup-prerequisite` | Operational |

Known constants remain native findings: all 391 held SAT8 images have the same
bank geometry; all 66 SAT9 images have the same selected IRQ effect. Both fields
are detected, compared and included. A detector miss is never an exclusion.
The registry contains no outer platform-specific field list.

## Canonical binary format

`filters::identity::Key` begins with the 16 bytes
`50494f4e4545522d46414d494c590007` (`PIONEER-FAMILY`, NUL, version 7), followed by
a u8 platform partition: 1 SAT1, 2 H8 SAT (SAT8 and SAT9), 4 ATA or 5 SCSI. The
complete eight-byte structured hardware tag establishes the domain; model labels
do not. SAT9 shares SAT8's partition byte because both receive, hand off,
finalize, checksum and marker-gate Kernel updates with the same native code
(the gated marker check differs only in its relocated RAM flag address) and use
the same versioned persistent-bank contract; every filter value must still match.

All integer encodings are big endian. A u64 hardware-entry count precedes entries
sorted lexically by stable owner ID. Each entry contains a u64 UTF-8 byte length,
the owner ID bytes, then its native finding. Known uses tag 1 and the typed value;
NotApplicable uses tag 2 and the owner's u16 proof discriminant. Positive
exclusion requires nonempty native evidence, but evidence prose is not hashed.

Typed value tags are: 1 u8; 2 u16; 3 u32; 4 Boolean as u8 0/1; 5 byte vector;
6 ordered value sequence; 7 owner-local u16 variant tag and ordered fields.
Byte vectors and sequences use u64 lengths. Variants use a u64 field count.
Widths, address spaces, native ordering, output coordinates and owner-local
contract tags remain explicit. No display label, Debug string, evidence offset,
model string or operational selection is serialized.

The family ID is the first eight SHA-256 bytes, interpreted as a big-endian u64.
`Identity.as_is` retains every hardware finding. `Identity.candidate` invokes
each owner's explicit candidate projection. The paired H8 phase owner can omit
assignment while retaining architecture and physical output interface; other
forms retain assignment until their own projection is proven. Candidate
projection does not authorize a checksum repair, a live setting or an update.

## Recorded corpus and coverage

The earlier 722-image replay reported 626 complete identities and 96 unresolved images
from 723 package records. SAT1 has 70 complete images and 11 families; SAT8 has
391 images and 10 candidate families; SAT9 has 66 images and three candidate
families; ATA has 99 complete M32C images and six candidate families. No SCSI
image has a complete identity.

All native hardware fields participate. Two previous SAT1 groups split when
initialization values are retained; this records additional native facts and
does not establish a physical failure. Forty-nine V850 images that previously
had an identity are now deferred because initialization has no complete
supported contract. Together with the 22 already incomplete V850 images, all
71 V850 identities are unresolved. A separately proven phase operation on
49 exact-Kernel V850 pairs remains a valid operation proof and does not fill
that missing initialization field.

Operational startup findings include 85 M32C comparisons for parameter
`0x00D9 == 0xFFFF`. H8 startup is a guarded correctable filter: a bound comparison
stays unchanged. An equal installed value is a read-only live prerequisite; a
differing value against a fixed target gate sets the target's word on the drive
before the first transfer, and against a conditional gate refuses. Missing
comparisons never select neutral FFFF.
ATA/SCSI do not inherit an H8 write command. Native absence remains unproved
when coverage is incomplete.

The native corpus replay checks all 722 images and retains all seven findings
per image. Owner, identity, runner and layout tests verify the typed findings,
canonical ordering and refusal boundaries. Three SAT1003 images (BDC-202 8.07
and BDR-202 1.06/1.07) retain a required unresolved layout: the other five
hardware findings are recognized, but the exact resident reader at 0x404622 is
unavailable in their Normal-only installers. This is missing evidence, not a
proven incompatible layout or an unsupported model label. The other 93 deferred
images retain their explicit required unknowns. See
[filter ownership](filter-registry.md) and
[correction architecture](correction-completion.md).

The HTML consumes the generated typed native report and supplied full v7
fingerprints. Selected-filter previews compare canonical native values sorted
by owner ID and display comparison labels, not invented native family IDs.
Historical HTML source evidence and the [v6 reference](family-v6.md) are retained.
