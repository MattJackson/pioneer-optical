# Embedded settings adaptations

## Original hardware selects the route

`production::ProductCode` exposes the raw factory code, canonical prefix,
platform and product suffix. `Production::product_code_parts()` reads these from
the parsed A0 production record. For example, `BDR-UD02TBD` and `BDU-UD02ABC`
share platform `UD02`, while retaining their prefixes and suffixes. Matching is
ASCII-case-insensitive and uses complete tokens: `UD020` does not match `UD02`.
The parser does not authorize a conversion.

The retained-hoard grammar audit covers 723 embedded model strings: 662 use a
recognized naming grammar and 61 OEM aliases remain unclassified. These are
firmware strings, not 723 live factory captures. Synthetic tests also cover
factory variants, case, separators, malformed records and `BDR-UD03FAL`.

Original hardware A remains the routing source while firmware B is running.
UD02 uses a restrictive scope: every non-native destination needs an explicit
UD02-to-destination rule. Native UD03/UD04 inverse exceptions are additive,
preserving their existing OEM-family routes. Firmware B never grants its own
hardware's permissions to A. Return to a
reviewed OEM image for A uses pristine firmware with no mechanism adaptation.
Unrelated hardware retains its existing checks without a per-product entry.

The compiled rules cover UD02 to UD03/UD04, native UD03/UD04 to UD02, and the
existing native UD03/UD04 interchanges. Original UD02 running UD03 or UD04
continues to need the UD02 adaptation, regardless of the reported model.
Original UD03 or UD04 running adapted UD02 can return to its own OEM image.
The independent family, receiver, startup, authentication and transport checks
still apply to every route, including Recovery with a family override.

The UD02 mechanism-convention issue applies within its identified firmware
family. A known different family does not by itself require that conversion;
the independent family gate decides whether to refuse it or honor an explicit
Recovery override. Missing family evidence remains unresolved when the other
image is in the issue's scope. Original-hardware destination restrictions and
required adaptations remain enforced independently of a family override.

## One declarative settings file

`src/settings/adaptation/settings.json` contains the hardware selectors and
version-bound firmware recipes. Rules reference a policy; multiple recipes can
implement that policy for different firmware versions or calibration formats.
All directions use the same preparation and execution code. There is no runtime
JSON loading or host-supplied patch interface.

Reviewed adaptation targets:

| Original hardware | Target firmware | Decoded input | Decoded output | Changed bytes |
| --- | --- | --- | --- | ---: |
| UD02 | UD04 1.14 | `87e8152f...` | `ca090322...` | 679 |
| UD02 | UD03 1.03 | `95664992...` | `f78a48ea...` | 678 |
| UD02 | UD03 1.14 | `e6bdfa9b...` | `57d0be1d...` | 680 |
| UD03, whole-word reader | UD02 1.00 | `84fab289...` | `95e5a7a5...` | 1363 |
| UD03, packed-byte reader | UD02 1.00 | `84fab289...` | `33d04b3d...` | 1434 |
| UD04 | UD02 1.00 | `84fab289...` | `33d04b3d...` | 1434 |

Counts are byte differences in decoded Normal, including four checksum bytes;
encoded transfer signatures are excluded. Other target versions need their own
reviewed recipe. Pristine native return entries cover UD02 1.00, UD03 1.03/1.14
and UD04 1.11/1.14. Those entries do not adapt mechanism settings or change the
image bytes.

Forward adaptations require live parameter word `0x028f = 1`. The reverse
replaces both UD02 waveform selections and uses the native fixed coefficient
loader, so it does not assume a native UD03/UD04 unit has UD02's parameter value.
No profile copies another unit's calibration or writes calibration to NVRAM.
Firmware's own later calibration/save behavior remains OEM behavior.

## Calibration is a firmware format contract

UD02 and UD03 1.03 read whole words `0x0112` and `0x0113`; their callers consume
the low byte. UD03 1.14 and UD04 read separate high/low bytes for the four modes.
This version difference must not be inferred from the model label or from the
numeric calibration values.

The source contract recognizes complete reader instruction patterns, allowing
relocated calls, and distinguishes whole-word, packed-byte and the reviewed
packed-reader low-byte shim. Missing or conflicting evidence is unresolved.
On original UD03 hardware, the inverse recipe preserves the running reader's
format. Original UD04 selects its native packed convention. This format check
does not replace the persistent original hardware identity. It also does not
rewrite native OEM upgrades/downgrades to use a different reader than the OEM
image contains.

The inverse installs the corresponding native movement, coefficient and
coordinate routines into UD02, with reviewed call and ROM-pointer relocations.
Larger routines use a guarded FF span between the Normal header and COMP
directory. Entry detours preserve instruction boundaries. The full image length,
descriptor, COMP directory and compressed streams remain unchanged. Full
encoding, authentication, decoding and receiver preparation include this span.

## Guards and execution

Each recipe binds the hardware scheme/family, exact target Normal SHA-256,
parsed target model, length, named settings issue, byte replacements, final
checksum and output SHA-256. Legacy source hashes support context-free offline
preparation; they are not the source of physical hardware identity in live use.
Changing the current image hash cannot erase an independently established
factory hardware identity. Invalid supplied factory evidence never falls back
to legacy source hashes.

Byte ranges and the aligned checksum word must be bounded and non-overlapping.
Expected bytes are checked before preparing an owned copy. The final image must
match its declared digest before re-encoding. Reapplying the same adaptation is
idempotent. The registry refuses ambiguous policies and overlapping selectors;
it never selects a recipe by table order.

`Receiver::with_original_parameters` binds the parsed factory record. The app
reads it for the affected cohort. Execution re-reads the factory evidence and
checks every stage's hardware guard and live prerequisites before any settings,
bridge or firmware write. It rechecks stage prerequisites at their boundaries.
A source-format or destination-recipe mismatch fails before writing. Native OEM
return leaves the mechanism parameters untouched.

## Catalogue and website

`adaptation::hardware_rules()` exposes the same compiled selectors as a
fallible API. A selector alone grants nothing: the app prepares each candidate
with explicit original-hardware evidence and all independent flash gates.
Additional admitted routes are published separately from ordinary crossflashes.

The website shows these under **Hardware Specific Cross Flash**, with required
hardware, destination firmware and available version. If the same source and
target firmware version already has an ordinary supported route, its hardware-
specific duplicate is omitted. An empty section is hidden. A listed ordinary
route still requires the live app to select settings for the actual hardware.

## Validation and limits

The original UD04 adaptation reproduces the owner-tested `ca090322...` Normal.
New UD03 and native inverse outputs are software-validated candidates; this does
not claim new physical flash or media trials.

Tests cover product grammar, scoped routing, factory variants independently of
current firmware, every supported direction, OEM return, unsupported targets,
altered images, unknown/conflicting calibration readers, idempotence and invalid
registry entries. Held-image tests exercise real envelopes, signatures and
receiver preparation. Flash and Recovery preparation use mocked read-only
factory inputs; failure paths assert no writes.

Instruction-level tests decode relocated OEM routines and compare every
instruction, call and ROM pointer to the independent reference fixture. A
bounded H8 reader interpreter exhausts all 65536 calibration word values in all
four valid modes and all invalid modes. It checks word selection, effective
values, no reads for invalid modes and preserved registers/stack. This is a
bounded software model, not an emulator of a complete drive.
