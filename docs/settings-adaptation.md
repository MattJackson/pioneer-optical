# Embedded settings adaptations

## Original hardware and scoped routing

The additive `production::ProductCode` API exposes the factory code's raw
string, canonical prefix, platform token and product suffix.
`Production::product_code_parts()` reads those parts from the existing parsed
A0 production record. Token matching is ASCII-case-insensitive; raw platform
and suffix spelling remain available. The parser does not grant a conversion.
For example, `BDR-UD02TBD` and `BDU-UD02ABC` share platform `UD02` while
retaining their prefixes and suffixes. `UD020` is not treated as `UD02`.

The 2026-11-01 full retained-hoard audit tested all 723 embedded firmware model
strings: 662 use a recognized Pioneer naming grammar; 61 OEM aliases or
unsupported names remain unclassified. These are firmware model strings,
not 723 live factory parameter captures. Public synthetic tests additionally
cover product variants, separators, case, malformed inputs and the captured
`BDR-UD03FAL` production-record example. No name is forced into a hardware
platform merely to reach a coverage percentage.

The settings table is a scoped exception policy. Original hardware
platform/product, current firmware and destination firmware are separate inputs.
Once original hardware belongs to a special-settings scope, every subsequent
non-native destination needs an explicit supported rule, even when the running
firmware has another name. Return to verified OEM firmware for the original
platform needs no settings adaptation. Thus UD02-original hardware on UD04 must not receive native
UD03 simply because UD03 and UD04 share a mechanism convention. Until an
UD02-original-to-UD03 rule exists, that hop is refused. Unrelated hardware
retains the existing family/settings checks without a per-product entry.

Settings transformations are needed for UD02 versus UD03/UD04. UD03-to-UD04
and the reverse need no distinct transformation, but must retain any adaptation
required by original UD02 hardware. Native reverse conversions require their
own validation; a return to UD02-original hardware does not prove them.

Live preparation binds the persistent factory record before selecting a route.
Execution re-reads it and validates all stages before any settings, bridge or
firmware write. Current firmware is never substituted for original hardware.

## Current registry

The production registry contains the tested original UD02 mechanism to UD04
1.14 adaptation and its return to pristine UD02 1.00 firmware. Other target
versions and native UD04-to-UD02 conversions are not enabled.

The forward adaptation requires live parameter word `0x028f = 1`. Native OEM
return has no adaptation prerequisite and leaves the mechanism parameters
untouched. Hardware selection uses the parsed original platform/product rather
than the current firmware hash. UD02 factory suffixes are preserved, not compared
against an exact SKU allowlist; the live mechanism prerequisite remains mandatory.
The reviewed target recipes remain bound to UD04 1.14 (`87e8152f...`, producing
`ca090322...`) and pristine UD02 1.00 (`84fab289...`). Other target versions and
UD02-hardware-to-UD03 need their own validated recipe before being enabled.
Hashes and exact byte guards are compiled in `adaptation/profiles/` to protect
the target transformation, rather than identify the physical source hardware.

Profiles are compiled with `include_str!`; the crate never loads runtime JSON,
accepts host-supplied patches or authorizes a conversion from a model name alone.
A crate/app release is required to add another profile. The previous 1.3.0
registry was empty; synthetic test documents remain restricted to `cfg(test)`.

## Exact binding

Each profile binds hardware scheme and family, the target decoded Normal hash
and parsed target model, input length, a named settings issue and live parameters.
Legacy source hashes remain only for context-free offline preparation; every
live prepared operation in this settings cohort has an independent factory
hardware guard. Invalid supplied factory evidence never falls back to those hashes.
Addresses are zero-based byte offsets in decoded Normal; A0 requirements use
word indices. Expected and replacement bytes have equal lengths. All ranges
(including the aligned checksum word) are validated and must not overlap.
All expected bytes are checked before preparing an owned copy. The final
additive checksum and SHA-256 must match before the envelope is re-encoded.

`adapt` profiles contain replacements. `stock_return` profiles contain none and
require equal input/output hashes: returning an original UD02 mechanism from
adapted UD03/UD04 firmware uses pristine OEM UD02 bytes. This is directional;
it does not authorize a native UD03/UD04 mechanism to receive UD02 firmware.

## Live settings requirements

Original hardware plus destination selects the conversion. The settings
executor confirms the original factory hardware and reads every stage's live
prerequisites before any parameter change or update-entry command, then rechecks
stage prerequisites at their normal boundaries. Read failures and mismatches abort
without writing. Recovery uses the same route and settings requirements. Source calibration is never
transplanted from another unit.

`Receiver::with_original_parameters` binds the independently parsed A0 factory
record. The application supplies it only for the affected settings cohort;
unrelated hardware needs neither a settings-table row nor an extra identity read.

Adapted envelopes are signed for the receiving Kernel, decoded again and passed
through the existing Update/receiver checks. Hardware, ABI, receiver, startup,
transfer-layout and readback checks remain mandatory. Only the named issue can
be resolved; unrelated issues and ambiguous recognition still refuse.

## Offline consumers

Unscoped hardware retains the existing settings checks. With no live factory
context, legacy certified-pair preparation remains available for offline
consumers. Such a plan cannot execute on the wrong original hardware: its
factory guard and live prerequisites still run before all writes. A native
UD03/UD04 link does not authorize that same link on UD02-original hardware.

## Tests

- One compiled test JSON changes only its exact source/target/model/family.
- Normal-only and paired preparation authenticate and decode the new bytes.
- Native UD04/UD03 firmware has no certified UD02 return route.
- Current UD02, UD03, OEM UD04 and adapted UD04 firmware all select the same
  reviewed UD04 output on UD02-original hardware; original product variants
  remain distinct data while sharing the validated hardware rule.
- UD02-original hardware cannot inherit a UD04-to-UD03 route. Ordinary and
  family-override preparation both refuse it.
- Native OEM return has byte-identical UD02 output and no adaptation prerequisite.
- Reapplying an already adapted image is idempotent.
- Malformed JSON, duplicate profiles, overlapping/out-of-range operations,
  wrong expected bytes and wrong output hashes fail before any device I/O.
- Unrelated hardware retains existing routes and command sequences.
- Unmet prerequisites produce no parameter writes or firmware transfers.
- A missing original record or a failed final-stage mechanism prerequisite
  refuses the entire operation before even the first bridge write, in Flash
  and Recovery.

## Validation and limits

The UD04 prepared Normal hash `ca090322...` reproduces the existing owner-tested
UHD configuration recorded on 2026-10-24. Held-image tests check all byte guards,
native reverse rejection, unknown-image rejection, issue resolution, envelope
authentication, receiver preparation and pristine stock return. The source
capture has an unsigned-backup signature sentinel; test preparation signs its
transfer without changing decoded firmware, matching the host's existing flow.
These tests are offline validation, not new physical flash/media trials.

Exact-image profiles resolve their named settings issue after the independent
hardware-family check. Adaptation can replace the old phase grammar itself, so
requiring that original grammar after preparing a known output would reject the
validated result. Unrecognized target layouts, unrelated issues and incompatible
hardware retain their refusals. A changed current-firmware hash does not erase
the drive's independently established original hardware identity.
