# Embedded settings adaptations

The production registry contains the tested original UD02 mechanism to UD04
1.14 adaptation and its return to pristine UD02 1.00 firmware. Other target
versions and native UD04-to-UD02 conversions are not enabled.

Both directions require live parameter word `0x028f = 1`. Factory SKU strings
are not an additional eligibility gate. Forward preparation accepts only the original UD02
Normal (`84fab289...`) or the tested adapted UD04 Normal (`ca090322...`) as its
source and the exact OEM UD04 Normal (`87e8152f...`) as target. Return accepts
only that adapted source and the original UD02 target. Full hashes and exact
byte guards are compiled in `adaptation/profiles/`.

Profiles are compiled with `include_str!`; the crate never loads runtime JSON,
accepts host-supplied patches or authorizes a conversion from a model name alone.
A crate/app release is required to add another profile. The previous 1.3.0
registry was empty; synthetic test documents remain restricted to `cfg(test)`.

## Exact binding

Each profile binds hardware scheme and family, approved decoded source Normal
hashes, the target decoded Normal hash and parsed target model, input length,
a named settings issue and required live parameters.
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

The certified source/target firmware pair selects the conversion. The settings
executor reads each live prerequisite before any parameter change or update-entry
command. Read failures and mismatches abort without writing. Recovery uses the
same firmware-pair and setting requirements. Source calibration is never
transplanted from another unit.

`Receiver::with_original_parameters` remains a no-op for source compatibility;
factory production codes do not grant or deny an adaptation.

Adapted envelopes are signed for the receiving Kernel, decoded again and passed
through the existing Update/receiver checks. Hardware, ABI, receiver, startup,
transfer-layout and readback checks remain mandatory. Only the named issue can
be resolved; unrelated issues and ambiguous recognition still refuse.

## Offline consumers

No match means unchanged bytes plus the existing settings check. A matching
profile is prepared from the certified firmware pair without factory identity.
The website can advertise that configured direction; actual execution still
checks the required live settings before writing.

## Tests

- Empty production registry returns no adaptations for all inputs.
- One compiled test JSON changes only its exact source/target/model/family.
- Normal-only and paired preparation authenticate and decode the new bytes.
- Native UD04/UD03 firmware has no certified UD02 return route.
- Certified preparation needs no factory-SKU record.
- Malformed JSON, duplicate profiles, overlapping/out-of-range operations,
  wrong expected bytes and wrong output hashes fail before any device I/O.
- Empty prerequisites preserve the old settings command sequence.
- Unmet prerequisites produce no parameter writes or firmware transfers.

## Validation and limits

The UD04 prepared Normal hash `ca090322...` reproduces the existing owner-tested
UHD configuration recorded on 2026-10-24. Held-image tests check all byte guards,
native reverse rejection, unknown-image rejection, issue resolution, envelope
authentication, receiver preparation and pristine stock return. The source
capture has an unsigned-backup signature sentinel; test preparation signs its
transfer without changing decoded firmware, matching the host's existing flow.
These new tests are offline validation, not new physical flash/media trials.

Exact-image profiles resolve their named settings issue after the independent
hardware-family check. Adaptation can replace the old phase grammar itself, so
requiring that original grammar after preparing a known output would reject the
validated result. Unmatched images, issues and hardware retain existing refusals.
