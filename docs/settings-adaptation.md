# Embedded settings adaptations

The `settings::adaptation` production registry is empty in 1.3.0. Existing
settings refusals and supported transitions are unchanged. Tests use synthetic
JSON under `cfg(test)`; there are no enabled UD02 conversions.

Reviewed profiles will be compiled with `include_str!` in `PROFILES`. The crate
never loads a runtime JSON file, accepts host-supplied patches or authorizes a
conversion from a model name alone. A crate/app release is required to add one.

## Exact binding

Each profile binds hardware scheme and family, approved decoded source Normal
hashes, the target decoded Normal hash and parsed target model, original factory
product codes, input length, a named settings issue and required live parameters.
Addresses are zero-based byte offsets in decoded Normal; A0 requirements use
word indices. Expected and replacement bytes have equal lengths. All ranges
(including the aligned checksum word) are validated and must not overlap.
All expected bytes are checked before preparing an owned copy. The final
additive checksum and SHA-256 must match before the envelope is re-encoded.

`adapt` profiles contain replacements. `stock_return` profiles contain none and
require equal input/output hashes: returning an original UD02 mechanism from
adapted UD03/UD04 firmware uses pristine OEM UD02 bytes. This is directional;
it does not authorize a native UD03/UD04 mechanism to receive UD02 firmware.

## Original mechanism evidence

`Receiver::with_original_parameters` binds a recognized factory production record
from the selected drive's A0 response. Running model/revision, family equality
and historical host state do not replace it. Missing, malformed or different
factory evidence blocks a matching route. The current production parser accepts
recognized tagged records; the historically untagged UD02 capture remains
unrecognized until its own codec is validated. Do not enable its profiles early.

The settings executor re-reads factory identity and each prerequisite before
any parameter change or update-entry command. Read failures and mismatches
abort without writing. A loader/recovery state cannot bypass these checks.
Source calibration is never transplanted from another unit.

Adapted envelopes are signed for the receiving Kernel, decoded again and passed
through the existing Update/receiver checks. Hardware, ABI, receiver, startup,
transfer-layout and readback checks remain mandatory. Only the named issue can
be resolved; unrelated issues and ambiguous recognition still refuse.

## Offline consumers

No match means unchanged bytes plus the existing settings check. A matching
profile without original-hardware evidence returns the typed
`pioneer.settings.original_hardware_required` error. A website must treat this
as conditional, never an unconditional permission to flash. Actual execution
requires the selected drive's evidence and checks it again.

## Tests

- Empty production registry returns no adaptations for all inputs.
- One compiled test JSON changes only its exact source/target/model/family.
- Normal-only and paired preparation authenticate and decode the new bytes.
- Native UD04/UD03 or unknown factory identity cannot use UD02-only return.
- Malformed JSON, duplicate profiles, overlapping/out-of-range operations,
  wrong expected bytes and wrong output hashes fail before any device I/O.
- Empty prerequisites preserve the old settings command sequence.
- Unmet prerequisites produce no parameter writes or firmware transfers.
