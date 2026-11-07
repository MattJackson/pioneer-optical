# Mapped loading interrupt channel

`loading-interrupt-channel` owns a guarded image-only correction for the positively
bound H8 external-event channel programs. It does not make the whole loading
column correctible and does not authorize a firmware pair on its own.

| Operand or role | Five | Seven |
| --- | --- | --- |
| Legacy FFC5 operation | clear bit 5 | clear bit 7 |
| Pending acknowledgement | FFFDFF31 bit 7 | FFFDFF30 bit 1 |
| Enable/disarm | FFFDFF29 bit 7 | FFFDFF28 bit 1 |
| Mode read/modify/write | FFFDFF0C, `(old & 8F) \| 10` | FFFDFF0B, `(old & 8F) \| 10` |
| Installed callback vector | V60 | V58 |
| Other mapped vector | V58 explicit empty wrapper | V60 explicit empty wrapper |

Recognition binds the setup block and its preceding native helper argument, the
installed table, the common enter/leave wrappers, the acknowledgement callback,
and its disarm routine. The full controller enable/disable helpers retain every
register operand and internal branch destination. The table-copy wrapper and its
ROM bridge retain the target copy ABI and exact ROM entry. The complete event
consumer retains all instruction and
control-flow bytes. Its two-selector and six-selector forms dispatch the same
native commands 117F and 217F; repeated RAM/call bindings and internal call
relocations are checked. This does not interpret every helper in the firmware.

Correction edits the linked register operands together and exchanges the two
existing target-local vector entries. It preserves the target's register choices,
branching, helpers, consumer code, and all other table entries. It does not copy
an installed image's code, vector contents, DSP, waveform or calibration data.
The immutable operation binds the original Normal and retained Kernel, requires
the established codec/checksum authority, and verifies every bound program after
shared composition. It requests no persistent parameter writes or prerequisites.

`loading-input-interrupt-setup` separately retains the positively installed V5C
consumer and additional recognized physical-input/independent-route requirements.
V5C is either an explicitly empty wrapper or the bound latched-object callback
acknowledging FFFDFF30 bit 0. An absent recognizer result is not an empty vector.
The legacy tray-close route recognizer uses a different complete callback body
from this mapped channel, so a separately recognized such route remains required.

Outside the complete binding domain both owners retain the original typed native
loading requirement. Direct FFC5 writes, mixed register setup, ATA programs and
unbound programs gain no correction. A binding miss means unavailable proof,
not a demonstrated physical incompatibility. The larger direct-write 20 versus
clear-five opportunity remains unsupported: native witnesses place those writes
in different reset/event programs, with different external callbacks. Enabling
that conversion requires a positive polling/interrupt and physical-consumer
mapping, not a six-byte substitution.

## Evidence and verification

The targeted OEM test in `tests/loading_channel.rs` uses SHA256-pinned Normal
components `0a3954c0…` (SAT 8801) and `00eeb09b…` (SAT 8722), each with its exact
Kernel from `phase-domain-inventory.json`. Both directions prove owner planning,
shared runner preparation/verification, original codec encode/decode, and
byte-exact reversal. They also prove that the independent V5C requirement stays
unchanged and still blocks full-registry admission. These are two real channel
corrections, not two newly admitted firmware routes.

Synthetic relocation tests exercise broken links, partial setup, consumer
control-flow changes, changed auxiliary entries and conflicting duplicate
bindings. They are not OEM admission witnesses. The CI-only corpus test is
sharded with `PIONEER_PHASE_SHARD` / `PIONEER_PHASE_SHARDS`, emits each record's
classification, separates native correction from codec proof, and collects
unavailable obligations through the end. Unbound clear-five/seven counts and
codec gaps must remain visible; no universal coverage claim follows from the
small targeted test.

Relocated diagnostic identifiers are accepted only after binding the complete
linked logger wrapper and record producer. The two consumer immediates must be
distinct and inside the producer's native `[0x900000, upper)` range. On that
branch the producer serializes the identifiers; its string-dereference fallback
is not reachable for those values. Native RAM roles, repeated operands, calls,
header-data reference and control flow remain checked, and all additional bound
spans remain unchanged during correction. No diagnostic identifier is copied
from the source. The SAT 8801/revision 1.01 WX1DM witness `9b44cfbe…` demonstrates
this distinction: its V5C entry is positively empty, like BDE `0a3954c0…`, and its
otherwise matching consumer differs only in these identifiers. The targeted
regression authenticates the WX1DM package and proves both correction directions
against the Seven witness. BDE's original pair returns `UpdateError::Authentication`;
its successful codec roundtrip must not be described as package authentication.

The older XS06JL `7b417d52…` remains outside the binding domain. Its positive V5C
latched-object program matches `00eeb09b…`, but the 830-byte controller helper,
absolute-versus-relative consumer call encoding, and diagnostic producer with a
different stack/header-copy implementation need separate equivalence proof. This
observed binding split is not evidence of a different V5C hardware requirement.

Exact Normal SHA256 witnesses for this comparison:

| Model / hardware / revision | Normal SHA256 | Observed independent V5C |
| --- | --- | --- |
| BDE-PR1JAME / SAT 8801 / 1.01 | `0a3954c01e54510eea5c870fe633fd0532d2415744e5a860962acfd06bb7430c` | Empty |
| BDR-WX1DM / SAT 8801 / 1.01 | `9b44cfbe5134d4f992b4f1b6e4cdea930c61f83cdbd6808f858f87ba27eedb23` | Empty |
| BDR-XS06JL / SAT 8722 / 1.11 | `00eeb09ba68c05db205d40efdcb7aac5c120439d39ba564e5b4c7d3061043a59` | Latched object |
| BDR-XS06JL / SAT 8721 / 1.01 | `7b417d52597883ce77717c4fe9701e528ecbffc0c9733cd28e3aa6dc8a75287b` | Matching latched object; complete X binding unavailable |
