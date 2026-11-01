# Pioneer register analysis backlog — 2026-11-01

## Decision and evidence

Exclude **FEC0 bit 6 only** from hardware-family matching. Keep FE94, the
remaining FEC0 bits, ASIC setup, board markers and servo evidence. Scheme v5
normalizes FEC0 values with `value & 0xBF`, deduplicating the resulting set.
Raw values remain available as `FamilyFingerprint::raw_pins` and in the saved
unmodified evidence. No firmware register value is patched by this change.

BDX-PR1ML SAT 8801 initializes FEC0 to C7; BDR-211M SAT 8801 initializes it
to 87. Their ASIC, board, FE94 and servo fingerprints otherwise match.
Both Kernel and Normal contain the differing write, in initialization/reset
code. A feature/mode selection on a shared platform is the working hypothesis;
its physical function is **not established**. Do not label it a confirmed PR1
feature enable or infer what flipping it will do.

Observed direct accesses also set/clear bit 0, clear bits 2/7 and update bits
3/4 using a read/modify/write sequence. These preserve bit 6. This is not a
proof that indirect or resident code never changes it.

PR1ML Kernel body offsets: immediate C7 at 0x3bc2, FEC0 write at 0x3bc4.
211M SAT8801 ID60 Kernel: immediate 87 at 0x3bf4, write at 0x3bf6.
PR1ML Normal stored-region offsets: immediate C7 at 0xa0168, write at 0xa016a.
211M Normal: immediate 87 at 0xa06b6, write at 0xa06b8.
Offsets identify decoded regions, not universal addresses across versions.

On the retained 723-package corpus (531 fingerprinted), masking bit 6 joins
three pairs of v4 families. It joins PR1ML and 211M SAT8801, but does not join
the distinct 211M SAT8800 board/servo fingerprint. Family equality alone does
not establish completion of a physical crossflash.

## Bit-by-bit research backlog

| Register | Family filter status | What is established / open |
|---|---|---|
| FE8F | Excluded since v4 | Seen in ATA/ATAPI host bring-up; individual bit meanings and possible feature selection remain open. |
| FE94 | Retained | Configuration evidence; individual physical functions unestablished. Do not remove merely by analogy. |
| FE9D | Excluded since v4 | Seen in host bring-up; investigate mode, feature, timing and electrical constraints per bit. |
| FE9F | Excluded since v4 | Seen in host bring-up and retained settings evidence; all bit meanings remain research items. |
| FEC0 | All bits except bit 6 retained in v5 | Bit 6 C7/87 split above; analyze all eight bits, not just bit 6. |

For each bit 0–7 in each register: catalog exact OEM values by firmware and
platform, distinguish initialization/reset from runtime changes, trace direct
and indirect reads/writes and dependent branches, correlate differences on
otherwise matching hardware, and seek chip-specific documentation. Record
whether software controls the bit or hardware supplies status; identify any
reserved or write-one-to-clear semantics before proposing experiments.
Only then design isolated bit-flip experiments with measurable expected
behavior. No bit-flip firmware experiments or physical tests were performed.

Historical removal: pioneer-optical commit 07e9b8eee03c26b045f7639dd076ae0f67e6a7d5
removed FE8F/FE9D/FE9F from the family key on October 24; FE94 was retained.
This established a host-configuration versus identity distinction, not a
complete bitfield map or proof that the excluded bits are feature switches.

## Retained evidence

Private evidence: `freemkv-private/research/pioneer-registers-20261101/`.
Contains original 723-package fingerprints, comparison results, disassembly
contexts and four hash-bound Kernel/Normal probe pairs. Inputs were decoded
using pioneer-optical c8fbc1581cb29c99e929291d24c8ac616b0cf778.
Raw firmware and archives remain private; do not add them to the public crate.
