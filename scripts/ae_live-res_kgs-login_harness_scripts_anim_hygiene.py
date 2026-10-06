#!/usr/bin/env python3
"""Animation-asset hygiene for the headless eFootball harness (M12).

cmd-6 = the per-player animation rig build. With empty payloads (no FoxAnim
.hkx data) the rig build retries forever because the clip-id scan
(0x2bd7160: linear search over 0x2f0-stride entries, count [this+0xa0],
table [this+0x98]) returns -1 for every real key, and the caller restarts
the build. Emulation trace: 800M-instruction dispatcher call never
returns; the hot PC is the scan body (0x2bd718c).

Fix: at the scan's last iteration, if no entry matched, stamp the
requested key into the final (empty) entry so the game's own lookup
succeeds with a zeroed (empty) animation. Runtime-context repair —
no game logic rewritten.
"""
from unicorn import *
from unicorn.arm64_const import *

HEAP_LO = 0x90000000000
HEAP_HI = 0x91000000000

# scan loop body: ldr x11, [x10] (the id compare iteration)
A_SCAN_BODY = 0x2bd7180
# dispatcher retry gate: after player_ctor2 (0x6a027f8) returns, the
# handler at 0x6a018d8 re-reads a completion flag (x20 = flag address,
# e.g. inner+0x3ca4 for cmd 6); flag stays set without real asset data
# -> the dispatcher loops forever. After RETRY_LIMIT ctor calls per flag
# address, clear the flag so the game's own advance path runs.
A_GATE_CHECK = 0x6a018d8
RETRY_LIMIT = 400


def is_heap(v):
    return HEAP_LO <= v < HEAP_HI


def install_anim_hygiene(core):
    base = core.base
    stats = {'scan_fix': 0, 'gate_clear': 0}
    gate_counts = {}

    def on_scan(uc, address, size, ud):
        x10 = uc.reg_read(UC_ARM64_REG_X10)   # entry ptr
        x8 = uc.reg_read(UC_ARM64_REG_X8)     # key
        x9 = uc.reg_read(UC_ARM64_REG_X9)     # count (w)
        x0 = uc.reg_read(UC_ARM64_REG_X0)     # i
        if not is_heap(x10) or not x8:
            return
        try:
            eid = core.safe_read_u64(x10)
        except Exception:
            return
        if eid == x8:
            return                              # will match naturally
        if (x0 + 1) >= (x9 & 0xFFFFFFFF):
            # last iteration and no match: stamp the key so the compare
            # that follows (ldr x11, [x10]) succeeds
            try:
                core.write_u64(x10, x8)
                stats['scan_fix'] += 1
            except Exception:
                pass

    core.uc.hook_add(UC_HOOK_CODE, on_scan,
                     begin=base + A_SCAN_BODY, end=base + A_SCAN_BODY + 4)

    def on_gate(uc, address, size, ud):
        x20 = uc.reg_read(UC_ARM64_REG_X20)   # the flag address
        if not is_heap(x20):
            return
        try:
            flag = core.uc.mem_read(x20, 1)[0]
        except Exception:
            return
        if flag == 0:
            return                            # gate already passed
        n = gate_counts.get(x20, 0) + 1
        gate_counts[x20] = n
        if n >= RETRY_LIMIT:
            # the async-completion never comes headless: force the advance
            core.uc.mem_write(x20, b'\0')
            gate_counts[x20] = 0
            stats['gate_clear'] += 1

    core.uc.hook_add(UC_HOOK_CODE, on_gate,
                     begin=base + A_GATE_CHECK, end=base + A_GATE_CHECK + 4)
    return stats
