#!/usr/bin/env python3
"""M11c: run Konami's own subsystem bootstrap 0x677dbf0(1,1,0,1,0), then
drive the sequencer. This replaces the fabricated dtmgr *(0xa409b10) with the
REAL object (calloc(0x340,0x10) + big ctor 0x66eece0 + vtable 0x977ae90 +
real slot arrays at +0xd0), fixing the cmd-5 envelope fault at its root.

Call convention (from the 3 real call sites, esp. 0x69921f0 in MatchMain):
    w0=1 (construct dtmgr), w1=1, w2=0 (dtmgr ctor arg), w3=1 (flags bit3),
    x4=0
"""
import json
import os
import struct
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from unicorn import *
from unicorn.arm64_const import *
from m9_setup_seq import SetupWorld, slots22
from m10_realctor import A_INNER_CTOR

OUT = '/home/z/my-project/apk_lab/analysis/m11c_drive.json'
INIT_FNS = [0x68a7a5c, 0x66fb250, 0x66f3f3c]
A_SUBSYS_BOOT = 0x677dbf0

TRACE_FNS = {
    0x6a0195c: 'gate', 0x70c1c00: 'db_query', 0x6993afc: 'player_ctor',
    0x6a02000: 'construction_driver', 0x6a027f8: 'player_ctor2',
    0x6a027b0: 'cmd5_guard', 0x71e1ea8: 'extra_ctor_C0',
    0x6fbc05c: 'extra_ctor_E0', 0x6fa6f5c: 'extra_ctor_D8',
    0x677dbf0: 'subsys_boot',
    0x66eec8c: 'dtmgr_ctor',
}


def main():
    world = SetupWorld(verbose=True)
    core = world.core
    inner = world.inner
    events = []

    def hook_fn(addr, name):
        def h(uc, address, size, ud):
            events.append({'fn': name,
                           'x0': hex(uc.reg_read(UC_ARM64_REG_X0)),
                           'x1': hex(uc.reg_read(UC_ARM64_REG_X1)),
                           'x2': hex(uc.reg_read(UC_ARM64_REG_X2)),
                           'cmd': core.safe_read_u32(inner + 8)})
        return h

    for addr, name in TRACE_FNS.items():
        core.uc.hook_add(UC_HOOK_CODE, hook_fn(addr, name),
                         begin=core.base + addr, end=core.base + addr + 4)

    faults = []

    def mem_err(uc, type_, address, size, value, ud):
        pc = uc.reg_read(UC_ARM64_REG_PC)
        lr = uc.reg_read(UC_ARM64_REG_LR)
        faults.append({'type': int(type_), 'addr': address,
                       'pc': pc - core.base, 'lr': lr - core.base})
        return False

    core.uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED
                     | UC_HOOK_MEM_FETCH_UNMAPPED | UC_HOOK_MEM_FETCH_PROT,
                     mem_err)

    core.uc.mem_write(core.base + 0x68a0f30, struct.pack('<I', 0xD503201F))
    bs = world.bootstrap_game(run_init_array=True, max_init=15)
    r = core.call(0x6a09418, timeout_s=60)
    for fn in INIT_FNS:
        r = core.call(fn, timeout_s=120, max_insns=500_000_000)
        print(f'init {fn:#x}: err={r["error"]}')

    # *** THE NEW STEP: Konami's own subsystem bootstrap ***
    # The dtmgr lazy ctor 0x66eec8c bails if *(0xa409b10) != NULL — our M6
    # fabrication blocks it. NULL the global first so Konami's own code
    # constructs the REAL dtmgr (calloc + big ctor + vtable 0x977ae90).
    core.write_u64(core.base + 0xa409b10, 0)
    faults.clear()
    r = core.call(A_SUBSYS_BOOT, w0=1, w1=1, x2=0, x3=1, w4=0,
                  timeout_s=300, max_insns=1_000_000_000)
    print(f'subsys_boot 0x677dbf0: err={r["error"]}')
    if faults:
        print('  faults during subsys boot:')
        for f in faults[:10]:
            print(f'    {f}')
        faults.clear()
    dt = core.safe_read_u64(core.base + 0xa409b10)
    print(f'dtmgr *(0xa409b10) = {dt:#x}')
    if dt:
        vt = core.safe_read_u64(dt)
        slots = core.safe_read_u64(dt + 0xd0)
        cnt = core.safe_read_u32(dt + 0xc4)
        cap = core.safe_read_u32(dt + 0xc8)
        print(f'  vtable={vt - core.base:#x} (want 0x977ae90) '
              f'slotarray={slots:#x} count={cnt} cap={cap}')

    for i in range(16):
        core.write_u64(world.garr + i * 8, 0)
    core.write_u64(world.garr + 9 * 8, world.gobj)
    core.write_u64(world.garr + 10 * 8, world.gobj)
    r = core.call(A_INNER_CTOR, x0=inner, w1=0, timeout_s=300,
                  max_insns=1_000_000_000)
    print('inner ctor err:', r['error'])
    core.write_u32(inner + 8, 0)

    def replug():
        core.write_u64(inner + 0x3868 + 0x40, world.ctrl3868)
        core.write_u64(inner + 0x3818 + 0x40, world.ctrl3818)

    replug()
    hist = []
    for i in range(120):
        events.append({'fn': 'STEP', 'x0': i, 'x1': 0, 'x2': 0, 'cmd': -1})
        faults.clear()
        before, after, err, pc = world.step(timeout_s=240)
        replug()
        n = sum(1 for p in slots22(core, inner) if p)
        extras = [core.safe_read_u64(inner + 0xC0 + j * 8) for j in range(4)]
        n_ex = sum(1 for e in extras if e)
        hist.append({'step': i, 'cmd': before, 'next': after, 'err': err,
                     'slots22': n, 'extras': n_ex,
                     'faults': list(faults[-3:])})
        print(f'step {i:2d}: cmd {before:#04x} -> {after:#04x} err={err} '
              f'slots={n}/22 extras={n_ex}/4'
              + (f' F={faults[-1]}' if faults else ''))
        if after == 0x67:
            print('*** SEQUENCER COMPLETE (cmd 0x67) ***')
            break

    c = Counter(e['fn'] for e in events)
    print('--- call counts ---')
    for k, v in c.most_common():
        print(f'  {k:20s} {v}')
    pc2 = [e for e in events if e['fn'] == 'player_ctor2']
    print(f'player_ctor2 (0x6a027f8) events: {len(pc2)}')
    for e in pc2[:44]:
        print('   ', e['x1'], e['x2'])

    json.dump({'history': hist, 'counts': dict(c),
               'player_ctor2': pc2[:300], 'events': events[-800:]},
              open(OUT, 'w'), indent=1, default=str)
    print('JSON ->', OUT)


if __name__ == '__main__':
    main()
