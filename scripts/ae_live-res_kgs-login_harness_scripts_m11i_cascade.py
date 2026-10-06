#!/usr/bin/env python3
"""M11i: run Konami's own 41-initializer bootstrap cascade 0x68a83b4,
then the subsystem bootstrap, then drive the sequencer past cmd 6."""
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

OUT = '/home/z/my-project/apk_lab/analysis/m11i_drive.json'
INIT_FNS = [0x68a7a5c, 0x66fb250, 0x66f3f3c]
A_SUBSYS_BOOT = 0x677dbf0
A_CASCADE = 0x68a83b4       # the 41-initializer GameThread boot

TRACE_FNS = {
    0x6a0195c: 'gate', 0x70c1c00: 'db_query', 0x6993afc: 'player_ctor',
    0x6a02000: 'construction_driver', 0x6a027f8: 'player_ctor2',
    0x6a027b0: 'cmd5_guard', 0x71e1ea8: 'extra_ctor_C0',
    0x6fbc05c: 'extra_ctor_E0', 0x6fa6f5c: 'extra_ctor_D8',
    0x677dbf0: 'subsys_boot', 0x66eec8c: 'dtmgr_ctor',
    0x68a83b4: 'cascade_boot',
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

    # *** STEP 1: Konami's 41-initializer cascade ***
    core.write_u64(core.base + 0xa409b10, 0)   # let the real dtmgr construct
    faults.clear()
    r = core.call(A_CASCADE, timeout_s=600, max_insns=2_000_000_000)
    print(f'cascade 0x68a83b4: err={r["error"]}')
    if faults:
        print(f'  {len(faults)} faults; last: {faults[-1]}')

    # *** STEP 2: the subsystem bootstrap (dtmgr etc.) ***
    faults.clear()
    core.write_u64(core.base + 0xa409b10, 0)
    r = core.call(A_SUBSYS_BOOT, w0=1, w1=1, x2=0, x3=1, w4=0,
                  timeout_s=300, max_insns=1_000_000_000)
    print(f'subsys_boot: err={r["error"]}')

    # check the singletons
    for g, want in ((0xa409c38, 0x977ae70), (0xa409b10, 0x977ae90),
                    (0xa409c40, None), (0xa409c48, None)):
        v = core.safe_read_u64(core.base + g)
        vt = core.safe_read_u64(v) if v else 0
        print(f'  *({g:#x}) = {v:#x} vt={vt - core.base:#x}'
              + (f' (want {want:#x})' if want else ''))

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
        hist.append({'step': i, 'cmd': before, 'next': after, 'err': err,
                     'slots22': n, 'faults': list(faults[-3:])})
        print(f'step {i:2d}: cmd {before:#04x} -> {after:#04x} err={err} '
              f'slots={n}/22'
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
