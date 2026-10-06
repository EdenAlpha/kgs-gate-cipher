#!/usr/bin/env python3
"""M11k: register "body" via the game's own 0x66d9360 with the exact args
its caller 0x6819f70 uses, then verify lookup + drive past cmd 6.

The game's own call (from 0x6819ff4 disassembly):
    hub = 0x66d930c()
    0x66d9360(hub, "body", "cpk_dat/common/anime/FoxAnim/Body/", "Projekt.hkx")
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

OUT = '/home/z/my-project/apk_lab/analysis/m11k_drive.json'
INIT_FNS = [0x68a7a5c, 0x66fb250, 0x66f3f3c]
A_SUBSYS_BOOT = 0x677dbf0
A_CASCADE = 0x68a83b4
A_HUB = 0x66d930c
A_REGISTER = 0x66d9360
A_LOOKUP = 0x66d9a88


def mk_str(core, s):
    """libc++ std::string in guest memory (SSO or long form)."""
    b = s.encode() if isinstance(s, str) else s
    if len(b) < 23:
        buf = bytes([len(b) << 1]) + b + b'\0' * (24 - 1 - len(b))
        a = core.alloc(32, buf, name=f'str_{s[:8]}')
        return a
    # long form: [0]=cap<<1|1, [8]=size, [16]=char ptr
    cap = (len(b) + 16) & ~15
    chars = core.alloc(len(b) + 1, b + b'\0', name=f'strc_{s[:8]}')
    buf = struct.pack('<QQQ', (cap << 1) | 1, len(b), chars)
    a = core.alloc(32, buf, name=f'str_{s[:8]}')
    return a


def main():
    world = SetupWorld(verbose=True)
    core = world.core
    inner = world.inner

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

    # cascade + subsys boot (with dtmgr real-construct)
    core.write_u64(core.base + 0xa409b10, 0)
    r = core.call(A_CASCADE, timeout_s=600, max_insns=2_000_000_000)
    print(f'cascade: err={r["error"]}')
    core.write_u64(core.base + 0xa409b10, 0)
    r = core.call(A_SUBSYS_BOOT, w0=1, w1=1, x2=0, x3=1, w4=0,
                  timeout_s=300, max_insns=1_000_000_000)
    print(f'subsys: err={r["error"]}')

    # *** REGISTER "body" via the game's own register function ***
    faults.clear()
    r = core.call(A_HUB, timeout_s=60)
    hub = core.safe_read_u64(core.base + 0xa4097f8)
    print(f'name hub: {hub:#x} (err={r["error"]})')

    s_body = mk_str(core, 'body')
    s_path = mk_str(core, 'cpk_dat/common/anime/FoxAnim/Body/')
    s_file = mk_str(core, 'Projekt.hkx')
    r = core.call(A_REGISTER, x0=hub, x1=s_body, x2=s_path, x3=s_file,
                  timeout_s=300, max_insns=500_000_000)
    print(f'register("body"): err={r["error"]}')
    if faults:
        print(f'  {len(faults)} faults; last {faults[-1]}')

    # verify: lookup "body"
    r = core.call(A_LOOKUP, x0=hub, x1=s_body, timeout_s=60)
    print(f'lookup("body") -> x0={r["x0"]:#x} (err={r["error"]})')
    body = r['x0']
    if body:
        print(f'  body+0x20 = {core.safe_read_u64(body + 0x20):#x}'
              f'  body[0] = {core.safe_read_u64(body):#x}')

    # register "fixdemo" too (the second container 0x68197cc looks up)
    # find its args: check 0x68197cc's register sibling — first just try the
    # same path pattern; skip unless needed.

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

    json.dump({'history': hist}, open(OUT, 'w'), indent=1, default=str)
    print('JSON ->', OUT)


if __name__ == '__main__':
    main()
