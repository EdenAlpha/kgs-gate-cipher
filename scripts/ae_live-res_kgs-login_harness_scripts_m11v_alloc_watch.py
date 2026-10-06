#!/usr/bin/env python3
"""M11v: catch pool_alloc returning small ints (8) + callers of 0x6780eb4."""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from unicorn import *
from unicorn.arm64_const import *
from m9_setup_seq import SetupWorld, slots22
from m10_realctor import A_INNER_CTOR

INIT_FNS = [0x68a7a5c, 0x66fb250, 0x66f3f3c]
A_SUBSYS_BOOT = 0x677dbf0
A_CASCADE = 0x68a83b4
A_HUB = 0x66d930c
A_REGISTER = 0x66d9360
# every bl 0x2efa4dc call site we care about: log return value after
ALLOC_CALLER_SITES = [0x6781234, 0x6781360]   # map-insert(0x28) x2 sites
A_RESET = 0x6780eb4


def mk_str(core, s):
    b = s.encode() if isinstance(s, str) else s
    if len(b) < 23:
        buf = bytes([len(b) << 1]) + b + b'\0' * (24 - 1 - len(b))
        return core.alloc(32, buf, name=f'str_{s[:8]}')
    cap = (len(b) + 16) & ~15
    chars = core.alloc(len(b) + 1, b + b'\0', name=f'strc_{s[:8]}')
    buf = struct.pack('<QQQ', (cap << 1) | 1, len(b), chars)
    return core.alloc(32, buf, name=f'str_{s[:8]}')


def main():
    world = SetupWorld(verbose=True)
    core = world.core
    inner = world.inner
    caught = [False]
    events = []

    def at_free(uc, address, size, ud):
        x0 = uc.reg_read(UC_ARM64_REG_X0)
        if x0 == 8 and not caught[0]:
            caught[0] = True
            x19 = uc.reg_read(UC_ARM64_REG_X19)
            print(f'\n=== free(8) caught; X19(this2)={x19:#x} ===')
            head = core.safe_read_u64(x19 + 0x30)
            print(f'  [this2+0x30] head/tail = {head:#x}')
            node = head
            for k in range(10):
                if not (0x500000000000 < node < 0xF000000000000):
                    print(f'  chain[{k}] = {node:#x} <== NON-HEAP')
                    break
                print(f'  chain[{k}] node={node:#x} [n]={core.safe_read_u64(node):#x} '
                      f'[n+8]={core.safe_read_u64(node + 8):#x} '
                      f'[n+0x10]={core.safe_read_u64(node + 0x10):#x}')
                node = core.safe_read_u64(node + 0x10)
            print('  --- events (last 40) ---')
            for e in events[-40:]:
                print(f'    {e}')

    core.uc.hook_add(UC_HOOK_CODE, at_free,
                     begin=core.base + 0x2efa830, end=core.base + 0x2efa830 + 4)

    # after map-insert's pool_alloc(0x28): is the return sane?
    def after_alloc(uc, address, size, ud):
        x0 = uc.reg_read(UC_ARM64_REG_X0)
        if x0 == 0 or (0x1000 < x0 < 0x500000000000) or x0 < 0x1000:
            events.append(f'alloc@{address - core.base:#x} -> {x0:#x}'
                          + (' *** SMALL ***' if x0 <= 0x1000 else ''))

    for site in ALLOC_CALLER_SITES:
        core.uc.hook_add(UC_HOOK_CODE, after_alloc,
                         begin=core.base + site, end=core.base + site + 4)

    # who calls A_RESET(this, 8)?
    def at_reset(uc, address, size, ud):
        x0 = uc.reg_read(UC_ARM64_REG_X0)
        x1 = uc.reg_read(UC_ARM64_REG_X1)
        lr = uc.reg_read(UC_ARM64_REG_LR) - core.base
        if x1 == 8:
            events.append(f'RESET(this={x0:#x}, arg=8) caller_lr={lr:#x}')

    core.uc.hook_add(UC_HOOK_CODE, at_reset,
                     begin=core.base + A_RESET, end=core.base + A_RESET + 4)

    def at_444(uc, address, size, ud):
        x8 = uc.reg_read(UC_ARM64_REG_X8)
        if x8 and not core.safe_read_u64(x8 + 0x80):
            buf = core.alloc(0x200, b'\0' * 0x200, name='empty_payload')
            core.write_u64(x8 + 0x80, buf)

    core.uc.hook_add(UC_HOOK_CODE, at_444,
                     begin=core.base + 0x66dd444, end=core.base + 0x66dd444 + 4)

    def at_hash(uc, address, size, ud):
        x0 = uc.reg_read(UC_ARM64_REG_X0)
        w1 = uc.reg_read(UC_ARM64_REG_X1) & 0xFFFFFFFF
        bad = x0 == 0
        if not bad:
            try:
                core.uc.mem_read(x0, 1)
                if w1:
                    core.uc.mem_read(x0 + w1 - 1, 1)
            except Exception:
                bad = True
        if bad:
            uc.reg_write(UC_ARM64_REG_X0, core.alloc(0x200, b'\0' * 0x200,
                                                     name='empty_payload'))
            uc.reg_write(UC_ARM64_REG_X1, 0)

    core.uc.hook_add(UC_HOOK_CODE, at_hash,
                     begin=core.base + 0x66ee728, end=core.base + 0x66ee728 + 4)

    def mem_err(uc, type_, address, size, value, ud):
        return False

    core.uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED
                     | UC_HOOK_MEM_FETCH_UNMAPPED | UC_HOOK_MEM_FETCH_PROT,
                     mem_err)

    core.uc.mem_write(core.base + 0x68a0f30, struct.pack('<I', 0xD503201F))
    bs = world.bootstrap_game(run_init_array=True, max_init=15)
    r = core.call(0x6a09418, timeout_s=60)
    for fn in INIT_FNS:
        r = core.call(fn, timeout_s=120, max_insns=500_000_000)
    core.write_u64(core.base + 0xa409b10, 0)
    r = core.call(A_CASCADE, timeout_s=600, max_insns=2_000_000_000)
    core.write_u64(core.base + 0xa409b10, 0)
    r = core.call(A_SUBSYS_BOOT, w0=1, w1=1, x2=0, x3=1, w4=0,
                  timeout_s=300, max_insns=1_000_000_000)
    r = core.call(A_HUB, timeout_s=60)
    hub = core.safe_read_u64(core.base + 0xa4097f8)
    r = core.call(A_REGISTER, x0=hub, x1=mk_str(core, 'body'),
                  x2=mk_str(core, 'cpk_dat/common/anime/FoxAnim/Body/'),
                  x3=mk_str(core, 'Projekt.hkx'),
                  timeout_s=300, max_insns=500_000_000)
    for i in range(16):
        core.write_u64(world.garr + i * 8, 0)
    core.write_u64(world.garr + 9 * 8, world.gobj)
    core.write_u64(world.garr + 10 * 8, world.gobj)
    r = core.call(A_INNER_CTOR, x0=inner, w1=0, timeout_s=300,
                  max_insns=1_000_000_000)
    core.write_u32(inner + 8, 0)
    core.write_u64(core.base + 0x9a9da10, 0)

    def replug():
        core.write_u64(inner + 0x3868 + 0x40, world.ctrl3868)
        core.write_u64(inner + 0x3818 + 0x40, world.ctrl3818)

    replug()
    for i in range(20):
        before, after, err, pc = world.step(timeout_s=240)
        replug()
        print(f'step {i}: cmd {before:#x} -> {after:#x} err={err}')
        if caught[0]:
            break


if __name__ == '__main__':
    main()
