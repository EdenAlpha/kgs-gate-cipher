#!/usr/bin/env python3
"""M13c: instrument cmd-0x66's aggregation loops (outer 0x6a017fc / inner
0x6a0181c / done 0x6a012b8) during big-budget calls to measure progress."""
import os
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from unicorn import *
from unicorn.arm64_const import *
from m9_setup_seq import SetupWorld, slots22, A_DISPATCH
from m10_realctor import A_INNER_CTOR
from pool_hygiene import install_pool_hygiene
from anim_hygiene import install_anim_hygiene

INIT_FNS = [0x68a7a5c, 0x66fb250, 0x66f3f3c]
A_SUBSYS_BOOT = 0x677dbf0
A_CASCADE = 0x68a83b4
A_HUB = 0x66d930c
A_REGISTER = 0x66d9360


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
    stats = install_pool_hygiene(core, verbose=True)
    astats = install_anim_hygiene(core)

    counts = {'outer': 0, 'inner': 0, 'done': 0, 'spin': 0}

    def on_outer(uc, address, size, ud):
        counts['outer'] += 1

    def on_inner(uc, address, size, ud):
        counts['inner'] += 1

    def on_done(uc, address, size, ud):
        counts['done'] += 1

    core.uc.hook_add(UC_HOOK_CODE, on_outer,
                     begin=core.base + 0x6a017fc, end=core.base + 0x6a017fc + 4)
    core.uc.hook_add(UC_HOOK_CODE, on_inner,
                     begin=core.base + 0x6a0181c, end=core.base + 0x6a0181c + 4)
    core.uc.hook_add(UC_HOOK_CODE, on_done,
                     begin=core.base + 0x6a012b8, end=core.base + 0x6a012b8 + 4)

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

    def dispatch(insns, tmo):
        r = core.call(A_DISPATCH, x0=inner, x1=world.msg,
                      timeout_s=tmo, max_insns=insns)
        return core.safe_read_u32(inner + 8), r

    replug()
    for i in range(12):
        before, after, err, pc = world.step(timeout_s=60)
        replug()
    before, after, err, pc = world.step(timeout_s=45)
    core.write_u32(inner + 8, 0x66)
    print('*** JUMPED TO 0x66 ***', flush=True)
    logf = open('/tmp/m13c.log', 'a')
    for j in range(6):
        c0 = dict(counts)
        t0 = time.time()
        cmd, r = dispatch(2_000_000_000, 250)
        dur = time.time() - t0
        c1 = dict(counts)
        line = (f'big {j}: cmd={cmd:#x} err={r["error"]} '
                f'pc={r["pc"] - core.base:#x} dur={dur:.0f}s '
                f'outer+={c1["outer"] - c0["outer"]} '
                f'inner+={c1["inner"] - c0["inner"]} '
                f'done+={c1["done"] - c0["done"]}')
        print(line, flush=True)
        logf.write(line + '\n')
        logf.flush()
        replug()
        if cmd >= 0x6d:
            print('*** LAST CMD 0x6d REACHED ***', flush=True)
            break
    print(f'counts: {counts}', flush=True)
    print(f'pool stats: {stats}', flush=True)
    print(f'anim stats: {astats}', flush=True)
    logf.write(f'counts: {counts}\npool stats: {stats}\n'
               f'anim stats: {astats}\n')
    logf.close()


if __name__ == '__main__':
    main()
