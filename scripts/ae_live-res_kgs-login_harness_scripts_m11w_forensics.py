#!/usr/bin/env python3
"""M11w: full forensic dump at free(8): frame chain, all free-target fields,
memory scan for the 8 value around the per-player rig objects."""
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

    def at_free(uc, address, size, ud):
        x0 = uc.reg_read(UC_ARM64_REG_X0)
        if x0 != 8 or caught[0]:
            return
        caught[0] = True
        print(f'\n=== free(8) @0x2efa830 FORENSICS ===')
        for rn in ('X0', 'X1', 'X2', 'X19', 'X20', 'X21', 'X22', 'X23'):
            print(f'  {rn}={uc.reg_read(globals()[f"UC_ARM64_REG_{rn}"]):#x}')
        # full frame chain
        fp = uc.reg_read(UC_ARM64_REG_FP)
        print('  frame chain:')
        for k in range(10):
            try:
                fpv = core.safe_read_u64(fp)
                ret = core.safe_read_u64(fp + 8)
            except Exception:
                break
            if not (core.base < ret < core.base + 0xA0000000):
                break
            print(f'    frame {k}: ret={ret - core.base:#x}')
            fp = fpv
            if fp < 0x500000000000 or fp > 0x800000000000:
                break
        # if x19 looks like an object, dump its free-target fields
        x19 = uc.reg_read(UC_ARM64_REG_X19)
        if 0x500000000000 < x19 < 0xF000000000000:
            print(f'  [x19 object fields]:')
            for off in (0x18, 0x30, 0x60, 0x78, 0xa8, 0xc0, 0xf0, 0x108, 0x138, 0x170):
                try:
                    print(f'    [{off:#x}] = {core.safe_read_u64(x19 + off):#x}')
                except Exception:
                    print(f'    [{off:#x}] unreadable')
        # scan the rig region for qwords containing 8 in entry-like slots:
        # entries are 0x300-spaced at 0x900019f7910.. — check their +0x20
        print('  entry scan ([E+0x20] should be valid sub-obj):')
        for e in (0x900019f7910, 0x900019f7a10, 0x900019f7d10,
                  0x900019f8310, 0x900019f8410, 0x900019f8610,
                  0x900019f9010, 0x900019f9210, 0x900019f9310):
            try:
                v20 = core.safe_read_u64(e + 0x20)
                v10 = core.safe_read_u64(e + 0x10)
                print(f'    E {e:#x}: [+0x10]={v10:#x} [+0x20]={v20:#x}'
                      + ('   <== 8!!!' if v20 == 8 else ''))
            except Exception:
                print(f'    E {e:#x}: unreadable')
        # scan backwards from 0x900019f6d00 to 0x900019f6f80 for value 8
        print('  qword==8 scan in 0x900019f6c00..0x900019f7000:')
        for a in range(0x900019f6c00, 0x900019f7000, 8):
            try:
                if core.safe_read_u64(a) == 8:
                    print(f'    {a:#x} = 8')
            except Exception:
                pass

    core.uc.hook_add(UC_HOOK_CODE, at_free,
                     begin=core.base + 0x2efa830, end=core.base + 0x2efa830 + 4)

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
