#!/usr/bin/env python3
"""M11l: probe the NEW cmd-6 fault (after body registration)."""
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

    armed = {'v': False}
    fault = {}

    def mem_err(uc, type_, address, size, value, ud):
        pc = uc.reg_read(UC_ARM64_REG_PC)
        if armed['v'] and 'pc' not in fault:
            regs = {}
            for i in range(29):
                regs[f'x{i}'] = uc.reg_read(globals()[f'UC_ARM64_REG_X{i}'])
            fault.update(regs)
            fault['pc'] = pc - core.base
            fault['addr'] = address
            fault['lr'] = uc.reg_read(UC_ARM64_REG_LR) - core.base
            fault['sp'] = uc.reg_read(UC_ARM64_REG_SP)
        if armed['v']:
            print(f'  FAULT type={type_} addr={address:#x} pc={pc-core.base:#x}')
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
    r = core.call(A_HUB, timeout_s=60)     # lazy-construct the name hub
    hub = core.safe_read_u64(core.base + 0xa4097f8)
    r = core.call(A_REGISTER, x0=hub,
                  x1=mk_str(core, 'body'),
                  x2=mk_str(core, 'cpk_dat/common/anime/FoxAnim/Body/'),
                  x3=mk_str(core, 'Projekt.hkx'),
                  timeout_s=300, max_insns=500_000_000)
    print(f'register("body"): err={r["error"]}')
    for i in range(16):
        core.write_u64(world.garr + i * 8, 0)
    core.write_u64(world.garr + 9 * 8, world.gobj)
    core.write_u64(world.garr + 10 * 8, world.gobj)
    r = core.call(A_INNER_CTOR, x0=inner, w1=0, timeout_s=300,
                  max_insns=1_000_000_000)
    core.write_u32(inner + 8, 0)

    def replug():
        core.write_u64(inner + 0x3868 + 0x40, world.ctrl3868)
        core.write_u64(inner + 0x3818 + 0x40, world.ctrl3818)

    replug()
    for i in range(20):
        before, after, err, pc = world.step(timeout_s=240)
        replug()
        print(f'step {i}: cmd {before:#x} -> {after:#x} err={err}')
        if i >= 12:
            armed['v'] = True
        if fault:
            break

    print('\n=== fault registers ===')
    for k in sorted(fault):
        print(f'  {k} = {fault[k]:#x}' if isinstance(fault[k], int)
              else f'  {k} = {fault[k]}')
    # stack
    if fault:
        sp = fault['sp']
        try:
            stack = core.safe_read(sp - 0x40, 0x300)
            print('=== stack text addrs ===')
            for j in range(0, len(stack), 8):
                v = struct.unpack_from('<Q', stack, j)[0]
                if core.base < v < core.base + 0xA0000000:
                    print(f'  {sp - 0x40 + j - sp:+#x}: {v - core.base:#x}')
        except Exception as e:
            print('stack dump failed:', e)


if __name__ == '__main__':
    main()
