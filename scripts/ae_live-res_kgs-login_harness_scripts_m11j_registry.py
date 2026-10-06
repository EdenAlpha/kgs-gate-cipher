#!/usr/bin/env python3
"""M11j: full name-registry traffic during the drive.
Hooks: 0x66d9360 (register), 0x66d9a88 (lookup), 0x6819f70 (register-body)."""
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


def read_str(core, x1):
    try:
        raw = core.safe_read(x1, 64)
        b0 = raw[0]
        if b0 & 1:
            plen = (b0 >> 1) & 0x3F
            if plen >= 0x3F:
                hp = struct.unpack_from('<Q', raw, 8)[0]
                hraw = core.safe_read(hp, 128)
                return hraw.split(b'\0')[0].decode('utf8', 'replace')
            return raw[1:1 + plen].decode('utf8', 'replace')
        return raw[1:].split(b'\0')[0].decode('utf8', 'replace')
    except Exception:
        return f'<unreadable {x1:#x}>'


def main():
    world = SetupWorld(verbose=True)
    core = world.core
    inner = world.inner

    regs = []
    lookups = []
    body_regs = 0

    def at_reg(uc, address, size, ud):
        name = read_str(core, uc.reg_read(UC_ARM64_REG_X1))
        if len(regs) < 100:
            regs.append(name)

    core.uc.hook_add(UC_HOOK_CODE, at_reg,
                     begin=core.base + 0x66d9360, end=core.base + 0x66d9360 + 4)

    def at_lookup(uc, address, size, ud):
        name = read_str(core, uc.reg_read(UC_ARM64_REG_X1))
        if len(lookups) < 200:
            lookups.append(name)

    core.uc.hook_add(UC_HOOK_CODE, at_lookup,
                     begin=core.base + 0x66d9a88, end=core.base + 0x66d9a88 + 4)

    def at_body(uc, address, size, ud):
        nonlocal body_regs
        body_regs += 1

    core.uc.hook_add(UC_HOOK_CODE, at_body,
                     begin=core.base + 0x6819f70, end=core.base + 0x6819f70 + 4)

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

    print('--- registrations during cascade ---')
    regs.clear()
    core.write_u64(core.base + 0xa409b10, 0)
    r = core.call(A_CASCADE, timeout_s=600, max_insns=2_000_000_000)
    print(f'cascade err={r["error"]}; registered: {regs}')
    print(f'body-register calls so far: {body_regs}')

    regs.clear()
    core.write_u64(core.base + 0xa409b10, 0)
    r = core.call(A_SUBSYS_BOOT, w0=1, w1=1, x2=0, x3=1, w4=0,
                  timeout_s=300, max_insns=1_000_000_000)
    print(f'subsys err={r["error"]}; registered: {regs}')

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
    regs.clear()
    lookups.clear()
    for i in range(16):
        before, after, err, pc = world.step(timeout_s=240)
        replug()
        print(f'step {i}: cmd {before:#x} -> {after:#x} err={err}')
        print(f'  regs this step: {regs[-6:]}')
        print(f'  lookups this step: {lookups[-6:]}')
        regs.clear()
        lookups.clear()
    print(f'total body-register calls: {body_regs}')


if __name__ == '__main__':
    main()
