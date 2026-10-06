#!/usr/bin/env python3
"""M11e: identify the bogus-envelope arg1 at 0x66dccdc([x0], x1, x2, x3, w4).
The fault: envelope = [arg1+0x20] = 0xffffffff00000000 (packed metadata).
Dump arg1 contents + the 0x68f38e4 frame's x23 provenance."""
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
A_ENROLL = 0x66dccdc
A_CALLER = 0x68f38b0          # the function containing 0x68f38e4


def main():
    world = SetupWorld(verbose=True)
    core = world.core
    inner = world.inner

    enrolls = []

    def at_enroll(uc, address, size, ud):
        x0 = uc.reg_read(UC_ARM64_REG_X0)
        x1 = uc.reg_read(UC_ARM64_REG_X1)
        lr = uc.reg_read(UC_ARM64_REG_LR) - core.base
        rec = {'x0': x0, 'x1': x1, 'lr': lr}
        # dump arg1 contents
        fields = {}
        for off in (0, 8, 0x10, 0x18, 0x20, 0x28, 0x30):
            try:
                fields[f'+{off:#x}'] = core.safe_read_u64(x1 + off) if x1 else 0
            except Exception:
                fields[f'+{off:#x}'] = None
        rec['arg1'] = fields
        if len(enrolls) < 30:
            enrolls.append(rec)

    core.uc.hook_add(UC_HOOK_CODE, at_enroll,
                     begin=core.base + A_ENROLL, end=core.base + A_ENROLL + 4)

    armed = {'v': False}
    fault = {}

    def mem_err(uc, type_, address, size, value, ud):
        pc = uc.reg_read(UC_ARM64_REG_PC)
        if armed['v']:
            fault.setdefault('hits', []).append(
                {'type': int(type_), 'addr': address, 'pc': pc - core.base})
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
    r = core.call(A_SUBSYS_BOOT, w0=1, w1=1, x2=0, x3=1, w4=0,
                  timeout_s=300, max_insns=1_000_000_000)
    print(f'subsys_boot: err={r["error"]}')
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

    print('\n=== 0x66dccdc enroll calls (last 12) ===')
    for e in enrolls[-12:]:
        print(f"  this={e['x0']:#x} arg1={e['x1']:#x} lr={e['lr']:#x}")
        for k, v in e['arg1'].items():
            print(f'    arg1{k} = {v:#x}' if v is not None
                  else f'    arg1{k} = UNREADABLE')

    print('\n=== faults ===')
    for f in fault.get('hits', [])[:5]:
        print(f'  {f}')


if __name__ == '__main__':
    main()
