#!/usr/bin/env python3
"""M11h: catch the exact context of the UC_ERR_EXCEPTION at 0x8b34e7c
inside the subsys bootstrap. Logs every ldaxr target + registers at death."""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from unicorn import *
from unicorn.arm64_const import *
from m9_setup_seq import SetupWorld
from m10_realctor import A_INNER_CTOR

INIT_FNS = [0x68a7a5c, 0x66fb250, 0x66f3f3c]
A_SUBSYS_BOOT = 0x677dbf0


def main():
    world = SetupWorld(verbose=True)
    core = world.core
    inner = world.inner

    xs = {'log': []}

    def at_ldaxr(uc, address, size, ud):
        x1 = uc.reg_read(UC_ARM64_REG_X1)
        lr = uc.reg_read(UC_ARM64_REG_LR)
        xs['log'].append((x1, lr - core.base))
        if len(xs['log']) > 200:
            xs['log'].pop(0)

    core.uc.hook_add(UC_HOOK_CODE, at_ldaxr,
                     begin=core.base + 0x8b34e7c, end=core.base + 0x8b34e7c + 4)

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

    xs['log'].clear()
    core.write_u64(core.base + 0xa409b10, 0)
    r = core.call(A_SUBSYS_BOOT, w0=1, w1=1, x2=0, x3=1, w4=0,
                  timeout_s=300, max_insns=1_000_000_000)
    print(f'subsys_boot: err={r["error"]}')
    print(f'ldaxr count: {len(xs["log"])}')
    print('last 15 (x1, lr):')
    for x1, lr in xs['log'][-15:]:
        note = ''
        if not (0x10000000000 <= x1 < 0xC00000000000):
            note = '  <-- OUT OF RANGE'
        print(f'  x1={x1:#x} lr={lr:#x}{note}')
    # dump memory around the last valid x1
    if xs['log']:
        x1, lr = xs['log'][-1]
        if 0x10000000000 <= x1 < 0xC00000000000:
            try:
                data = core.safe_read(x1 - 0x20, 0x40)
                print(f'memory around last x1={x1:#x}:')
                for j in range(0, 0x40, 8):
                    v = struct.unpack_from('<Q', data, j)[0]
                    print(f'  {x1-0x20+j:#x}: {v:#x}')
            except Exception as e:
                print('dump failed:', e)


if __name__ == '__main__':
    main()
