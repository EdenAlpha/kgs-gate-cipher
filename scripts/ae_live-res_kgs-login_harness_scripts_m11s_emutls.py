#!/usr/bin/env python3
"""M11s: dump every __emutls_get_address call (x0 control struct + return)."""
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
A_CASCADE = 0x68a83b4


def main():
    world = SetupWorld(verbose=True)
    core = world.core
    inner = world.inner
    calls = []

    def at_emutls(uc, address, size, ud):
        x0 = uc.reg_read(UC_ARM64_REG_X0)
        lr = uc.reg_read(UC_ARM64_REG_LR)
        try:
            d = core.safe_read(x0, 24)
            u = struct.unpack('<6I', d)
        except Exception:
            u = None
        if len(calls) < 60:
            calls.append({'x0': x0, 'lr': lr - core.base, 'fields': u})

    core.uc.hook_add(UC_HOOK_CODE, at_emutls,
                     begin=core.base + 0x8b382e0,
                     end=core.base + 0x8b382e0 + 4)

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

    # also dump 0x9907d8 region after all relocations
    print('\n0x9907d8 after relocations:')
    d = core.safe_read(core.base + 0x9907d8, 24)
    print(' ', d.hex())
    print('  u32s:', [hex(x) for x in struct.unpack('<6I', d)])
    print('\nemutls calls seen:', len(calls))
    seen = {}
    for c in calls:
        k = c['x0']
        seen.setdefault(k, []).append(c)
    for k, v in list(seen.items())[:10]:
        c = v[0]
        print(f'  control={k:#x} (n={len(v)}) lr={c["lr"]:#x}')
        if c['fields']:
            print(f'    fields: {[hex(x) for x in c["fields"]]}')


if __name__ == '__main__':
    main()
