#!/usr/bin/env python3
"""M11g: locate the UC_ERR_EXCEPTION inside the subsys bootstrap 0x677dbf0."""
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

    last = {'blk': 0}
    trail = []

    def blk(uc, address, size, ud):
        last['blk'] = address - core.base
        if len(trail) > 40:
            trail.pop(0)
        trail.append(address - core.base)

    core.uc.hook_add(UC_HOOK_BLOCK, blk)

    def mem_err(uc, type_, address, size, value, ud):
        return False

    core.uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED
                     | UC_HOOK_MEM_FETCH_UNMAPPED | UC_HOOK_MEM_FETCH_PROT,
                     mem_err)

    def inv(uc, ud):
        print(f'INVALID INSN at {last["blk"]:#x}')
        return False

    try:
        core.uc.hook_add(UC_HOOK_INSN_INVALID, inv)
    except Exception as e:
        print('insn-invalid hook:', e)

    core.uc.mem_write(core.base + 0x68a0f30, struct.pack('<I', 0xD503201F))
    bs = world.bootstrap_game(run_init_array=True, max_init=15)
    r = core.call(0x6a09418, timeout_s=60)
    for fn in INIT_FNS:
        r = core.call(fn, timeout_s=120, max_insns=500_000_000)

    trail.clear()
    core.write_u64(core.base + 0xa409b10, 0)
    r = core.call(A_SUBSYS_BOOT, w0=1, w1=1, x2=0, x3=1, w4=0,
                  timeout_s=300, max_insns=1_000_000_000)
    print(f'subsys_boot: err={r["error"]} stopped_at={r.get("pc", 0) - core.base:#x}'
          if r.get('pc') else f'subsys_boot: err={r["error"]}')
    print('last blocks:')
    for t in trail[-25:]:
        print(f'  {t:#x}')
    # disassemble around the stop
    stop = r.get('pc', 0)
    if stop:
        from disasm import Bin
        b = Bin()
        print('--- around stop ---')
        for line in b.dump(stop - core.base - 0x20, 24):
            print(' ', line)


if __name__ == '__main__':
    main()
