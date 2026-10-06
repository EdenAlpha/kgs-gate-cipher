#!/usr/bin/env python3
"""M11m: dump the body node + payload; try the empty-container approach
(zero the entry count so the game's own parser loop skips)."""
import json
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
A_LOOKUP = 0x66d9a88


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
    core.write_u64(core.base + 0xa409b10, 0)
    r = core.call(A_CASCADE, timeout_s=600, max_insns=2_000_000_000)
    core.write_u64(core.base + 0xa409b10, 0)
    r = core.call(A_SUBSYS_BOOT, w0=1, w1=1, x2=0, x3=1, w4=0,
                  timeout_s=300, max_insns=1_000_000_000)
    r = core.call(A_HUB, timeout_s=60)
    hub = core.safe_read_u64(core.base + 0xa4097f8)
    s_body = mk_str(core, 'body')
    r = core.call(A_REGISTER, x0=hub, x1=s_body,
                  x2=mk_str(core, 'cpk_dat/common/anime/FoxAnim/Body/'),
                  x3=mk_str(core, 'Projekt.hkx'),
                  timeout_s=300, max_insns=500_000_000)
    print(f'register("body"): err={r["error"]}')
    r = core.call(A_LOOKUP, x0=hub, x1=s_body, timeout_s=60)
    node = r['x0']
    print(f'body node: {node:#x}')

    # dump the node's first 0xC0 bytes
    data = core.safe_read(node, 0xC0)
    print('node dump:')
    for j in range(0, 0xC0, 8):
        v = struct.unpack_from('<Q', data, j)[0]
        tag = ''
        if j == 0 and core.base < v < core.base + 0xA0000000:
            tag = f'  <- vtable {v-core.base:#x}'
        elif j == 0x80:
            tag = '  <- the payload ptr parsed by 0x66dd440'
        print(f'  +{j:#04x}: {v:#x}{tag}')

    # what's at node+0x80?
    payload = core.safe_read_u64(node + 0x80)
    print(f'\n[node+0x80] = {payload:#x}')
    if payload:
        try:
            pdata = core.safe_read(payload, 0x40)
            print('payload dump:')
            for j in range(0, 0x40, 4):
                v = struct.unpack_from('<I', pdata, j)[0]
                print(f'  +{j:#04x}: {v:#x}')
        except Exception as e:
            print('payload unreadable:', e)


if __name__ == '__main__':
    main()
