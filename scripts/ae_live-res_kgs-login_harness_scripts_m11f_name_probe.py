#!/usr/bin/env python3
"""M11f: capture the NAME string of the failed lookup at 0x66d9a88."""
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


def main():
    world = SetupWorld(verbose=True)
    core = world.core
    inner = world.inner

    lookups = []
    names_ok = 0
    names_fail = []

    def at_lookup(uc, address, size, ud):
        # 0x66d9a88(x0=hub, x1=&str) — capture at ENTRY
        x1 = uc.reg_read(UC_ARM64_REG_X1)
        name = ''
        try:
            raw = core.safe_read(x1, 64)
            # std::string: if [x1]&1 -> heap; else inline at x1+1
            b0 = raw[0]
            if b0 & 1:
                plen = (b0 >> 1) & 0x3F
                if plen >= 0x3F:
                    hp = struct.unpack_from('<Q', raw, 8)[0]
                    hraw = core.safe_read(hp, 128)
                    name = hraw.split(b'\0')[0].decode('utf8', 'replace')
                else:
                    name = raw[1:1 + plen].decode('utf8', 'replace')
            else:
                name = raw[1:].split(b'\0')[0].decode('utf8', 'replace')
        except Exception:
            name = f'<unreadable x1={x1:#x}>'
        if len(lookups) < 60:
            lookups.append(name)

    core.uc.hook_add(UC_HOOK_CODE, at_lookup,
                     begin=core.base + 0x66d9a88, end=core.base + 0x66d9a88 + 4)

    def at_ret(uc, address, size, ud):
        # after 0x66d9a88 returns we can't easily hook; use the caller
        # site 0x68f38a8 (mov x23, x0) to see result
        x0 = uc.reg_read(UC_ARM64_REG_X0)
        if lookups:
            nm = lookups[-1]
            if x0:
                global names_ok
                names_ok += 1
            else:
                if len(names_fail) < 20:
                    names_fail.append(nm)

    core.uc.hook_add(UC_HOOK_CODE, at_ret,
                     begin=core.base + 0x68f38a8, end=core.base + 0x68f38a8 + 4)

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

    print('\n=== name lookups (in order) ===')
    for n in lookups:
        print(f'  {n!r}')
    print(f'\nfailed lookups: {names_fail}')


if __name__ == '__main__':
    main()
