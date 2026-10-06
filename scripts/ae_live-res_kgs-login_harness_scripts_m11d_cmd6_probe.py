#!/usr/bin/env python3
"""M11d: probe the cmd-6 fault: refcount inc on envelope = -0x48.
Dumps: every refcount-op caller, the fault registers, the source slot."""
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


def main():
    world = SetupWorld(verbose=True)
    core = world.core
    inner = world.inner

    refops = []
    bad_refs = []

    def ref_hook(name):
        def h(uc, address, size, ud):
            x0 = uc.reg_read(UC_ARM64_REG_X0)
            lr = uc.reg_read(UC_ARM64_REG_LR)
            rec = {'fn': name, 'x0': x0, 'lr': lr - core.base}
            if len(refops) < 400:
                refops.append(rec)
            if x0 > 0xFFFFFFFFFFFF0000 or 0 < x0 < 0x10000:
                if len(bad_refs) < 20:
                    bad_refs.append(rec)
        return h

    for a, n in ((0x66ec9b4, 'inc'), (0x66ec9d0, 'inc2'), (0x66ec9ec, 'dec')):
        core.uc.hook_add(UC_HOOK_CODE, ref_hook(n),
                         begin=core.base + a, end=core.base + a + 4)

    fault_reg = {}
    armed = {'v': False}

    def mem_err(uc, type_, address, size, value, ud):
        pc = uc.reg_read(UC_ARM64_REG_PC)
        if armed['v'] and not fault_reg:
            regs = {}
            for i in range(29):
                regs[f'x{i}'] = uc.reg_read(
                    globals()[f'UC_ARM64_REG_X{i}'])
            fault_reg.update(regs)
            fault_reg['pc'] = pc - core.base
            fault_reg['addr'] = address
            fault_reg['lr'] = uc.reg_read(UC_ARM64_REG_LR) - core.base
            fault_reg['sp'] = uc.reg_read(UC_ARM64_REG_SP)
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
    bad_refs.clear()
    refops.clear()
    for i in range(20):
        before, after, err, pc = world.step(timeout_s=240)
        replug()
        print(f'step {i}: cmd {before:#x} -> {after:#x} err={err}')
        if i >= 12:
            armed['v'] = True
        if fault_reg:
            break

    print('\n=== bad refops (bogus envelope ptrs) ===')
    for b in bad_refs[:20]:
        print(f"  {b['fn']} x0={b['x0']:#x} lr={b['lr']:#x}")

    print('\n=== fault registers ===')
    for k, v in fault_reg.items():
        print(f'  {k} = {v:#x}' if isinstance(v, int) else f'  {k} = {v}')

    # stack walk: dump return addresses on the stack
    if fault_reg:
        sp = fault_reg['sp']
        try:
            stack = core.safe_read(sp - 0x40, 0x400)
            print('\n=== stack qwords that look like text addrs ===')
            for j in range(0, len(stack), 8):
                v = struct.unpack_from('<Q', stack, j)[0]
                if core.base < v < core.base + 0xA0000000:
                    print(f'  sp{sp - 0x40 + j - sp:+#x}: {v - core.base:#x}')
        except Exception as e:
            print('stack dump failed:', e)


if __name__ == '__main__':
    main()
