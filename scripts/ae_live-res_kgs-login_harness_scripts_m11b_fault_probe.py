#!/usr/bin/env python3
"""M11b: full-context probe of the cmd-5 envelope fault.

Fault: blr x8 @ 0x66f0a40, x8 = [[x25]+0x18] = heap ptr (0x9001457110).
x25 = envelope popped (atomic CAS @ 0x66eca24) from slot [this+0xd0]+w6*8.

This probe dumps:
  - entry of 0x66f09c0: this(x0), w6, lr(caller)  [first 40 calls]
  - the slot addr + value at 0x66f0a0c
  - x25, [x25], [[x25]], [[x25]+0x18] at 0x66f0a34
  - stores into the slot region (who wrote the envelope into the slot)
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from unicorn import *
from unicorn.arm64_const import *
from m9_setup_seq import SetupWorld, slots22
from m10_realctor import A_INNER_CTOR

INIT_FNS = [0x68a7a5c, 0x66fb250, 0x66f3f3c]

A_FAULTFN = 0x66f09c0
A_POP = 0x66eca24
A_SEND = 0x68ccc00
A_ENVCTOR = 0x66eca94


def main():
    world = SetupWorld(verbose=True)
    core = world.core
    inner = world.inner

    calls = []
    pops = []
    sends = []
    envctors = []
    slot_writes = {}
    fault_ctx = {}

    def entry_faultfn(uc, address, size, ud):
        if len(calls) < 60:
            calls.append({
                'this': uc.reg_read(UC_ARM64_REG_X0),
                'w6': uc.reg_read(UC_ARM64_REG_X6) & 0xFFFFFFFF,
                'lr': uc.reg_read(UC_ARM64_REG_LR),
                'x1': uc.reg_read(UC_ARM64_REG_X1),
            })

    core.uc.hook_add(UC_HOOK_CODE, entry_faultfn,
                     begin=core.base + A_FAULTFN, end=core.base + A_FAULTFN + 4)

    def at_slot(uc, address, size, ud):
        # 0x66f0a0c: ldr x8,[x0] — x0 = slot addr
        x0 = uc.reg_read(UC_ARM64_REG_X0)
        if len(pops) < 30:
            pops.append({'slot': x0, 'val': core.safe_read_u64(x0)})

    core.uc.hook_add(UC_HOOK_CODE, at_slot,
                     begin=core.base + 0x66f0a0c, end=core.base + 0x66f0a0c + 4)

    def at_env(uc, address, size, ud):
        # 0x66f0a34: ldr x8,[x25] — x25 = envelope
        x25 = uc.reg_read(UC_ARM64_REG_X25)
        v0 = core.safe_read_u64(x25)
        vt18 = core.safe_read_u64(v0 + 0x18) if v0 else None
        if len(fault_ctx) < 6 and vt18 and not (core.base <= vt18 < core.base + 0xA0000000):
            fault_ctx['x25'] = x25
            fault_ctx['x25_v0'] = v0
            fault_ctx['vt18'] = vt18
            # dump the envelope bytes
            try:
                fault_ctx['env_bytes'] = core.safe_read(x25, 0x40).hex()
            except Exception:
                pass
            try:
                fault_ctx['v0_bytes'] = core.safe_read(v0, 0x40).hex()
            except Exception:
                pass

    core.uc.hook_add(UC_HOOK_CODE, at_env,
                     begin=core.base + 0x66f0a34, end=core.base + 0x66f0a34 + 4)

    def at_send(uc, address, size, ud):
        if len(sends) < 40:
            sends.append({'x0': uc.reg_read(UC_ARM64_REG_X0),
                          'x1': uc.reg_read(UC_ARM64_REG_X1),
                          'x2': uc.reg_read(UC_ARM64_REG_X2),
                          'lr': uc.reg_read(UC_ARM64_REG_LR) - core.base})

    core.uc.hook_add(UC_HOOK_CODE, at_send,
                     begin=core.base + A_SEND, end=core.base + A_SEND + 4)

    def at_envctor(uc, address, size, ud):
        if len(envctors) < 40:
            envctors.append({'x0': uc.reg_read(UC_ARM64_REG_X0),
                             'x1': uc.reg_read(UC_ARM64_REG_X1),
                             'lr': uc.reg_read(UC_ARM64_REG_LR) - core.base})

    core.uc.hook_add(UC_HOOK_CODE, at_envctor,
                     begin=core.base + A_ENVCTOR, end=core.base + A_ENVCTOR + 4)

    def mem_err(uc, type_, address, size, value, ud):
        pc = uc.reg_read(UC_ARM64_REG_PC)
        print(f'  FAULT type={type_} addr={address:#x} '
              f'pc={pc - core.base:#x}')
        return False

    core.uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED
                     | UC_HOOK_MEM_FETCH_UNMAPPED | UC_HOOK_MEM_FETCH_PROT,
                     mem_err)

    core.uc.mem_write(core.base + 0x68a0f30, struct.pack('<I', 0xD503201F))
    bs = world.bootstrap_game(run_init_array=True, max_init=15)
    r = core.call(0x6a09418, timeout_s=60)
    for fn in INIT_FNS:
        r = core.call(fn, timeout_s=120, max_insns=500_000_000)
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
    for i in range(12):
        before, after, err, pc = world.step(timeout_s=240)
        replug()
        print(f'step {i}: cmd {before:#x} -> {after:#x} err={err}')

    print('\n=== 0x66f09c0 calls (this/w6/lr) ===')
    for c in calls[:40]:
        print(f"  this={c['this']:#x} w6={c['w6']} lr={c['lr']-core.base:#x}")

    print('\n=== slots at 0x66f0a0c ===')
    for p in pops[:20]:
        print(f"  slot={p['slot']:#x} val={p['val']:#x}")

    print('\n=== Send 0x68ccc00 calls ===')
    for s in sends[:20]:
        print(f"  x0={s['x0']:#x} x1={s['x1']:#x} x2={s['x2']:#x} "
              f"lr={s['lr']:#x}")

    print('\n=== envelope ctor 0x66eca94 calls ===')
    for e in envctors[:20]:
        print(f"  x0={e['x0']:#x} x1={e['x1']:#x} lr={e['lr']:#x}")

    print('\n=== fault envelope context ===')
    for k, v in fault_ctx.items():
        print(f'  {k} = {v}')


if __name__ == '__main__':
    main()
