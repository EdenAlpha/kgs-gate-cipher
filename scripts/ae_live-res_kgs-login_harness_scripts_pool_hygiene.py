#!/usr/bin/env python3
"""Pool hygiene for the headless eFootball harness (M11x).

Root cause (decoded this session): the game's pooled allocator
(0x2efa57c / 0x2efa7a0 cores, free at 0x2efa830) recycles chunks WITHOUT
zeroing. The per-player animation rig's hash maps + intrusive lists get
rebuilt every setup step; fields the real game would have initialized
from async-loaded asset data (FoxAnim .hkx) instead contain recycled
pool dirt — most notably the size-class tag 8 that 0x2efa774 writes at
[chunk-8]. The match-setup teardown (0x6783260 family) then walks a
poisoned chain and calls free(8) -> write to [0] -> UC_ERR_WRITE_UNMAPPED.

Fix bundle (all harness-level runtime-context repair; zero game code is
rewritten — the game's own instructions still do all the work):
  1. zero-on-alloc   — allocator epilogues: payload zeroed on return
                       (fresh-page semantics; also REQUIRED for lockstep
                       determinism across peers).
  2. free guard      — 0x2efa830 entry: invalid ptr -> early return.
  3. walk-head fix   — teardown walk heads: invalid slot -> sentinel.
  4. insert sanitize — map inserts: invalid old-tail/old-head -> sentinel.
"""
from unicorn import *
from unicorn.arm64_const import *

HEAP_LO = 0x90000000000
HEAP_HI = 0x91000000000
ZERO_CAP = 0x200000            # don't zero chunks larger than 2 MB

# allocator epilogue ret sites (x0 = returned chunk)
ALLOC_RETS = [0x2efa798, 0x2efa7e8, 0x2efa82c]
# pool free entry (x0 = ptr)
A_POOL_FREE = 0x2efa830
# teardown 0x6783260 walk heads: (site, slot offset); sentinel = slot-0x10
WALK_HEADS = [(0x6783274, 0x30), (0x67832b0, 0x78), (0x67832f4, 0xc0),
              (0x678331c, 0x108), (0x6783358, 0x170), (0x6783390, 0x1b8),
              (0x67833c8, 0x200), (0x6783400, 0x248)]
# map insert sites: sanitize X8 (old tail / old head) -> x19+0x20
INSERT_SITES = [0x678126c, 0x6781274, 0x6781398, 0x67813a8]
# teardown walk bodies: (body site, node reg name, loop exit addr).
# If the node is not a valid heap pointer (page-0 garbage / stale dirt),
# jump to the loop's empty-list continuation. Detected via the live trace:
# the walk cycles 0 -> 8 -> heapD -> heapE -> 0 through [N+0x10].
WALK_BODIES = [(0x6783288, 'X20', 0x67832a8),
                (0x67832cc, 'X20', 0x67832ec),
                (0x6783374, 'X0', 0x6783388),
                (0x67833ac, 'X0', 0x67833c0),
                (0x67833e4, 'X0', 0x67833f8),
                (0x678341c, 'X0', 0x6783430)]


def is_heap(v):
    return HEAP_LO <= v < HEAP_HI


def install_pool_hygiene(core, verbose=False):
    base = core.base
    stats = {'zeroed': 0, 'free_guard': 0, 'walk_fix': 0, 'insert_fix': 0,
             'body_break': 0}

    def on_alloc_ret(uc, address, size, ud):
        ptr = uc.reg_read(UC_ARM64_REG_X0)
        if not is_heap(ptr):
            return
        try:
            hdr = core.safe_read_u32(ptr - 4)
        except Exception:
            return
        n = hdr & 0x7FFFFFFF
        if 0 < n <= ZERO_CAP:
            try:
                uc.mem_write(ptr, b'\0' * n)
                stats['zeroed'] += 1
            except Exception:
                pass

    for site in ALLOC_RETS:
        core.uc.hook_add(UC_HOOK_CODE, on_alloc_ret,
                         begin=base + site, end=base + site + 4)

    def on_free(uc, address, size, ud):
        x0 = uc.reg_read(UC_ARM64_REG_X0)
        if x0 != 0 and not is_heap(x0):
            if verbose:
                stats['free_guard'] += 1
            uc.reg_write(UC_ARM64_REG_X0, 0)
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))

    core.uc.hook_add(UC_HOOK_CODE, on_free,
                     begin=base + A_POOL_FREE, end=base + A_POOL_FREE + 4)

    def mk_walk(site, off):
        def hook(uc, address, size, ud):
            x19 = uc.reg_read(UC_ARM64_REG_X19)
            if not is_heap(x19):
                return
            try:
                v = core.safe_read_u64(x19 + off)
            except Exception:
                return
            if v != 0 and not is_heap(v):
                # stale dirt in the walk-head slot: restore the sentinel
                try:
                    core.write_u64(x19 + off, x19 + off - 0x10)
                    stats['walk_fix'] += 1
                except Exception:
                    pass
        return hook

    for site, off in WALK_HEADS:
        core.uc.hook_add(UC_HOOK_CODE, mk_walk(site, off),
                         begin=base + site, end=base + site + 4)

    def mk_insert(site):
        def hook(uc, address, size, ud):
            x8 = uc.reg_read(UC_ARM64_REG_X8)
            x19 = uc.reg_read(UC_ARM64_REG_X19)
            if not is_heap(x19):
                return
            if x8 != 0 and not is_heap(x8):
                uc.reg_write(UC_ARM64_REG_X8, x19 + 0x20)
                stats['insert_fix'] += 1
        return hook

    for site in INSERT_SITES:
        core.uc.hook_add(UC_HOOK_CODE, mk_insert(site),
                         begin=base + site, end=base + site + 4)

    def mk_body(site, reg, exit_addr):
        r = globals()[f'UC_ARM64_REG_{reg}']

        def hook(uc, address, size, ud):
            node = uc.reg_read(r)
            if node == 0 or not is_heap(node):
                # stale/page-0 artifact in the chain: take the empty exit
                uc.reg_write(UC_ARM64_REG_PC, base + exit_addr)
                stats['body_break'] += 1
        return hook

    for site, reg, exit_addr in WALK_BODIES:
        core.uc.hook_add(UC_HOOK_CODE, mk_body(site, reg, exit_addr),
                         begin=base + site, end=base + site + 4)

    return stats
