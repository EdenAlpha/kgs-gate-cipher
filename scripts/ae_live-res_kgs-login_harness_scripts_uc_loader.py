#!/usr/bin/env python3
"""Minimal headless ELF loader + execution harness for eFootball libUE4.so (AArch64)
on Unicorn — Route B of the PeerLink strategy: execute ORIGINAL ARM64 gameplay code.

Features:
- maps all PT_LOADs at a chosen base (single RWX region, bss zero-filled)
- applies packed DT_ANDROID_RELA relocations (APS2, decoded by decode_packed.py)
- resolves GLOB_DAT / ABS64 / JUMP_SLOT: internal symbols -> base+st_value,
  undefined imports -> Python-emulated stubs (memcpy/memset/memmove/...)
- PLT calls: PLT stub -> GOT -> stub page (register branch, no BL range limit)
- TLS: TPIDR_EL0 page with bionic layout (stack canary at +0x28)
- FPCR=0 (RN, no FTZ) — device-default float32 semantics
- call(fn, args): clean call with RET trap, instruction counting, fault diagnostics
"""
import struct, sys, time, json, os
import numpy as np
from elftools.elf.elffile import ELFFile
from unicorn import *
from unicorn.arm64_const import *
import unicorn.arm64_const as A64C

AN = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'apk_lab', 'analysis')

# The APK lab was folded into the repo as
#   peerlink-efootball-disconnects/efootball-apk/native/lib/arm64-v8a/libUE4.so
# Prefer that copy; fall back to the old apk_lab path if it is still there.
_REPO_SO = os.path.join(
    r'C:\Users\Administrator\Documents\Default Project',
    'peerlink-efootball-disconnects', 'efootball-apk', 'native', 'lib',
    'arm64-v8a', 'libUE4.so')
_OLD_SO = os.path.normpath(os.path.join(
    os.path.dirname(os.path.abspath(__file__)), '..', 'apk_lab', 'libUE4.so'))
SO_PATH = _REPO_SO if os.path.exists(_REPO_SO) else _OLD_SO

# stub addresses (far from code; reached only via register branches)
STUB_BASE = 0x50000000000
STUB_SIZE = 0x400000        # 4 MB = 524,288 stubs (binary has 15,345 imports)
STACK_BASE = 0x60000000000
STACK_SIZE = 0x1000000        # 16 MB
TLS_BASE = 0x70000000000
RET_TRAP = 0x80000000000
HEAP_BASE = 0x90000000000
HEAP_SIZE = 0x10000000        # 256 MB for any allocation stubs


class EFootballCore:
    def __init__(self, so_path=SO_PATH, base=0x10000000000,
                 fpcr=0, verbose=True):
        self.path = so_path
        self.base = base
        self.verbose = verbose
        self.fpcr = fpcr
        self.f = open(so_path, 'rb')
        self.elf = ELFFile(self.f)
        self.loads = []
        for seg in self.elf.iter_segments():
            if seg['p_type'] == 'PT_LOAD':
                fl = seg['p_flags']
                self.loads.append(dict(vaddr=seg['p_vaddr'], memsz=seg['p_memsz'],
                                       filesz=seg['p_filesz'], offset=seg['p_offset'],
                                       perms=('r' if fl & 4 else '-') + ('w' if fl & 2 else '-') + ('x' if fl & 1 else '-')))
        self.uc = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
        self.import_calls = {}      # name -> count
        self.icount = 0
        self._log = []
        self._auto_pages = 0
        self.next_heap = HEAP_BASE
        self._prepare()

    # ------------------------------------------------------------------ setup
    def _prepare(self):
        uc = self.uc
        t0 = time.time()
        lo = min(l['vaddr'] for l in self.loads)
        hi = max(l['vaddr'] + l['memsz'] for l in self.loads)
        lo_a = lo & ~0xFFF
        hi_a = (hi + 0xFFF) & ~0xFFF
        self.map_lo, self.map_hi = lo_a, hi_a
        uc.mem_map(self.base + lo_a, hi_a - lo_a, UC_PROT_ALL)
        fdata = open(self.path, 'rb').read()
        for l in self.loads:
            uc.mem_write(self.base + l['vaddr'], fdata[l['offset']:l['offset'] + l['filesz']])
        self.fdata = fdata
        if self.verbose:
            print(f'[loader] mapped {hi_a - lo_a:,} bytes image in {time.time()-t0:.1f}s')

        # stub region / stack / tls / ret trap / heap
        # STUB_SIZE must hold one 8-byte stub per PLT import.  This binary has
        # 15,345 of them, so 0x10000 (8,192 stubs) was not enough and the
        # loader ran off the end of the mapping.
        uc.mem_map(STUB_BASE, STUB_SIZE, UC_PROT_ALL)
        uc.mem_write(STUB_BASE,
                     struct.pack('<I', 0x14000000) * (STUB_SIZE // 4))  # b . self
        uc.mem_map(STACK_BASE, STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE)
        uc.mem_map(TLS_BASE, 0x1000, UC_PROT_READ | UC_PROT_WRITE)
        uc.mem_map(RET_TRAP, 0x1000, UC_PROT_ALL)
        uc.mem_write(RET_TRAP, struct.pack('<I', 0xD65F03C0) * 1024)
        uc.mem_map(HEAP_BASE, HEAP_SIZE, UC_PROT_READ | UC_PROT_WRITE)

        # dynsym
        self.dynsym = self.elf.get_section_by_name('.dynsym')
        self.symtab = {}
        for i, s in enumerate(self.dynsym.iter_symbols()):
            if s.name:
                self.symtab[i] = (s.name, s['st_value'])

        # assign stub addresses to imports
        self.stub_of = {}      # stub addr -> (name)
        self.addr_of_stub = {}
        self.next_stub = STUB_BASE

        # hooks
        uc.hook_add(UC_HOOK_CODE, self._stub_hook, begin=STUB_BASE,
                    end=STUB_BASE + STUB_SIZE)
        uc.hook_add(UC_HOOK_MEM_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED, self._mem_fault)
        uc.hook_add(UC_HOOK_INSN_INVALID, self._inv_insn)

        # registers
        uc.reg_write(UC_ARM64_REG_TPIDR_EL0, TLS_BASE)
        uc.reg_write(UC_ARM64_REG_FPCR, self.fpcr)
        uc.reg_write(UC_ARM64_REG_FPSR, 0)
        self.sp0 = STACK_BASE + STACK_SIZE - 0x10000

        self._apply_relocs()
        if self.verbose:
            print(f'[loader] relocation pass done in {time.time()-t0:.1f}s')

    def _get_stub(self, name):
        if name in self.addr_of_stub:
            return self.addr_of_stub[name]
        a = self.next_stub
        self.next_stub += 8
        self.stub_of[a] = name
        self.addr_of_stub[name] = a
        return a

    # ------------------------------------------------------------- relocations
    def _apply_relocs(self):
        uc = self.uc
        B = self.base
        pr = np.load(f'{AN}/packed_relocs.npz')
        off, sym, rtype, addend = pr['offset'], pr['sym'], pr['rtype'], pr['addend']

        # 1) RELATIVE: write base+addend, chunked over consecutive offsets
        rel = rtype == 1027
        ro = off[rel]
        ra = addend[rel]
        order = np.argsort(ro)
        ro, ra = ro[order], ra[order]
        n = len(ro)
        i = 0
        writes = 0
        while i < n:
            j = i
            while j + 1 < n and ro[j + 1] == ro[j] + 8:
                j += 1
            run_vals = (ra[i:j + 1] + B).astype('<u8')
            uc.mem_write(B + int(ro[i]), run_vals.tobytes())
            writes += 1
            i = j + 1
        if self.verbose:
            print(f'[loader] RELATIVE relocs: {n:,} in {writes:,} chunk writes')

        # 2) symbol relocs (ABS64=257, GLOB_DAT=1025)
        symrel = ~rel
        resolved = 0
        stubbed = {}
        for o, s, t, a in zip(off[symrel].tolist(), sym[symrel].tolist(),
                              rtype[symrel].tolist(), addend[symrel].tolist()):
            name, val = self.symtab.get(s, (f'sym{s}', 0))
            if val:
                value = B + val + (a if t == 257 else 0)
            else:
                sa = self._get_stub(name)
                value = sa + (a if t == 257 and False else 0)
                stubbed[name] = stubbed.get(name, 0) + 1
            uc.mem_write(B + o, struct.pack('<Q', value))
            resolved += 1
        if self.verbose:
            print(f'[loader] symbol relocs: {resolved:,} (stubbed imports: {len(stubbed)})')

        # 3) JUMP_SLOT (.rela.plt)
        rela = self.elf.get_section_by_name('.rela.plt')
        linksec = self.elf.get_section(rela['sh_link'])
        njs = 0
        for r in rela.iter_relocations():
            o = r['r_offset']
            si = r['r_info_sym']
            s = linksec.get_symbol(si)
            name = s.name if s and s.name else f'sym{si}'
            val = s['st_value'] if s else 0
            if val:
                value = B + val
            else:
                value = self._get_stub(name)
            uc.mem_write(B + o, struct.pack('<Q', value))
            njs += 1
        if self.verbose:
            print(f'[loader] JUMP_SLOT relocs: {njs:,}')

    # ----------------------------------------------------------------- stubs
    def _stub_hook(self, uc, addr, size, ud):
        name = self.stub_of.get(addr, f'unknown_{addr:#x}')
        self.import_calls[name] = self.import_calls.get(name, 0) + 1
        lr = uc.reg_read(UC_ARM64_REG_LR)
        x0 = uc.reg_read(UC_ARM64_REG_X0)
        x1 = uc.reg_read(UC_ARM64_REG_X1)
        x2 = uc.reg_read(UC_ARM64_REG_X2)
        ret = 0
        if name in ('memcpy', 'memmove'):
            n = x2
            if n:
                data = bytes(uc.mem_read(x1, n))
                uc.mem_write(x0, data)
            ret = x0
        elif name == 'memset':
            n = x2
            if n:
                uc.mem_write(x0, bytes([x1 & 0xFF]) * n)
            ret = x0
        elif name == 'malloc':
            ret = self._heap_alloc(x0)
        elif name == 'calloc':
            ret = self._heap_alloc(x0 * x1) if x0 and x1 else 0
            if ret:
                uc.mem_write(ret, b'\0' * (x0 * x1))
        elif name == 'free':
            ret = 0
        elif name in ('strlen',):
            data = bytes(uc.mem_read(x0, 4096))
            ret = data.find(b'\0')
            ret = 0 if ret < 0 else ret
        elif name == '__stack_chk_fail':
            self._log.append(f'STACK GUARD MISMATCH at lr={lr:#x}')
            uc.emu_stop()
            return
        elif name == 'abort':
            self._log.append(f'abort() called from lr={lr:#x}')
            uc.emu_stop()
            return
        else:
            if len(self._log) < 200:
                self._log.append(f'unhandled import: {name} (lr={lr:#x}) -> returning 0')
        uc.reg_write(UC_ARM64_REG_X0, ret & 0xFFFFFFFFFFFFFFFF)
        uc.reg_write(UC_ARM64_REG_PC, lr)

    def _heap_alloc(self, n):
        a = self.next_heap
        self.next_heap = (self.next_heap + max(n, 16) + 0xFF) & ~0xFF
        return a

    def _mem_fault(self, uc, access, address, size, value, ud):
        pc = uc.reg_read(UC_ARM64_REG_PC)
        is_fetch = access in (UC_MEM_FETCH_UNMAPPED, UC_MEM_FETCH_PROT)
        # demand-zero: unmapped data access outside the image -> map a zero page and retry
        if not is_fetch and address < self.base and self._auto_pages < 256:
            page = address & ~0xFFF
            try:
                uc.mem_map(page, 0x1000, UC_PROT_READ | UC_PROT_WRITE)
                self._auto_pages += 1
                self._log.append(f'auto-zero page {page:#x} (access={access} pc={pc:#x})')
                return True
            except UcError:
                pass
        self._log.append(f'MEM FAULT access={access} addr={address:#x} size={size} pc={pc:#x}')
        return False

    def _inv_insn(self, uc, ud):
        pc = uc.reg_read(UC_ARM64_REG_PC)
        self._log.append(f'INVALID INSN at pc={pc:#x}')
        return False

    # ------------------------------------------------------------------- call
    def fabricate_global(self, bss_vaddr, size=0x20000):
        """Point a .bss global pointer at a zeroed fabricated context object."""
        ctx = self.alloc(size, b'\0' * min(size, 0x20000) if size <= 0x20000 else None, name=f'ctx_{bss_vaddr:#x}')
        if size > 0x20000:
            pass  # alloc already zeroed
        self.uc.mem_write(self.base + bss_vaddr, struct.pack('<Q', ctx))
        if self.verbose:
            print(f'[loader] fabricated global {bss_vaddr:#x} -> {ctx:#x} ({size:#x} zeros)')
        return ctx

    def alloc(self, size, init=None, name=''):
        """Allocate guest memory in a scratch arena."""
        if not hasattr(self, 'scratch'):
            self.scratch = 0xA0000000000
            uc_addr = self.scratch
            self.uc.mem_map(self.scratch, 0x10000000, UC_PROT_READ | UC_PROT_WRITE)
            self.scratch += 0x1000
        a = self.scratch
        self.scratch = (self.scratch + size + 0xFF) & ~0xFF
        if init is not None:
            self.uc.mem_write(a, init)
        return a

    def call(self, fn, w0=0, w1=0, x2=0, x3=0, s0=0.0, w4=0, w5=0,
             x0=None, x1=None, s1=0.0, s2=0.0, timeout_s=30, max_insns=50_000_000,
             x6=0, x7=0, stack=None):
        """Call an original function by vaddr. Floats in s0/s1/s2, ints/ptrs elsewhere.

        x6/x7 give the full 8 integer argument registers, and `stack` (a list of
        ints) writes AAPCS stack arguments starting at the caller's SP -- needed
        for variadic/thrunk entry points like the POST sub-request sender.
        """
        uc = self.uc
        uc.reg_write(UC_ARM64_REG_X0, x0 if x0 is not None else w0)
        uc.reg_write(UC_ARM64_REG_X1, x1 if x1 is not None else w1)
        uc.reg_write(UC_ARM64_REG_X2, x2)
        uc.reg_write(UC_ARM64_REG_X3, x3)
        uc.reg_write(UC_ARM64_REG_X4, w4)
        uc.reg_write(UC_ARM64_REG_X5, w5)
        uc.reg_write(UC_ARM64_REG_X6, x6)
        uc.reg_write(UC_ARM64_REG_X7, x7)
        uc.reg_write(UC_ARM64_REG_SP, self.sp0)
        if stack:
            for i, v in enumerate(stack):
                self.write_u64(self.sp0 + i * 8, v)
        # x8..x28 are caller-saved scratch; clear them, but NOT x6/x7 -- those
        # are real AAPCS argument registers just set above.
        for i in range(8, 29):
            uc.reg_write(getattr(A64C, f'UC_ARM64_REG_X{i}'), 0)
        uc.reg_write(UC_ARM64_REG_X29, self.sp0 - 0x1000)  # sane frame ptr for leaf frame users
        self._write_float(UC_ARM64_REG_S0, s0)
        self._write_float(UC_ARM64_REG_S1, s1)
        self._write_float(UC_ARM64_REG_S2, s2)
        uc.reg_write(UC_ARM64_REG_LR, RET_TRAP)
        self.icount_start = self.icount
        try:
            uc.emu_start(self.base + fn, RET_TRAP, timeout=timeout_s * 1_000_000, count=max_insns)
            err = None
        except UcError as e:
            err = e
        pc = uc.reg_read(UC_ARM64_REG_PC)
        x0v = uc.reg_read(UC_ARM64_REG_X0)
        return {'error': str(err) if err else None, 'pc': pc, 'x0': x0v, 'lr': uc.reg_read(UC_ARM64_REG_LR)}

    def _write_float(self, reg, value):
        bits = struct.unpack('<I', struct.pack('<f', value))[0]
        self.uc.reg_write(reg, bits)

    def read_f32(self, addr, off=0):
        return struct.unpack('<f', bytes(self.uc.mem_read(addr + off, 4)))[0]

    def write_f32(self, addr, off, value):
        self.uc.mem_write(addr + off, struct.pack('<f', value))

    def read_u32(self, addr, off=0):
        return struct.unpack('<I', bytes(self.uc.mem_read(addr + off, 4)))[0]

    def dump_logs(self, n=40):
        for line in self._log[:n]:
            print('  [log]', line)


if __name__ == '__main__':
    core = EFootballCore()
    print('[selftest] calling timestep provider 0x6813eb8 (expects 27.0)')
    r = core.call(0x6813eb8)
    print('[selftest] result:', r, 'logs:', core._log[:5])
    # read s0 (raw 32-bit view)
    bits = core.uc.reg_read(UC_ARM64_REG_S0)
    print('[selftest] s0 =', struct.unpack('<f', struct.pack('<I', bits & 0xFFFFFFFF))[0])
