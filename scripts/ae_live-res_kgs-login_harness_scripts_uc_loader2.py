#!/usr/bin/env python3
"""PeerLink enhanced loader v2 — EFootballCore plus the Milestone-2 machinery.

Adds to the Session-A loader (uc_loader.py):
- full fault coverage (UC_HOOK_MEM_PROT / FETCH_PROT — the pc=0 crash class)
- GOT-hijack API (plt_map.json driven): redirect internal-symbol PLT slots
  (operator new/delete — UE FMemory overrides) to Python-emulated stubs
- real import stub suite: zeroing malloc/calloc, posix_memalign (writes ptr),
  pthread TLS keys/mutex, vsnprintf (real formatting), realloc, str*, mmap...
- fault-tolerant guest reads in stub context (safe_read)
- function neutralization (patch RET) for engine-plumbing registrations
- code watchers (per-address hooks with register capture)
- call(fn, ...) with x8 (sret) support and per-call fault log isolation
"""
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from uc_loader import (EFootballCore, STUB_BASE, RET_TRAP, HEAP_BASE,
                       HEAP_SIZE, STACK_BASE, STACK_SIZE, TLS_BASE)
from unicorn import *
from unicorn.arm64_const import *
import unicorn.arm64_const as A64C

AN = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'apk_lab', 'analysis')

# The APK lab now lives in the repo; prefer it, fall back to the old path.
_REPO_SO = os.path.join(
    r'C:\Users\Administrator\Documents\Default Project',
    'peerlink-efootball-disconnects', 'efootball-apk', 'native', 'lib',
    'arm64-v8a', 'libUE4.so')
_OLD_SO = os.path.normpath(os.path.join(
    os.path.dirname(os.path.abspath(__file__)), '..', 'apk_lab', 'libUE4.so'))
SO_PATH = _REPO_SO if os.path.exists(_REPO_SO) else _OLD_SO


def RET_INSN():
    return struct.pack('<I', 0xD65F03C0)


class EFootballCoreV2(EFootballCore):
    def __init__(self, so_path=SO_PATH,
                 base=0x10000000000, fpcr=0, verbose=True):
        super().__init__(so_path=so_path, base=base, fpcr=fpcr, verbose=verbose)
        self.watchers = []
        self._emutls_buf = {}
        self._add_prot_hooks()
        self._install_rich_stubs()
        if self.verbose:
            print('[loader2] PROT hooks + rich stubs installed')

    # ---------------------------------------------------------- fault hooks
    def _add_prot_hooks(self):
        uc = self.uc
        # cover fetch-protection faults (pc landing in non-exec pages, e.g. pc=0)
        uc.hook_add(UC_HOOK_MEM_PROT | UC_HOOK_MEM_FETCH_PROT, self._prot_fault)

    def _prot_fault(self, uc, access, address, size, value, ud):
        pc = uc.reg_read(UC_ARM64_REG_PC)
        is_fetch = access in (UC_MEM_FETCH_UNMAPPED, UC_MEM_FETCH_PROT)
        if is_fetch:
            self._log.append(f'FETCH FAULT access={access} addr={address:#x} pc={pc:#x}')
            return False
        # data access to a protected page: try demand-zero outside the image
        if address < self.base and self._auto_pages < 512:
            page = address & ~0xFFF
            try:
                uc.mem_map(page, 0x1000, UC_PROT_READ | UC_PROT_WRITE)
                self._auto_pages += 1
                self._log.append(f'auto-zero page {page:#x} (prot access={access} pc={pc:#x})')
                return True
            except UcError:
                pass
        self._log.append(f'PROT FAULT access={access} addr={address:#x} size={size} pc={pc:#x}')
        return False

    # ------------------------------------------------------------ safe read
    def safe_read(self, addr, n):
        try:
            return bytes(self.uc.mem_read(addr, n))
        except UcError:
            return b'\0' * n

    def safe_read_u64(self, addr):
        return struct.unpack('<Q', self.safe_read(addr, 8))[0]

    def safe_read_u32(self, addr):
        return struct.unpack('<I', self.safe_read(addr, 4))[0]

    def write_u32(self, addr, v):
        self.uc.mem_write(addr, struct.pack('<I', v & 0xFFFFFFFF))

    def write_u64(self, addr, v):
        self.uc.mem_write(addr, struct.pack('<Q', v & 0xFFFFFFFFFFFFFFFF))

    def write_u16(self, addr, v):
        self.uc.mem_write(addr, struct.pack('<H', v & 0xFFFF))

    def write_u8(self, addr, v):
        self.uc.mem_write(addr, bytes([v & 0xFF]))

    def write_f32(self, addr, v):
        self.uc.mem_write(addr, struct.pack('<f', v))

    def read_f32(self, addr):
        return struct.unpack('<f', self.safe_read(addr, 4))[0]

    # ------------------------------------------------------------ GOT hijack
    def hijack_plt(self, symbol, handler_name=None):
        """Write a Python-emulated stub address into the GOT slot used by the
        PLT entry for `symbol` (works for internal symbols too, e.g. _Znwm)."""
        plt = json.load(open(f'{AN}/plt_map.json'))
        hits = [(int(k, 16), v) for k, v in plt.items() if v['sym'] == symbol]
        if not hits:
            raise KeyError(f'PLT entry for {symbol} not found')
        stub = self._get_stub(handler_name or symbol)
        for plt_addr, info in hits:
            got = self.base + info['got']
            self.write_u64(got, stub)
            if self.verbose:
                print(f'[loader2] hijacked {symbol}: PLT {plt_addr:#x} GOT {got:#x} '
                      f'(internal={info.get("internal")}) -> stub {stub:#x}')
        return stub

    def patch_got(self, vaddr, value):
        self.write_u64(self.base + vaddr, value)

    # ------------------------------------------------------------ stub suite
    def _install_rich_stubs(self):
        """Pre-assign stub addresses for the rich import set (dispatch by addr)."""
        for name in ('_Znwm_h', '_Znam_h', '_ZdlPv_h', '_ZdaPv_h',
                     'posix_memalign_h', 'aligned_alloc_h',
                     'vsnprintf_h', 'sprintf_h', 'snprintf_h',
                     'pthread_getspecific_h', 'pthread_setspecific_h',
                     'pthread_key_create_h', 'pthread_key_delete_h',
                     'pthread_mutex_lock_h', 'pthread_mutex_unlock_h',
                     'pthread_mutex_init_h', 'pthread_once_h', 'pthread_self_h',
                     'realloc_h', 'memchr_h', 'strchr_h', 'strcmp_h',
                     'strncmp_h', 'strcpy_h', 'strncpy_h', 'strdup_h',
                     '__android_log_print_h', 'gettimeofday_h', 'clock_gettime_h',
                     'mmap_h', 'mprotect_h', '__errno_h'):
            self._get_stub(name)
        # ---- platform patch (DROP-class): thread-contention wait removal ----
        # std::ndk1::timed_mutex::lock at 0x823bec8 waits while [mtx+0x58]
        # (owner/waiter flag) is set. Headless = no other threads, so the
        # flag can never be legitimately set; garbage in partially-
        # constructed embedded mutexes spins it forever. Same precedent as
        # the v4 camera cond_wait neutralization.
        # 0x823bef4: ldrb w8, [x19, #0x58]  ->  movz w8, #0  (always fast path)
        self.uc.mem_write(self.base + 0x823bef4, struct.pack('<I', 0x52800008))
        # ---- platform patch (DROP-class): __cxa_guard single-thread semantics
        # bionic: [0]=done, [1]=in-progress(owner) + same-thread abort.
        # Headless: keep the in-progress marker (prevents ctor re-entry
        # recursion) but drop the abort (recursive access proceeds with
        # partial data instead of dying). A ctor must reach release to be
        # marked done; abort clears the marker (retryable).
        acq = struct.pack('<12I',
                          0x39400009,          # 0:  ldrb w9, [x0]       (done?)
                          0x34000069,          # 4:  cbz w9, +12 -> 16
                          0x2A1F03E0,          # 8:  mov w0, wzr
                          0xD65F03C0,          # 12: ret
                          0x39400409,          # 16: ldrb w9, [x0, #1]   (in progress?)
                          0x34000069,          # 20: cbz w9, +12 -> 32
                          0x2A1F03E0,          # 24: mov w0, wzr
                          0xD65F03C0,          # 28: ret
                          0x52800029,          # 32: mov w9, #1
                          0x39000409,          # 36: strb w9, [x0, #1]   (mark in-progress)
                          0x52800020,          # 40: mov w0, #1
                          0xD65F03C0)          # 44: ret
        self.uc.mem_write(self.base + 0x8207b84, acq)
        # __cxa_guard_release: done=1, in-progress=0
        self.uc.mem_write(self.base + 0x8207cc8,
                          struct.pack('<4I', 0x52800029, 0x39000009,
                                      0x3900041F, 0xD65F03C0))
        # __cxa_guard_abort: clear in-progress
        self.uc.mem_write(self.base + 0x8207d70,
                          struct.pack('<2I', 0x3900041F, 0xD65F03C0))

    # dispatch: override the parent hook to implement the rich set
    def _stub_hook(self, uc, addr, size, ud):
        name = self.stub_of.get(addr, f'unknown_{addr:#x}')
        # normalize: rich-stub names carry a _h suffix; GOT-relocated calls
        # arrive with the plain symbol name. Strip the suffix so BOTH hit
        # the rich handlers (posix_memalign, pthread_once, mmap, ...).
        if name.endswith('_h'):
            name = name[:-2]
        self.import_calls[name] = self.import_calls.get(name, 0) + 1
        lr = uc.reg_read(UC_ARM64_REG_LR)
        x0 = uc.reg_read(UC_ARM64_REG_X0)
        x1 = uc.reg_read(UC_ARM64_REG_X1)
        x2 = uc.reg_read(UC_ARM64_REG_X2)
        x3 = uc.reg_read(UC_ARM64_REG_X3)
        x4 = uc.reg_read(UC_ARM64_REG_X4)
        x5 = uc.reg_read(UC_ARM64_REG_X5)
        ret = 0
        if name in ('memcpy', 'memmove'):
            n = x2
            if n:
                uc.mem_write(x0, self.safe_read(x1, n))
            ret = x0
        elif name == 'memset':
            n = x2
            if n:
                uc.mem_write(x0, bytes([x1 & 0xFF]) * n)
            ret = x0
        elif name in ('malloc', '_Znwm', '_Znam'):
            n = x0 if name == 'malloc' else x0
            ret = self._heap_alloc_zero(n)
        elif name in ('calloc', 'symcalloc'):
            ret = self._heap_alloc_zero(x0 * x1) if x0 and x1 else 0
        elif name in ('realloc',):
            n = x1
            old = self.safe_read(x0, self._alloc_size.get(x0, 0)) if x0 else b''
            ret = self._heap_alloc_zero(max(n, 0))
            if n:
                uc.mem_write(ret, old[:n])
        elif name == '__emutls_get_address':
            # GNU/Android emutls: control = {u32 size, u32 align(?), ...}
            # per-thread buffer: allocate once per control, zeroed.
            if x0 not in self._emutls_buf:
                try:
                    size = self.safe_read_u32(x0)
                except Exception:
                    size = 8
                if size == 0 or size > 0x10000000:
                    size = 8
                self._emutls_buf[x0] = self._heap_alloc_zero(
                    (size + 0xFF) & ~0xFF)
            ret = self._emutls_buf[x0]
        elif name in ('free', 'symfree', '_ZdlPv', '_ZdaPv', 'cfree'):
            ret = 0
        elif name in ('posix_memalign',):
            # int posix_memalign(void **memptr, size_t alignment, size_t size)
            p = self._heap_alloc_zero(x2, align=x1)
            self.write_u64(x0, p)
            ret = 0
        elif name in ('aligned_alloc',):
            ret = self._heap_alloc_zero(x1, align=x0)
        elif name in ('strlen',):
            data = self.safe_read(x0, 4096)
            idx = data.find(b'\0')
            ret = idx if idx >= 0 else 4096
        elif name in ('strcmp',):
            a = self.safe_read(x0, 256).split(b'\0')[0]
            b = self.safe_read(x1, 256).split(b'\0')[0]
            ret = 0 if a == b else (1 if a > b else 0xFFFFFFFFFFFFFFFF)
        elif name in ('strncmp',):
            a = self.safe_read(x0, x2).split(b'\0')[0]
            b = self.safe_read(x1, x2).split(b'\0')[0]
            ret = 0 if a == b else 1
        elif name in ('strcpy', 'strncpy'):
            src = self.safe_read(x1, 4096).split(b'\0')[0]
            if name == 'strncpy':
                src = src[:x2]
            uc.mem_write(x0, src + b'\0')
            ret = x0
        elif name in ('strdup',):
            src = self.safe_read(x0, 4096).split(b'\0')[0] + b'\0'
            ret = self._heap_alloc_zero(len(src))
            uc.mem_write(ret, src)
        elif name in ('memchr', 'strchr', 'strrchr', 'strchrnul'):
            if name == 'memchr':
                data = self.safe_read(x0, x2) if x2 else b''
                idx = data.find(bytes([x1 & 0xFF]))
            else:
                data = self.safe_read(x0, 4096)
                end = data.find(b'\0')
                # strchr/strrchr scan the whole string INCLUDING its NUL
                hay = (data[:end + 1] if end >= 0 else data)
                n = bytes([x1 & 0xFF])
                idx = hay.rfind(n) if name == 'strrchr' else hay.find(n)
                if idx < 0 and name == 'strchrnul':
                    idx = hay.find(b'\0')
            ret = (x0 + idx) if idx >= 0 else 0
        elif name in ('strcspn', 'strspn'):
            s = self.safe_read(x0, 4096)
            end = s.find(b'\0')
            s = s[:end] if end >= 0 else s
            charset = self.safe_read(x1, 256).split(b'\0')[0]
            idx = -1
            for i, ch in enumerate(s):
                hit = ch in charset
                if name == 'strcspn' and hit:
                    idx = i
                    break
                if name == 'strspn' and not hit:
                    idx = i
                    break
            ret = idx if idx >= 0 else len(s)
        elif name in ('strpbrk', 'strstr'):
            s = self.safe_read(x0, 4096)
            end = s.find(b'\0')
            s = s[:end] if end >= 0 else s
            if name == 'strpbrk':
                charset = self.safe_read(x1, 256).split(b'\0')[0]
                idx = -1
                for i, ch in enumerate(s):
                    if ch in charset:
                        idx = i
                        break
            else:
                needle = self.safe_read(x1, 4096).split(b'\0')[0]
                idx = s.find(needle)
            ret = (x0 + idx) if idx >= 0 else 0
        elif name in ('memcmp', 'strcasecmp', 'strncasecmp'):
            if name == 'memcmp':
                a = self.safe_read(x0, x2) if x2 else b''
                b = self.safe_read(x1, x2) if x2 else b''
                n = min(len(a), len(b))
                d = 0
                for i in range(n):
                    if a[i] != b[i]:
                        ca, cb = (a[i], b[i]) if name == 'memcmp' else (
                            a[i:i + 1].lower(), b[i:i + 1].lower())
                        d = (ca - cb) if isinstance(ca, int) else (
                            1 if ca > cb else -1)
                        break
                ret = d & 0xFFFFFFFFFFFFFFFF
            else:
                a = self.safe_read(x0, 4096).split(b'\0')[0].lower()
                b = self.safe_read(x1, 4096).split(b'\0')[0].lower()
                if name == 'strncasecmp':
                    a, b = a[:x2], b[:x2]
                ret = 0 if a == b else (1 if a > b else 0xFFFFFFFFFFFFFFFF)
        elif name in ('atoi', 'atol', 'atoll', 'strtol', 'strtoul'):
            txt = self.safe_read(x0, 64).split(b'\0')[0].strip()
            base = 10 if name in ('atoi', 'atol', 'atoll') else int(x2)
            consumed = 0
            val = 0
            try:
                body = txt
                sign = 1
                if body[:1] in (b'+', b'-'):
                    sign = -1 if body[:1] == b'-' else 1
                    body = body[1:]
                if base == 16 and body[:2].lower() == b'0x':
                    body = body[2:]
                    consumed += 2
                digits = (b'0123456789abcdef' if base == 16
                          else b'0123456789abcdef' if base == 0
                          else b'0123456789')
                if base == 0:
                    base = 16 if body[:2].lower() == b'0x' else 10
                    if base == 16:
                        body = body[2:]
                        consumed += 2
                    digits = b'0123456789abcdef'
                out = 0
                k = 0
                while k < len(body):
                    c = body[k:k + 1].lower()
                    if c not in digits or digits.find(c) >= base:
                        break
                    out = out * base + digits.find(c)
                    k += 1
                consumed += k
                val = sign * out
            except Exception:
                val = 0
            if x1:
                try:
                    self.write_u64(x1, x0 + consumed)
                except Exception:
                    pass
            if name == 'strtoul':
                ret = int(val) & 0xFFFFFFFFFFFFFFFF
            else:
                ret = int(val) & 0xFFFFFFFFFFFFFFFF
        # ---------------------------------------------------- FORTIFY _chk
        elif name in ('__strlen_chk',):
            # bionic: __strlen_chk(s, s_bufsize) -> strlen(s)
            # (a returning-0 stub makes inet_ntop() think the buffer is empty
            #  and every address formatting attempt fails)
            s = self.safe_read(x0, 1 << 16)
            end = s.find(b'\0')
            ret = (end if end >= 0 else len(s)) & 0xFFFFFFFFFFFFFFFF
        elif name in ('__strchr_chk', '__strrchr_chk'):
            data = self.safe_read(x0, 4096)
            end = data.find(b'\0')
            hay = data[:end + 1] if end >= 0 else data
            n = bytes([x1 & 0xFF])
            idx = hay.rfind(n) if name.endswith('rchr_chk') else hay.find(n)
            ret = (x0 + idx) if idx >= 0 else 0
        elif name in ('__strcpy_chk', '__strncpy_chk', '__strcat_chk',
                      '__strncat_chk', '__memcpy_chk', '__memmove_chk',
                      '__memset_chk'):
            if name in ('__memcpy_chk', '__memmove_chk'):
                if x2:
                    self.uc.mem_write(x0, bytes(self.safe_read(x1, x2)))
                ret = x0
            elif name == '__memset_chk':
                if x2:
                    self.uc.mem_write(x0, bytes([x1 & 0xFF]) * x2)
                ret = x0
            else:
                dst = x0
                if name in ('__strcat_chk', '__strncat_chk'):
                    cur = self.safe_read(dst, 4096)
                    p = cur.find(b'\0')
                    dst = dst + (p if p >= 0 else len(cur))
                    n = x2 if name.endswith('ncat_chk') else 4096
                    s = self.safe_read(x1, min(n, 4096))
                    e = s.find(b'\0')
                    if e >= 0:
                        s = s[:e + 1] if name.endswith('cat_chk') and \
                            not name.endswith('ncat_chk') else s[:e]
                    self.uc.mem_write(dst, s)
                else:
                    if name == '__strncpy_chk':
                        n = x2
                        s = self.safe_read(x1, min(max(n, 1), 1 << 16))
                        e = s.find(b'\0')
                        if e >= 0 and e + 1 <= n:
                            s = (s[:e + 1]).ljust(n, b'\0')
                        else:
                            s = s[:n]
                    else:
                        s = self.safe_read(x1, 4096)
                        e = s.find(b'\0')
                        s = s[:e + 1] if e >= 0 else s
                    if s:
                        self.uc.mem_write(dst, s)
                ret = x0
        # ---------------------------------------------------- misc libc
        elif name in ('usleep',):
            # The GateInfo task spins on curl_multi_perform and calls
            # usleep(1050605) between polls.  A stub returning 0 would let it
            # burn every poll budget before the response ever arrives, so
            # really wait -- just capped, exactly like nanosleep below.
            import time as _t
            _t.sleep(min(max(int(x0), 0) / 1e6, 0.05))
            ret = 0
        elif name in ('time',):
            import time as _t
            ret = int(_t.time()) & 0xFFFFFFFFFFFFFFFF
        elif name in ('getenv',):
            key = self.safe_read(x0, 256).split(b'\0')[0].decode('latin1')
            val = os.environ.get(key)
            if val is None:
                ret = 0
            else:
                b = val.encode('latin1', 'replace') + b'\0'
                ret = self.alloc(len(b), b, name='getenv')
        elif name in ('sysconf',):
            # Linux _SC_*: PAGE_SIZE=60, CLK_TCK=4, OPEN_MAX=102,
            # NPROCESSORS_ONLN=84, PHYS_PAGES=100, AVPHYS_PAGES=101
            ret = {60: 4096, 8: 4096, 4: 100, 102: 1024, 84: 4, 100: 1 << 16,
                   101: 1 << 16, 2: 1 << 20, 3: 1 << 20}.get(x0, 1 << 16)
        elif name in ('sysinfo',):
            # struct sysinfo { uptime, loads[3], totalram, freeram,
            #   sharedram, bufferram, totalswap, freeswap, procs, pad,
            #   totalhigh, freehigh, mem_unit, _f[] }
            import time as _t
            ram = 8 << 30
            vals = [int(_t.time()) % 100000, 1 << 16, 1 << 16, 1 << 16,
                    ram, ram - (512 << 20), 0, 0, 0, 0, 64, 0,
                    0, 0, 0, 1]
            if x0:
                blob = struct.pack('<16Q', *[v & ((1 << 64) - 1)
                                             for v in vals[:16]])
                self.uc.mem_write(x0, blob)
                self.write_u32(x0 + 80, 300)   # procs
                self.write_u32(x0 + 104, 1)    # mem_unit
            ret = 0
        elif name in ('__stack_chk_fail',):
            # No stack protector canary service: report and continue.
            self._log.append('stack canary hit -> ignored')
            ret = 0
        elif name in ('vsnprintf', 'snprintf'):
            ret = self._emu_snprintf(uc, name, x0, x1, x2)
        elif name in ('__vsnprintf_chk',):
            # The GateInfo request builder (0x7d17d24) funnels every message
            # through this.  Returning 0 made it write an empty body, so
            # Konami answered 400 to a request with nothing in it.
            ret = self._emu_vsnprintf_chk(uc, x0, min(x1, x3), x4, x5)
        elif name in ('sprintf',):
            ret = self._emu_snprintf(uc, name, x0, 1 << 30, x1)
        elif name in ('pthread_getspecific', 'pthread_getspecific'):
            ret = self._tls_get(x0)
        elif name in ('pthread_setspecific', 'pthread_setspecific'):
            self._tls_set(x0, x1)
            ret = 0
        elif name in ('pthread_key_create',):
            # write a fresh key id
            self._key_seq = getattr(self, '_key_seq', 16) + 1
            self.write_u32(x0, self._key_seq)
            ret = 0
        elif name in ('pthread_key_delete', 'pthread_mutex_lock',
                      'pthread_mutex_unlock', 'pthread_mutex_init',
                      'pthread_mutex_lock', 'pthread_mutex_unlock',
                      'pthread_mutex_init', 'pthread_key_delete'):
            ret = 0
        elif name in ('pthread_cond_signal', 'pthread_cond_broadcast',
                      'pthread_cond_init', 'pthread_cond_destroy',
                      'pthread_cond_wait', 'pthread_cond_timedwait'):
            ret = 0
        elif name in ('pthread_once', 'pthread_once'):
            # REAL semantics: run the init routine exactly once.
            # The old zero-return stub made TLS init retry ~292k times
            # (once-control never set) -> the 80M-insn spin in cmd 0.
            if x0 and self.safe_read_u32(x0) == 0:
                self.write_u32(x0, 1)          # set FIRST (recursion-safe)
                if x1:
                    # jump into the init routine; ret -> lr (original caller)
                    uc.reg_write(UC_ARM64_REG_X0, 0)
                    uc.reg_write(UC_ARM64_REG_PC, x1)
                    return
            ret = 0
        elif name in ('pthread_self',):
            ret = 0x70000011
        elif name in ('__errno',):
            ret = self._errno_addr()
        elif name in ('gettimeofday', 'clock_gettime'):
            # zero tv structs (deterministic time)
            if x1:
                uc.mem_write(x1, b'\0' * 16)
            ret = 0
        elif name in ('__android_log_print',):
            ret = 0
        elif name in ('mmap',):
            # REAL mmap: map fresh zero pages in a dedicated arena.
            # (The game's memory pools mmap/munmap for growth; the old
            # heap-fake stub corrupted pool bookkeeping.)
            length = x1
            if length:
                if not hasattr(self, '_mmap_next'):
                    self._mmap_next = 0xA90000000000
                a = (self._mmap_next + 0xFFFF) & ~0xFFFF
                need = (length + 0xFFFF) & ~0xFFFF
                try:
                    self.uc.mem_map(a, need, UC_PROT_ALL)
                except UcError:
                    pass
                self._mmap_next = a + need
                ret = a
            else:
                ret = 0
        elif name in ('munmap',):
            # REAL munmap: unmap the page range (best effort).
            if x0 and x1:
                start = x0 & ~0xFFF
                span = (x1 + (x0 - start) + 0xFFF) & ~0xFFF
                try:
                    self.uc.mem_unmap(start, span)
                except UcError:
                    self._log.append(f'munmap({x0:#x},{x1:#x}) failed (ignored)')
            ret = 0
        elif name in ('sysconf',):
            # REAL platform values (ARM64 Android). _SC_PAGESIZE=39 -> 4096;
            # the game's memory pools use it as the per-block overhead.
            if x0 == 39:            # _SC_PAGESIZE
                ret = 4096
            elif x0 == 40:          # _SC_NPROCESSORS_ONLN
                ret = 4
            elif x0 in (74, 118):   # _SC_NPROCESSORS_CONF / _SC_PAGESIZE alt
                ret = 4 if x0 == 74 else 4096
            else:
                ret = 4096
        elif name == '__stack_chk_fail':
            self._log.append(f'STACK GUARD MISMATCH at lr={lr:#x}')
            uc.emu_stop()
            return
        elif name in ('abort',):
            self._log.append(f'abort() called from lr={lr:#x}')
            uc.emu_stop()
            return
        elif name in ('open', 'open64', '__open_2', '__open64_2'):
            # curl opens /dev/urandom directly for TLS entropy
            path = self._read_cstr(uc, x0)
            import os as _os
            if 'urandom' in path or 'random' in path:
                data = _os.urandom(65536)
            elif 'r' in (self._read_cstr(uc, x1) or 'r'):
                try:
                    with open(path, 'rb') as fh:
                        data = fh.read(1 << 20)
                except Exception:
                    data = b''
            else:
                data = b''
            ret = self._alloc_file(data, path, "")
        elif name in ('read', '__read_chk'):
            # read(fd, buf, n): x0=fd x1=buf x2=n
            data = self._read_file(x0, x2)
            if data and x1:
                uc.mem_write(x1, data)
            ret = len(data)
        elif name in ('close', '__close_chk'):
            self._close_file(x0)
            ret = 0
        elif name in ('lseek', 'lseek64', '__lseek_chk'):
            self._seek_file(x0, x1, x2)
            ret = self._tell_file(x0)
        elif name in ('fopen', 'fopen64'):
            # libcurl needs entropy (/dev/urandom) and a writable scratch
            # (cookie jar) to initialise its TLS and state.  We back both
            # with real host bytes so the game's own curl comes up cleanly.
            path = self._read_cstr(uc, x0)
            mode = self._read_cstr(uc, x1)
            import os as _os
            if 'urandom' in path or 'random' in path:
                data = _os.urandom(4096)
            elif 'r' in mode and not path.startswith('/dev/'):
                try:
                    with open(path, 'rb') as fh:
                        data = fh.read(1 << 20)
                except Exception:
                    data = b''
            else:
                data = b''          # writable scratch: empty file
            ret = self._alloc_file(data, path, mode)
        elif name in ('fread', '__fread_chk'):
            # fread(buf, size, count, stream): x0=buf x1=size x2=count x3=stream
            total = x1 * x2
            data = self._read_file(x3, total)
            if data and x0:
                uc.mem_write(x0, data)
            ret = len(data) // x1 if x1 else 0
        elif name in ('fwrite', '__fwrite_chk'):
            # fwrite(ptr, size, count, stream): x0=ptr x1=size x2=count x3=stream
            self._write_file(x3, bytes(uc.mem_read(x0, x1 * x2)) if x0 else b"")
            ret = x2
        elif name in ('fclose',):
            self._close_file(x0)
            ret = 0
        elif name in ('fseek',):
            self._seek_file(x0, x1, x2)
            ret = 0
        elif name in ('ftell', 'ftello', 'ftello64'):
            ret = self._tell_file(x0)
        elif name in ('feof',):
            ret = 1 if self._eof_file(x0) else 0
        elif name in ('ferror',):
            ret = 0
        elif name in ('gettimeofday', 'clock_gettime', 'timespec_get'):
            import time as _t
            now = _t.time()
            sec, usec = int(now), int((now - int(now)) * 1_000_000)
            if name == 'gettimeofday':
                if x0:
                    uc.mem_write(x0, struct.pack('<qq', sec, usec))
            else:
                if x1:
                    uc.mem_write(x1, struct.pack('<qq', sec, usec))
            ret = 0
        elif name in ('time',):
            import time as _t
            ret = int(_t.time())
            if x0:
                uc.mem_write(x0, struct.pack('<q', ret))
        elif name in ('getentropy', '__getentropy_chk'):
            # THE entropy source for curl's RNG on bionic.  Unimplemented it
            # returns 0 and leaves the buffer empty -> curl aborts TLS with
            # "Insufficient randomness".  Real host randomness, as requested.
            import os as _os
            n = min(x1, 256)                  # getentropy caps at 256
            if x0 and n:
                uc.mem_write(x0, _os.urandom(n))
            ret = 0
        elif name in ('syscall', '__syscall'):
            # raw syscall indirection: getrandom(278) is the one that matters.
            # Note the args shift: x0=nr x1=arg1 x2=arg2 ...
            nr = x0
            if nr == 278:                     # getrandom(buf, n, flags)
                import os as _os
                n = min(x2, 4096)
                if x1 and n:
                    uc.mem_write(x1, _os.urandom(n))
                ret = n
            elif nr == 222:                   # mmap(addr, len, prot, ...)
                ret = self._heap_alloc_zero(max(x2, 1))
            else:
                ret = 0
        elif name in ('rand',):
            import random as _r
            ret = _r.getrandbits(31)
        elif name in ('srand',):
            ret = 0
        elif name in ('stat', 'stat64', 'lstat', 'lstat64', '__stat_chk',
                      'fstat', 'fstat64'):
            # VIRTUAL filesystem first: /dev/urandom and friends must stat OK,
            # otherwise curl concludes there is no entropy source and aborts
            # with "Insufficient randomness".
            path = self._read_cstr(uc, x0) if 'stat' in name[:4] else \
                self._file_table() and self._fname.get(x0, ('',))[0] or ''
            if path in self._fname_values() or path.startswith('/dev/'):
                n = self._virt_size(path)
                if x1:
                    uc.mem_write(x1, self._stat_struct(n))
                ret = 0
            else:
                import os as _os
                try:
                    st = _os.stat(path)
                    if x1:
                        uc.mem_write(x1, self._stat_struct(st.st_size))
                    ret = 0
                except Exception:
                    ret = -1
        elif name in ('fgets', '__fgets_chk'):
            # fgets(buf, n, stream): x0=buf x1=n x2=stream
            data = self._gets_file(x2, max(1, min(x1, 4096)))
            if data and x0:
                uc.mem_write(x0, data)
            ret = x0 if data else 0
        elif name in ('opendir',):
            import os as _os
            path = self._read_cstr(uc, x0)
            try:
                names = _os.listdir(path)
            except Exception:
                names = []
            ret = self._alloc_dir(names)
        elif name in ('readdir', 'readdir64'):
            ret = self._read_dir(x0)
        elif name in ('closedir',):
            ret = 0
        elif name in ('rewinddir',):
            self._rewind_dir(x0)
            ret = 0
        elif name in ('__errno', '__errno_location'):
            ret = self._errno_slot()
        elif 'random_device' in name or 'RandomDevice' in name:
            # libc++ std::random_device: the entropy source for the game's
            # TLS.  ctors take the device path, operator() returns 32 bits,
            # the dtor is a no-op.  Returning real randomness unblocks
            # curl's "Insufficient randomness" TLS failure.
            if name.endswith('clEv') or name.endswith('clEmm'):
                import os as _os
                ret = int.from_bytes(_os.urandom(4), 'little')
            else:
                ret = x0 if not name.endswith('D1Ev') else 0
        elif name.startswith('sym') or name in ('malloc_usable_size',):
            # curl's private allocator family (symmalloc/symcalloc/symrealloc/
            # symstrdup/symfree/...).  Anything that looks like an allocator
            # gets real behaviour; the rest are no-ops.
            low = name.lower()
            if 'calloc' in low:
                ret = self._heap_alloc_zero(x0 * x1) if x0 and x1 else 0
            elif 'realloc' in low:
                n = x1
                ret = self._heap_alloc_zero(max(n, 0))
                if n and x0:
                    old = self._alloc_size.get(x0, 0)
                    if old:
                        uc.mem_write(ret, bytes(uc.mem_read(x0, min(old, n))))
            elif 'strndup' in low:
                n = min(x1, 4096)
                raw = bytes(uc.mem_read(x0, n)).split(b"\0")[0]
                ret = self._heap_alloc_zero(len(raw) + 1)
                uc.mem_write(ret, raw + b"\0")
            elif 'strdup' in low:
                raw = bytes(uc.mem_read(x0, 4096)).split(b"\0")[0]
                ret = self._heap_alloc_zero(len(raw) + 1)
                uc.mem_write(ret, raw + b"\0")
            elif 'memalign' in low or 'align' in low:
                ret = self._heap_alloc_zero(max(x1, 1))
            elif 'free' in low:
                ret = 0
            elif 'malloc' in low:
                ret = self._heap_alloc_zero(x0)
            elif 'usable' in low:
                ret = self._alloc_size.get(x0, 0)
            else:
                ret = 0
        else:
            if len(self._log) < 400:
                self._log.append(f'unhandled import: {name} (lr={lr:#x}) -> returning 0')
        uc.reg_write(UC_ARM64_REG_X0, ret & 0xFFFFFFFFFFFFFFFF)
        uc.reg_write(UC_ARM64_REG_PC, lr)

    def _read_cstr(self, uc, addr, limit=4096):
        try:
            return bytes(uc.mem_read(addr, limit)).split(b"\0")[0].decode(
                "utf-8", "replace")
        except Exception:
            return ""

    # ------------------------------------------------------ stdio emulation
    def _file_table(self):
        if not hasattr(self, "_files"):
            self._files = {}          # handle -> bytearray
            self._fpos = {}
            self._fname = {}
            self._dirs = {}
            self._next_fh = 0x900000000000
            self._next_dir = 0x910000000000
        return self._files

    def _virt_size(self, path):
        """Size for a virtual device node."""
        return 65536 if 'urandom' in path or 'random' in path else 0

    def _stat_struct(self, size: int) -> bytes:
        """Linux aarch64 `struct stat` (128 bytes): st_ino@0, st_mode@16,
        st_size@48.  Enough for curl's existence + size checks."""
        b = bytearray(128)
        struct.pack_into("<Q", b, 0, 1)                  # st_ino
        struct.pack_into("<I", b, 16, 0x81A4)            # st_mode (regular 0644)
        struct.pack_into("<q", b, 48, size)              # st_size
        return bytes(b)

    def _fname_values(self):
        self._file_table()
        return {v[0] for v in self._fname.values()}

    def _gets_file(self, fh, n):
        """fgets(buf, n, stream): read up to n-1 bytes, stop after '\\n'."""
        files = self._file_table()
        if fh not in files:
            return b""
        pos = self._fpos[fh]
        buf = files[fh]
        if pos >= len(buf):
            return b""
        end = min(pos + n - 1, len(buf))
        chunk = bytes(buf[pos:end])
        nl = chunk.find(b"\n")
        if nl >= 0:
            chunk = chunk[:nl + 1]
        self._fpos[fh] = pos + len(chunk)
        return chunk + b"\0"

    def _alloc_dir(self, names):
        self._file_table()
        h = self._next_dir
        self._next_dir += 0x1000
        self._dirs[h] = (list(names), 0)
        return h

    def _read_dir(self, h):
        self._file_table()
        if h not in self._dirs:
            return 0
        names, i = self._dirs[h]
        if i >= len(names):
            return 0
        self._dirs[h] = (names, i + 1)
        return self._alloc_file(names[i].encode() + b"\0", "dirent", "r")

    def _rewind_dir(self, h):
        self._file_table()
        if h in self._dirs:
            names, _ = self._dirs[h]
            self._dirs[h] = (names, 0)

    def _alloc_file(self, data, path, mode):
        files = self._file_table()
        fh = self._next_fh
        self._next_fh += 0x1000
        files[fh] = bytearray(data)
        self._fpos[fh] = 0
        self._fname[fh] = (path, mode)
        return fh

    def _read_file(self, fh, n):
        files = self._file_table()
        if fh not in files:
            return b""
        pos = self._fpos[fh]
        blob = files[fh][pos:pos + n]
        self._fpos[fh] = pos + len(blob)
        return bytes(blob)

    def _write_file(self, fh, data):
        files = self._file_table()
        if fh not in files:
            return 0
        pos = self._fpos[fh]
        buf = files[fh]
        if len(buf) < pos:
            buf.extend(b"\0" * (pos - len(buf)))
        buf[pos:pos + len(data)] = data
        self._fpos[fh] = pos + len(data)
        return len(data)

    def _seek_file(self, fh, off, whence):
        files = self._file_table()
        if fh not in files:
            return
        if whence == 0:
            self._fpos[fh] = off
        elif whence == 1:
            self._fpos[fh] += off
        elif whence == 2:
            self._fpos[fh] = len(files[fh]) + off

    def _tell_file(self, fh):
        return self._fpos.get(fh, 0)

    def _eof_file(self, fh):
        files = self._file_table()
        return self._fpos.get(fh, 0) >= len(files.get(fh, b""))

    def _close_file(self, fh):
        files = self._file_table()
        files.pop(fh, None)

    def _errno_slot(self):
        if not hasattr(self, "_errno_addr"):
            self._errno_addr = self._heap_alloc(4)
            self.uc.mem_write(self._errno_addr, struct.pack("<I", 0))
        return self._errno_addr

    def _heap_alloc_zero(self, n, align=16):
        """Zeroing allocator (UE object payloads must be zeroed)."""
        if n == 0:
            n = 16
        a = self.next_heap
        if align and align > 16:
            a = (a + align - 1) & ~(align - 1)
        self.next_heap = (a + max(n, 16) + 0xFF) & ~0xFF
        self._alloc_size = getattr(self, '_alloc_size', {})
        self._alloc_size[a] = n
        try:
            self.uc.mem_write(a, b'\0' * max(n, 16))
        except UcError:
            # grow heap if needed
            need = self.next_heap - HEAP_BASE
            if need > HEAP_SIZE:
                self.uc.mem_map(HEAP_BASE + HEAP_SIZE, 0x10000000)
            self.uc.mem_write(a, b'\0' * max(n, 16))
        return a

    def _tls_get(self, key):
        if not hasattr(self, '_tls_vals'):
            self._tls_vals = {}
        return self._tls_vals.get(key, 0)

    def _tls_set(self, key, val):
        if not hasattr(self, '_tls_vals'):
            self._tls_vals = {}
        self._tls_vals[key] = val

    def _errno_addr(self):
        if not hasattr(self, '_errno_a'):
            self._errno_a = self.alloc(64, b'\0' * 64, name='errno')
        return self._errno_a

    # ---------------------------------------------------------- snprintf emu
    def _emu_snprintf(self, uc, kind, out, size, fmt):
        """Minimal but REAL snprintf: supports %s %d %02d %u %x %f %c %p %%.
        Varargs: ints in x2..x7 then stack (for sprintf: x1..x6)."""
        base_arg = 2 if kind != 'sprintf_h' else 1
        regs = [uc.reg_read(getattr(A64C, f'UC_ARM64_REG_X{i}'))
                for i in range(base_arg, 8)]
        # stack varargs
        sp = uc.reg_read(UC_ARM64_REG_SP)
        stack = []
        try:
            stack_raw = bytes(uc.mem_read(sp, 64))
            for i in range(8):
                (v,) = struct.unpack_from('<Q', stack_raw, i * 8)
                stack.append(v)
        except UcError:
            stack = [0] * 8
        varargs = regs + stack
        fmt_s = self.safe_read(fmt, 512).split(b'\0')[0].decode('utf-8', 'replace')
        out_b = b''
        ai = 0

        def nextarg():
            nonlocal ai
            v = varargs[ai] if ai < len(varargs) else 0
            ai += 1
            return v

        i = 0
        while i < len(fmt_s):
            c = fmt_s[i]
            if c != '%':
                out_b += c.encode()
                i += 1
                continue
            j = i + 1
            spec = '%'
            while j < len(fmt_s) and fmt_s[j] not in 'diufcxXspge%':
                spec += fmt_s[j]
                j += 1
            if j >= len(fmt_s):
                break
            conv = fmt_s[j]
            spec += conv
            try:
                if conv == '%':
                    out_b += b'%'
                elif conv == 's':
                    p = nextarg()
                    out_b += self.safe_read(p, 256).split(b'\0')[0]
                elif conv in 'di':
                    v = nextarg()
                    sv = v if v < (1 << 63) else v - (1 << 64)
                    out_b += (spec % sv).encode()
                elif conv in 'uxX':
                    out_b += (spec % nextarg()).encode()
                elif conv in 'feEgG':
                    # floats come via SIMD; approximate from int regs is wrong,
                    # but the ctor only uses %d/%s — treat as 0.0 fallback
                    raw = nextarg()
                    out_b += (spec % 0.0).encode()
                elif conv == 'c':
                    out_b += bytes([nextarg() & 0xFF])
                elif conv == 'p':
                    out_b += (f'{nextarg():#x}').encode()
            except Exception:
                pass
            i = j + 1
        if kind != 'sprintf_h':
            out_b = out_b[:max(size - 1, 0)]
        try:
            uc.mem_write(out, out_b + b'\0')
        except UcError:
            pass
        return len(out_b)

    # --------------------------------------------------- va_list-based printf
    @staticmethod
    def _r64(uc, addr):
        return struct.unpack('<Q', bytes(uc.mem_read(addr, 8)))[0]

    @staticmethod
    def _r32s(uc, addr):
        return struct.unpack('<i', bytes(uc.mem_read(addr, 4)))[0]

    @staticmethod
    def _wraw(uc, addr, blob):
        try:
            uc.mem_write(addr, blob)
        except UcError:
            pass

    def _emu_vsnprintf_chk(self, uc, out, size, fmt, ap):
        """__vsnprintf_chk(char *s, size_t maxlen, int flags, size_t slen,
        const char *fmt, va_list ap).

        bionic's AArch64 va_list is

            +0  __stack      next stack argument
            +8  __gr_top     top of the saved x-registers
            +16 __vr_top     top of the saved v-registers
            +24 __gr_offs    signed, relative to __gr_top
            +28 __vr_offs    signed, relative to __vr_top

        so the next GP argument sits at __gr_top + __gr_offs while that is
        negative, and spills to __stack once every saved register is used up.
        """
        gr_top = self._r64(uc, ap + 8)
        vr_top = self._r64(uc, ap + 16)
        gr_offs = self._r32s(uc, ap + 24)
        vr_offs = self._r32s(uc, ap + 28)
        stk = self._r64(uc, ap + 0)

        def next_gp():
            nonlocal gr_offs, stk
            if gr_offs < 0:
                v = self._r64(uc, gr_top + gr_offs)
                gr_offs += 8
                self._wraw(uc, ap + 24, struct.pack('<i', gr_offs))
            else:
                v = self._r64(uc, stk)
                stk += 8
                self._wraw(uc, ap + 0, struct.pack('<Q', stk))
            return v

        def next_fp():
            nonlocal vr_offs
            if vr_offs < 0:
                raw = bytes(uc.mem_read(vr_top + vr_offs, 8))
                vr_offs += 8
                self._wraw(uc, ap + 28, struct.pack('<i', vr_offs))
                return struct.unpack('<d', raw)[0]
            return float(next_gp())

        fmt_s = self.safe_read(fmt, 2048).split(b'\0')[0].decode('utf-8',
                                                                 'replace')
        written = self._fmt_apply(uc, fmt_s, next_gp, next_fp)
        blob = written[:max(int(size) - 1, 0)] if size else b''
        if size:
            try:
                uc.mem_write(out, blob + b'\0')
            except UcError:
                pass
        return len(written)

    def _fmt_apply(self, uc, fmt_s, next_gp, next_fp):
        """printf subset shared by the va_list entry points."""
        out_b = b''
        i, n = 0, len(fmt_s)
        while i < n:
            c = fmt_s[i]
            if c != '%':
                out_b += c.encode('utf-8', 'replace')
                i += 1
                continue
            j = i + 1
            flags = ''
            while j < n and fmt_s[j] in '-+ #0':
                flags += fmt_s[j]
                j += 1
            star_w = False
            width = ''
            if j < n and fmt_s[j] == '*':
                star_w = True
                j += 1
            else:
                while j < n and fmt_s[j].isdigit():
                    width += fmt_s[j]
                    j += 1
            star_p = False
            prec = None
            if j < n and fmt_s[j] == '.':
                j += 1
                if j < n and fmt_s[j] == '*':
                    star_p = True
                    j += 1
                else:
                    digits = ''
                    while j < n and fmt_s[j].isdigit():
                        digits += fmt_s[j]
                        j += 1
                    prec = int(digits) if digits else 0
            while j < n and fmt_s[j] in 'hlLzjt':
                j += 1
            if j >= n:
                break
            conv = fmt_s[j]
            if star_w:
                width = str(next_gp() if conv not in 'aAeEfFgG' else next_gp())
            if star_p:
                prec = int(next_gp())
            if conv == '%':
                out_b += b'%'
                i = j + 1
                continue
            try:
                if conv in 'aAeEfFgG':
                    val = next_fp()
                elif conv in 'pdiouxXc':
                    val = next_gp()
                else:
                    val = next_gp()
                pyspec = ('%' + flags + width
                          + ('.%d' % prec if prec is not None else '')
                          + conv)
                if conv == 's':
                    p = val
                    if not p:
                        s = '(null)'
                    else:
                        s = bytes(uc.mem_read(p, 4096)).split(b'\0')[0] \
                            .decode('utf-8', 'replace')
                    out_b += (pyspec % s).encode('utf-8', 'replace')
                elif conv in 'di':
                    v = val if val < (1 << 63) else val - (1 << 64)
                    out_b += (pyspec % v).encode('utf-8', 'replace')
                elif conv == 'c':
                    out_b += (pyspec % chr(val & 0xFF)).encode('utf-8',
                                                               'replace')
                elif conv in 'aAeEfFgG':
                    out_b += (pyspec % float(val)).encode('utf-8', 'replace')
                else:
                    out_b += (pyspec % val).encode('utf-8', 'replace')
            except Exception:
                pass
            i = j + 1
        return out_b

    # ------------------------------------------------------------ utilities
    def neutralize(self, vaddr, note=''):
        """Patch a function to a bare RET (engine-plumbing neutralization)."""
        self.uc.mem_write(self.base + vaddr, RET_INSN())
        self._neutralized = getattr(self, '_neutralized', set())
        self._neutralized.add(vaddr)
        if self.verbose:
            print(f'[loader2] neutralized {vaddr:#x} {note}')

    def watch(self, vaddr, callback, name=''):
        """Code watcher at one address; callback(uc, core). One hook per
        watcher, dispatch ONLY its own callback. Returns a handle with
        .remove()."""
        w = dict(addr=vaddr, cb=callback, name=name, h=None, active=True)

        def _dispatch(uc, addr, size, ud):
            if w['active']:
                try:
                    w['cb'](uc, self)
                except Exception as e:
                    self._log.append(f'watcher {w["name"]} error: {e}')

        w['h'] = self.uc.hook_add(UC_HOOK_CODE, _dispatch,
                                  begin=self.base + vaddr,
                                  end=self.base + vaddr + 3)
        self.watchers.append(w)
        return w

    def unwatch(self, w):
        w['active'] = False
        try:
            self.uc.hook_del(w['h'])
        except Exception:
            pass
        if w in self.watchers:
            self.watchers.remove(w)

    def call_x8(self, fn, x0=0, x1=0, x2=0, x3=0, w4=0, w5=0, x8=None,
                timeout_s=60, max_insns=100_000_000):
        """Call with x8 (sret) support."""
        uc = self.uc
        uc.reg_write(UC_ARM64_REG_X0, x0)
        uc.reg_write(UC_ARM64_REG_X1, x1)
        uc.reg_write(UC_ARM64_REG_X2, x2)
        uc.reg_write(UC_ARM64_REG_X3, x3)
        uc.reg_write(UC_ARM64_REG_X4, w4)
        uc.reg_write(UC_ARM64_REG_X5, w5)
        if x8 is not None:
            uc.reg_write(UC_ARM64_REG_X8, x8)
        uc.reg_write(UC_ARM64_REG_SP, self.sp0)
        for i in range(6, 29):
            uc.reg_write(getattr(A64C, f'UC_ARM64_REG_X{i}'), 0)
        uc.reg_write(UC_ARM64_REG_X29, self.sp0 - 0x1000)  # sane frame ptr
        uc.reg_write(UC_ARM64_REG_LR, RET_TRAP)
        try:
            uc.emu_start(self.base + fn, RET_TRAP,
                         timeout=timeout_s * 1_000_000, count=max_insns)
            err = None
        except UcError as e:
            err = e
        return {'error': str(err) if err else None,
                'pc': uc.reg_read(UC_ARM64_REG_PC),
                'x0': uc.reg_read(UC_ARM64_REG_X0)}

    # ------------------------------------------------- fabricated singletons
    def fabricate_component_manager(self, comp_id=0x4D, comp_size=0x10000):
        """*(0xa40f950) = M(0x48); [M+0] = comps[245]; comps[comp_id] = C.
        Returns C — install params (ball.o) at C+8."""
        M = self.alloc(0x48, b'\0' * 0x48, name='comp_manager')
        comps = self.alloc(245 * 8, b'\0' * (245 * 8), name='comp_array')
        C = self.alloc(comp_size, b'\0' * comp_size, name=f'comp_{comp_id:#x}')
        self.write_u64(M, comps)
        self.write_u64(comps + 8 * comp_id, C)
        self.write_u64(self.base + 0xa40f950, M)
        if self.verbose:
            print(f'[loader2] component manager @ *(0xa40f950) -> M={M:#x}; '
                  f'comp[{comp_id:#x}] = {C:#x}')
        return C

    def set_substep_global(self, N):
        """*(0x98dddc8) -> &N  (chain_top reads w4 = *(*(0x98dddc8)))."""
        if not hasattr(self, '_n_cell'):
            self._n_cell = self.alloc(16, struct.pack('<II', N, 0), name='n_cell')
        self.write_u32(self._n_cell, N)
        self.write_u64(self.base + 0x98dddc8, self._n_cell)
        return self._n_cell

    def fabricate_module_registry(self, size=0x1000):
        """*(0x98ddd28) -> R (6e91da8 registers module at [R + idx*8 + 0x298])."""
        R = self.alloc(size, b'\0' * size, name='module_registry')
        self.write_u64(self.base + 0x98ddd28, R)
        return R


if __name__ == '__main__':
    core = EFootballCoreV2()
    r = core.call(0x6813eb8)
    bits = core.uc.reg_read(UC_ARM64_REG_S0)
    import struct as _s
    print('[selftest2] timestep =', _s.unpack('<f', _s.pack('<I', bits & 0xFFFFFFFF))[0])
    print('[selftest2] log:', core._log[:5])
