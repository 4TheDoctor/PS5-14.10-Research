# PS5 14.10 Kernel Research — AI Guide

## What This Project Is

Systematic kernel exploit research on PlayStation 5 firmware 14.10. The goal is: **userland code exec → kernel R/W → hypervisor bypass**. We have userland code execution via a Lua 5.1 loader on TCP 9026. We need kernel memory access.

## Critical Context

## Current Evidence Correction — 2026-10-18

This section scopes the current claims; older notes describe their cited probe sets. See [the ledger guide](docs/RESEARCH_EVIDENCE.md). A writable pointer, a truncated write, a returned Lua value, and an identified dispatcher implementation are different evidence.

- Probe 45c recorded sysctl/getpid results persisting after selected fn_addr changes and corruption of chain entries 0–7 in one run. This contradicts the earlier dependency model for those tested calls; it does not identify the complete dispatch implementation or establish that every path ignores those fields.
- Probe 46b reports a shared C-function __call address, but its log is truncated and does not establish the function's implementation or a redirection primitive.
- Probes 54o and 54p are incomplete: 54o stops immediately after writing the candidate `+0x20` field, while 54p stops after printing the `xor eax,eax;ret` gadget address. The captures contain no post-call marker, restore confirmation, or returned Lua value. Probe 55g changes to binary output after its write marker, and 54r reads target bytes; neither alone identifies executed instructions. The 54q timeout has no returned-call evidence. Later 56c supplies discriminating output after selected +0x20 target changes.
- **Selected userland CClosure redirects are supported** (56c/56f, 2026-10-18): 56c records rawequal→rawget and rawget→type with distinguishing outputs and restoration; its tostring targets print 42 without a return-type check. 56f adds string.len/math.abs target-like values. General executable-target support, native-register argument control and internal calls to type() remain unverified. A 14.10 kernel vulnerability, kernel read/write, and KASLR defeat are not demonstrated.
- Probes 43o, 43p, 43a/43b, and 47b have evidence gaps. Retest 53d established qword writability/restoration across the tested CClosure offsets; 54o/54p remain incomplete redirect experiments. The older audit predates the saved 52a/52b outputs noted next.
- Scripts 52a/52b now have saved outputs (2026-10-18): 52a crashed at sys 631 (627-630 PCALL-FAIL); 52b confirmed sys 624 as a VM operation counter (+5 per mmap, zero jitter).
- **thr_create(430) kernel panic root cause identified** (PRs #30/#31, 2026-10-19): 13.60 Ghidra decompile of 22 functions shows `set_mcontext()` copies CS register from user ucontext without OR-ing `SEL_RPL_MASK` (0x3). CS=0 from zeroed context → `ISPL(0)=0` → kernel-mode fault path → `pcb_onfault==NULL` → `trap_fatal` → panic. Fix hypothesis: CS=0x43/SS=0x3B should produce a user-mode thread. This is a 13.60 analysis; behavioral match with 14.10 panic (rv=0, TID returned, delayed panic, entry point irrelevant) is strong but identical code is not proven. Probe 80a tests the CS=0x43 fix on 14.10. **The selector question is measured (448a-452a, 2026-10-23)**: `CS = 0x40` starts a child that executes (448a), but `in al, dx` - illegal at CPL 3 - faults in that child (452a), so the thread stays ring 3. 14.10 replaces or masks the selector; a bad context can only panic, never raise CPL. The earlier "probe 189a" line had no probe, capture or commit behind it and is replaced by these measurements. **Capture re-read (2026-10-21, `docs/THR_CREATE_SETMCONTEXT_COPYMAP_13_60.md`): the 13.60 set_mcontext never reads the context CS field (+0xC0) at all** — it copies GPRs, RIP, RSP, SS (raw, unvalidated) and masked rflags; tf_cs is inherited from the parent frame. 189a's CS=0x40 result is therefore predicted by the copy map, not a divergence; the zeroed-context panic is better explained by SS=0 copied raw into tf_ss (or RIP/RSP=0). Probe 274a discriminates CS=0 vs SS=0 live.
- **The "umtx" probes called syscall 557, not `_umtx_op(454)** (2026-10-19): phase-1/2 probes 04/10-13 and the first revision of 82a bound `sc_umtx_op` to 557 (namedobj_create in the 13.60 capture). 56i2's section [F] is the only saved 454 execution (ops 5/21 ret=0, op 5 wrote a TID-shaped owner word). UMTX_OP_SHM(25) and UMTX_OP_ROBUST_LISTS(26) were never exercised on 454, and FreeBSD 11 reads their key/params pointer from uaddr1. Do not treat probe 10's SHM/robust findings as umtx evidence. Probe 110a prepared; see docs/UMTX_454_EVIDENCE.md.
- The captures labeled 13.60 are fixed ranges, not complete kernel sections; acquisition authenticity remains unresolved; no verified 14.10 kernel image is present in this repository.


### The Environment
- **Target:** PS5 at YOUR_PS5_IP:9026, firmware 14.10
- **Kernel:** FreeBSD r230171 (Sep 28 2026), 16KB pages
- **Entry:** Lua 5.1 scripts sent over TCP (8-byte LE length prefix + raw source)
- **Tool:** `python tools/send_probe.py --save probes/<path>.lua` (writes a JSON run record; `tools/run_probe_batch.py` provides bounded sequential execution)
- **Per-connection ASLR:** Fresh process spawns for every TCP connection. All addresses must be re-derived each run.

### What We Have (Confirmed Working)
| Primitive | How |
|-----------|-----|
| Tested raw syscall invocation | make_syscall(N) bypasses the Lua syscall.resolve() filter for tested numbers; kernel-side restrictions still apply |
| Heap R/W (256+ pages) | GPU mmap adjacency, no guard pages |
| Userland module-base discovery | dynlib_get_info(593) returned base information for 39 userland modules; kernel ASLR is separate |
| eboot gadget catalog | Readable candidate bytes; 56e records nil gadget-test returns, but no working general ROP chain is established |
| Network packet injection | RAW socket + IP_HDRINCL, TCP connect-back with ARP responder |
| sys 649 module member query | Returns userland addresses for member types 1-4, 7, 8 across module handles (no kernel pointers). Probe 54k, 2026-10-18 |
| CClosure function redirect | Selected existing Lua C targets produced target-like outputs and restore checks (56c/56f); eboot gadget execution confirmed via +0x20 redirect (56d-56d7); arbitrary native-register argument control and ROP chain remain unverified |
| Eboot gadget catalog (rax=N) | rax=0 (+0x471), rax=1 (+0x1AB0C6), rax=6 (+0xCEF50), rax=7 (+0xDBF50), rax=8 (+0x8D2D4); no rax=2,3,4,5 in 1.5MB scan. Gadgets control Lua return count for stack reads (probes 56d5-56d7) |
| native.fcall_with_rax | Arbitrary userland function calls: getpid=0x22a, socket=0x16, close=0x0 confirmed (probe 129b) |
| Native syscall chains | `thr_create(430)` starts a child at a gadget chain in eboot's RX text: `RIP = pop rax; ret` (eboot+0x992), stack `[num][syscall;ret][pop rax][num]...`, `pop rdi; ret` (eboot+0x75DFE) for per-link arguments, `pop rax; 431; syscall` to exit. 2 MiB stack, `RFLAGS=0x202` at +0x0F0. Probes 404a-422b, `docs/CHAIN_14_10.md` |
| C11 threading (Thrd_create) | 5+ concurrent threads with join; Atomic_fetch_add_8 as thread entry verified (probes 126g/126h) |
| UMTX_OP functional (op 5/21) | UMTX_OP_WAIT blocks correctly on value match; NWAKE_PRIVATE returns 0; MUTEX_LOCK writes owner TID (probes 56i2, 152k) |
| Device inventory (34/76 nodes) | 34 of 76 `/dev` nodes open from game process (`gc`, `dce`, `ajm`, `dmem0`-`2`, `camera`, `usb`, `hid`, `bt`, `rng`, `gic`, `notification*`, HMD sets); ioctl reaches drivers, they reject commands. 32-bit dirent layout. Probes 259a-268a, PR #74 ng643, 2026-10-21 |
| thr_new(455) with arg delivery | `start_func(arg)` where `arg` arrives in `rdi`. `struct thr_param` (0x38 bytes): start_func(+0), arg(+8), stack_base(+0x10), stack_size(+0x18), child_tid(+0x30). Much simpler than thr_create(430) ucontext. Gadget `mov [rdi],rax;ret` at eboot+0x92C67. Probe 56l, 2026-10-23 |
| Child thread ROP syscalls (4-arg) | thr_new child with controlled stack executes arbitrary 4-arg syscalls via ROP. Full gadget catalog: pop_rax_ret(+0x992), pop_rdi_ret(+0xC9DFE), pop_rsi_ret(+0xD77D), pop_rdx_ret(+0x3B02D7), pop_rcx_ret(+0xE64), pop_rdi_rbp_ret(+0x169), pop_rsi_rbp_ret(+0x78), bare_ret(+0x42). No pop_r8/r9 found — max 4 args. RSP = ((stack_base + stack_size) & ~0xF) - 8. Probes 271g/272a, 2026-10-23 |
| EVFILT_TIMER + socketpair | kqueue(362) + kevent(363) with EVFILT_TIMER(-7) works at 1ms resolution. AF_UNIX socketpair (SOCK_DGRAM) works: write/kevent pipeline confirmed. Probe 271i, 2026-10-23 |
| Child thread fake TCB fix | fn_addr stub error path accesses `%fs:0` for errno — child without TLS crashes on ANY failing syscall. Fix: prepend `sysarch(SET_FSBASE=129, &fake_tcb)` to child ROP chain. Fake TCB = 4KB self-referencing pointer buffer. After fix, `close(-1)` returns -1 normally, sysctl returns -1 (EFAULT). Probe 384b, 2026-10-23 |
| Child multi-arg confirmed | getpid(0-arg)=pid, write(3-arg)=8 bytes via socketpair, socketpair(4-arg)=ret 0 fds created — all from child thread. sysctl(6-arg) fails EFAULT: r8/r9 NOT zeroed at child entry. No mov_r8/xor_r8d gadgets in 4.6MB eboot (386a). Max controlled: 4 args. Probes 384b/386a, 2026-10-23 |
| Concurrent child races clean | Double-close (100 iter), UMTX trylock (50×4), socket write+close (50 iter) — zero kernel pointers, zero anomalies, zero corruption. fd table lock solid. UMTX trylock(op 6) always returns -1 from child (may need full umutex struct or unsupported). Probe 385a, 2026-10-23 |
| POSIX shm (shm_open/ftruncate/mmap) | shm_open(482) works: SHM_ANON, named objects, O_CREAT\|O_RDWR, ftruncate, mmap(MAP_SHARED). sendfile(393) on shm fds sends 16KB/page with interleaved drain. shm_open2(571) is nosys — no largepage objects. Probes 391a-391d, 2026-10-23 |
| mlock(203) heap pages | mlock returns 0 on heap pages — prevents paging, ensures residency. munlock(204) also works. Probe 392f, 2026-10-23 |
| stat(188) filesystem enumeration | stat works on /, /dev, /dev/*, /app0, /app0/*, /system_tmp. mode=0x0000 everywhere (Sony zeroes). Other paths (/system, /data, /proc, /tmp) return -1. Probe 392f, 2026-10-23 |
| SCM_RIGHTS fd passing | sendmsg/recvmsg with SCM_RIGHTS delivers working fds across SOCK_STREAM/DGRAM/SEQPACKET socketpairs. Multiple fds (3+) in one message work. Received fds pass fstat. **Probe 56q was wrong** — 526a confirms fd passing is NOT stripped in game jail. Probe 526a, 2026-10-24 |
| AllocateDirectMemory (GOT wrapper) | `libkernel+0x17EF0` (sceKernelAllocateDirectMemory) works from sandbox via GOT — rv=0, phys `0x110010000`+. `libkernel+0x17810` (GetDirectMemorySize) returns `0x150000000`. Raw syscalls 546-554 return -1 but the wrappers bypass that. MapDirectMemory (`libkernel+0x15020`) crashes because it's 7-arg and fcall only forwards 6 — needs ROP chain. DEM9N101 step163-190, 2026-10-25 |
| dmem0 R/W verified (kernel copyin) | DEM9N101 cross-validated: kernel copyin reads dmem0 pages, Lua memory.write_dword visible through copyin path, AIO-written bytes agree on both paths. dmem0 is genuine R/W over GPU direct memory. physhm write claim REFUTED (Lua shadow artifact). DEM9N101 step163-179, 2026-10-25 |
| osem lifecycle (549-556) | With corrected ABI: 549 create(name, attrs, initial, max), 553 wait, 554 poll, 555 post, 556 cancel, 550 delete — full lifecycle works. delete-while-waiting is safe (no UAF). DEM9N101 step184b, 2026-10-25 |

### What's Blocked (Hard Walls)
- **fn_addr/ROP execution is not demonstrated** — 45c undermines that earlier model for tested calls. Later selected CClosure redirects are separate userland evidence; neither identifies the complete syscall dispatcher
- **W^X enforced, refused bit named** — `mprotect` accepts exactly the values with bit 2 clear (32768 of 65536, probe 423a); bit `0x4` (execute) is the only one refused. `mmap` with `prot=0x7` maps a writable page and a child jumping to it faults on its first instruction, as with `0x33`; `prot=0x5` maps but cannot be written (424a-424c). No protection this process can request is executable.
- **Execute-only memory (XOM)** — system lib .text is XO (reading crashes); eboot is RX
- **Threading works via `thr_create(430)` and `thr_new(455)`** — `fork`, `rfork` stay blocked, but both `thr_create(430)` and `thr_new(455)` start userland threads. `thr_new` is simpler: `start_func(arg)` with arg in rdi, no ucontext gates. `thr_create(430)` starts a second userland thread when the context carries the handler's three gates (`+0x108 = 0x480`, `+0x0d0 <= 7`, `+0x110 = 0x10000`) plus `CS = 0x43` at `+0x0c0`, `RIP` at `+0x0e0`, `RSP` at `+0x0f8`, `SS = 0x3b` at `+0x100`; GP registers come from `+0x048..+0x0b8`. Probes 156c/156d: `rv = 0`, `thr_kill(tid, 0) = 0`, and the child executed `mov [rdi], rax; ret` in eboot and wrote `0xdeadbeefcafe` into a mapped page. The `+0x90..+0xb0` offsets used by 80a are not the fields the handler reads; that context is rejected at `+0x108` (`rv = -1`) with a TID written before validation. `thr_suspend(442)` returns -1 for the child, so a spinning thread outlives the probe; no kernel primitive and no TLS inside the child yet. See `docs/THREADING_ALIVE_14_10.md`.
- **Thread ucontext read is available, write is not** (325a/326a, 2026-10-22): 632 suspends, 633 resumes, and 634 copies 0x4c0 bytes of a suspended thread's saved registers (RIP at `+0xE0`, CS at `+0xE8`, RFLAGS at `+0xF0`, RSP at `+0xF8`) with no kernel pointer in the copy. 635 `thr_set_ucontext` returns `-1`, although its 13.60 dossier describes a stub returning 78, so register rewrite of an existing thread is unavailable.
- **mmap_dmem (628) refuses every shape** (330a/331a, 2026-10-22): the dossier's "descriptor -1 bypasses the device lookup" made it a physical-memory candidate, but 24 calls across descriptor `-1`, a `/dev/dmem0` fd, a `/dev/zero` fd and `0`, three protections, flag `0x40`, a nonzero address hint and two offsets all return `-1`. The refusal is independent of the descriptor, so the entry rejects before the lookup. The nodes themselves open (dmem0-2, dce, gic, gc, zero, fds 22-35 in both modes).
- **The authid gates hold** (332a/333a, 2026-10-22): 535, 536 and 563-566 compare `cred+0x58` against identity values and return `-1` when the caller names its own pid, while selector `0` (which skips the check) returns `0`. Sys 587 is the only reader of the credential record and exposes just the capability word on a game process (`+0x0C` = `0x20000000`; system pids show `0x40000000`), with `cred+0x60` zero, so bit 62 - the gate on 618/646/671 - is clear and unreadable.
- **CVE-2026-49418 (device pager page-list UAF) is not reachable** - `msync(MS_INVALIDATE)`, the call the advisory needs, returns `EINVAL` on every mapping a game process can create (anonymous, GPU-shaped, `/dev/dmem0`/`/dev/gc` `MAP_SHARED`, vnode-backed game files), while `MS_ASYNC`/`MS_SYNC` return 0. `msync` is 65 (`narg 3`); 226 is the shared nosys stub. Probes 455a-455d, `docs/MSYNC_CVE_2026_49418.md`.
- **A kill does not prove the slot is absent** (2026-10-20). It did, by the 173a reading: `make_syscall(4095)` kills and 4095 cannot have a handler. But 622 `ipmimgr_call` kills on six zeros and returned `ret=0` to a real request in 55c, so a present handler that faults on the arguments dies the same way, and a kernel that kills on a forbidden call would look identical. A kill is a result about the call, never about the handler. The range 661-670: 662, 663, 664, 666, 667, 669 return `-1` to six zeros, 670 returns `0`, and 661/665/668 kill on zeros. With the shape their contract names (an id array, a count and an output array) 662/663/664 return `0` and write one Sony status per id - `0x80020003`, unknown id - so they are working batch calls whose ids can only come from the submit path that kills (301a-303a). See `docs/SYSCALL_ABSENT_VS_LETHAL.md` and `docs/AIO_RANGE_14_10_EVIDENCE.md`.
- **The measured sysent ends at 676** (2026-10-20): 677 through 707 each killed the process, thirty-one consecutive numbers including the five `nosys` slots, which reads as past-the-end rather than thirty-one hostile handlers. The 13.60 capture has 735 entries and names the tail (`wait6`, `pipe2`, `ppoll`, `get_phys_page_size`, `ioreq`, `mmap2`, `virtual_query_by_pid`), so either 14.10 dropped it or the tables number differently; it cannot be settled without a 14.10 image. Names above 676 are unverified on 14.10, but the 13.60 CSV thunks all resolve to real code for 677-694 and 700-734 (53 real, 695-699 nosys) — so the 14.10 kill range needs real-args probes (275a) before 'past-the-end' is accepted. See `docs/SYSENT_PRESENCE_14_10.md`.
- **No kernel pointers found** — extensive scanning has found none. AF_ROUTE retest 53b confirmed kernel sanitizes route messages (zero kernel pointers). kldstat/kldnext/kldsym all terminate the process on 14.10 (56k4/56k5, 171a). No KASLR defeat path identified.
- **ROP-shaped metadata role is unknown** — tested calls persisted after selected fn_addr and chain mutations; do not treat the fields as a function-call primitive

### Tested raw syscall behavior
The Lua loader's resolver filter blocks some syscall names. Selected calls still returned results through make_syscall(); this bypasses the Lua-side filter only for those tested calls, and kernel-side restrictions remain. The full dispatch implementation is unknown.

## How to Write Probes

### Probe Template
```lua
-- CRASH_CLASS: LOW | MODERATE | HIGH | RISKY
-- PROBE XX: one-line description
--
-- Context: what we know, what we're testing, why

print("=== PROBE XX: TITLE ===")
print("")

-- Standard helpers (ALWAYS include these)
local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
```

### Lua 5.1 Constraints (MUST follow)
1. **uint64 for all addresses >32 bits:** `uint64(string.format("0x%X%08X", hi, lo))`
2. **pcall everything risky:** `pcall(function() return memory.read_qword(addr) end)`
3. **No `goto`/labels** — Lua 5.1 doesn't have them. Use `repeat...until true` + `break`
4. **XO pages kill past pcall** — reading execute-only memory terminates the process. Never read system lib .text sections. Eboot .text is RX and safe to read.
5. **Fresh ASLR every connection** — never hardcode addresses. Always re-derive from `dynlib_get_info` or `tostring(syscall.pipe)`.
6. **memory.alloc(N)** for heap buffers. Always zero them before use.
7. **Kernel pointer detection:** `h >= 0xFFFF8000` where `h, l = get_hi_lo(val)`. Values like `0xFFFFFFFF_00000000` and `0xFFFFFFFF_FFFFFFFF` are bitmasks/sentinels, NOT real kernel pointers.

### How make_syscall Works
```lua
local sc = make_syscall(202)  -- sysctl
local ret = sc(arg1, arg2, arg3, arg4, arg5, arg6)
-- Arguments are uint64 values
-- Returns: the syscall return value
```
Historical hypothesis only: the heap contains writable ROP-shaped metadata and argument slots. Probe 45c recorded tested calls continuing after selected mutations, so this does not establish that the loader calls fn_addr or executes the chain.

### Getting Key Addresses
```lua
-- Userland module-base discovery; this does not defeat kernel ASLR
local info = memory.alloc(0x200)
safe_wd(info, 0x160)
local sc_info = make_syscall(593)
pcall(function() sc_info(uint64(handle), info) end)
local text_lo = safe_rd(info + 0x108)
local text_hi = safe_rd(info + 0x10C)

-- Historical metadata addresses; not established as execution controls
local pipe_str = tostring(syscall.pipe)
local rop_str = pipe_str:match("ropchain @ (0x[0-9a-fA-F]+)")
local fn_str = pipe_str:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")

-- GPU mmap (heap R/W primitive)
local sc_mmap = make_syscall(477)
local gpu = sc_mmap(uint64(0), uint64(512*0x4000), uint64(0x33),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
```

### Sysctl Pattern
```lua
local sc_sysctl = make_syscall(202)
local mib = memory.alloc(16)
safe_wd(mib, 1)       -- CTL_KERN
safe_wd(mib + 4, 14)  -- KERN_PROC
safe_wd(mib + 8, 1)   -- KERN_PROC_PID
safe_wd(mib + 12, pid)
local outbuf = memory.alloc(0x800)
local oldlenp = memory.alloc(8)
safe_wd(oldlenp, 0x800)
local ret = sc_sysctl(uint64(mib), uint64(4), uint64(outbuf),
    uint64(oldlenp), uint64(0), uint64(0))
```

## Repository Layout

```
probes/
  phase1_identity_layout/    # 01-08: system ID, syscalls, memory
  phase2_kernel_objects/     # 09-21: UMTX, nwake, dmem, AIO, kqueue
  phase3_signals_codexec/    # 22-26: signals, sigaltstack, W^X, XOM
  phase4_ipc_network/        # 27-31: threading, fd passing, sockets
  phase5_buffer_io/          # 32-33: buffer stress, MSG_DONTWAIT
  phase6_raw_packets/        # 34-39: RAW sockets, fragments, IP options
  phase7_heap_exploitation/  # 40-41: GPU mmap, heap R/W, ROP, ASLR bypass
  phase8_live_network/       # 40tcp, 42: TCP fuzz, ktimer, live testing
  phase9_kaslr_defeat/       # 42b-42j: KASLR attempts (mostly failed)
  phase10_untested_theories/ # 43a+: theory-driven probes (results recorded; 2026-10-17 audit)
  phase11_network_attacks/   # 48a-50d: SCTP, IPv6, TCP inject, exotic protocols
  phase12_kernel_analysis/   # 51a+: kernel dump sysent analysis, Sony syscall survey
  phase13_52batch/           # 52a+: Sony syscall survey 627-676 + 624 oracle (written, queued)
phase13_53batch/           # 53a-53d: evidence-audit retests (AIO, AF_ROUTE, kldstat, CClosure)
results/                     # Output logs (same phase structure)
tools/                       # send_probe.py, run_session40.py, tcp_fuzz_server.py
docs/
  ATTACK_SURFACE.md          # Complete syscall status map
  FINDINGS.md                # Detailed technical findings
  PROBE_INDEX.md             # Every probe with status and key result
  STRATEGY.md                # Exploit strategy and dead ends
  UNTESTED_THEORIES.md       # 17 theories ranked by priority
```

## Known Dead Ends

> **Full list: [docs/DEAD_ENDS.md](docs/DEAD_ENDS.md)** (~170 entries). Read before writing any probe.
>
> Key categories closed: all KASLR paths (ioctl, sysctl, routing, timing, module data, GPU pool, kqueue — zero kernel pointers found anywhere), all CVEs tested (49418, 49412, 45257, 49427/49428, 49419, 45250, 58094, 58093, 58099, 58090, 2024-43102, 2019-5607 core, 2026-3038, ZDI-26-784), BSD-native range 1-530 exhausted, full device ioctl sweep (34 nodes, ~32M calls), W^X enforced at hypervisor level.

## Sending Probes

```bash
# Via Python (if installed):
PYTHONIOENCODING=utf-8 python tools/send_probe.py --save probes/<phase>/<name>.lua

# Via native PowerShell (no Python required):
.\tools\send_probe.ps1 probes\<phase>\<name>.lua -Save

# For TCP connect-back fuzzing:
python tools/run_session40.py --ps5-ip YOUR_PS5_IP --fake-ip YOUR_TEST_HOST_IP
```

Results are saved to `results/<phase>/<name>_<timestamp>.txt`.

## Current Attack Priority (Updated 2026-10-23 — post-56e2 results)

**Evidence update:** Phase 14 (54a–55g) and phase 15 (56d-56e2) examined KASLR candidates, CClosure gadgets, and routing socket paths. NET_RT_DUMP "kernel pointers" are proven false positives (sockaddr boundary artifacts). CVE-2026-3038 sa_len=127 accepted without panic. CClosure deep stack reads yield only userland. No KASLR defeat path identified. native.fcall_with_rax provides arbitrary userland function calls.

**CClosure +0x20: target bytes, write boundaries and later returned effects:**
- 55g wrote +1 to type()'s +0x20 low dword; output changes to binary after the write marker. The executed instruction and termination cause are not identified by that capture. Section D records same-value/no-op writes at +0x00, +0x08, +0x10, +0x18, +0x28 and +0x30. Sections E/F record different-value writes only at +0x18 and +0x00, followed by restoration; those operations returned without a recorded behavioral change.
- 54r read the first 64 bytes at each function's +0x20 target: all seven decode as `push rbp; mov rbp, rsp` (0x55 0x48 0x89 0xE5) — real x86-64 C function prologues in eboot's RX .text.
- 54q stops before its post-write marker. A successful tonumber redirect/loop is an interpretation without a recorded returned effect.
- **Scope:** later 56c/56f support selected existing Lua C targets with output and restore checks. Arbitrary target/ABI support, injected-page execution and a working general ROP chain remain unverified. The recorded region protection is userland metadata, not kernel access.

**REMAINING PRIMITIVES:**
- **CClosure +0x20 function redirect (selected targets)** — Lua arguments, target-like output and restore checks are recorded for rawequal/rawget/select changes (56c/56f); machine-register arguments and general native targets are not established.
- Tested syscall invocation via `make_syscall(N)`; the exact C-level dispatcher implementation is unidentified
- Heap R/W via GPU mmap (256+ pages)
- Userland ASLR bypass via `dynlib_get_info(593)`
- Full process VM map via sys 674 (317 named regions with protections)
- Network packet injection (RAW socket + IP_HDRINCL, TCP connect-back)
- **Syscall 624** — confirmed VM operation counter: +5 per mmap, stable (zero jitter over 100 samples), monotonic. Useful as side channel for counting kernel VM ops. (probe 52b)
- **11 accessible Sony syscalls** — 596, 585, 572, 624, 563-566, 606, 643, 640

**NEXT STEPS:**
1. **★★★ MapDirectMemory via ROP chain** — AllocateDirectMemory WORKS (DEM9N101 confirmed, phys addrs returned). MapDirectMemory (`libkernel+0x15020`) is 7-arg and crashes via fcall (only 6 regs). Use thr_new child thread ROP to call it with all 7 args via `push_sysv`/`align_stack`. If it succeeds → direct physical memory R/W → scan for kernel → KASLR defeated without any info leak. **This is the highest-priority target.**
2. **★★ GHOST HANDLE additional paths (527a)** — 89a tested core CVE-2019-5607 pattern → "CVE PATCHED". 527a covers 7 more error paths (buffer-full fail, inflight discard, double-send, SO_SNDBUF manipulation, 1000x DGRAM, SOCK_STREAM fill). Low expectation but closes the door. Push to fork for Qwen to execute.
3. **★★ WebKit FontFaceSet UAF** — ng643 demonstrated object substitution (PRs #149/#150). Needs a same-size class with a shapeable field + address disclosure. We could contribute the addr-leak side using our Lua primitives.
4. **★ fd-close race via child thread** — use thr_new ROP child to close(fd) simultaneously with main thread sendmsg(SCM_RIGHTS, fd). Detect stale fd, type confusion, or kernel panic.
5. **Kernel image acquisition** — without a 14.10 kernel dump, we can't verify sysent layout or find new attack surface.

## When Analyzing Results

1. **Kernel pointers** are in the `0xFFFF8xxx_xxxxxxxx` range. Values like `0xFFFFFFFF_00000000` are bitmasks, not pointers. **CRITICAL: Lua 5.1 NaN-boxed values also fall in this range** — any 64-bit value with IEEE 754 exponent bits = 0x7FF (bits 62:52) is NaN, not a pointer. Module `.data` regions contain thousands of NaN-boxed Lua TValues. Always check the exponent field before declaring a kernel pointer.
2. **ret=0** means success for most syscalls. **ret=-1** means failure. **ret=-999** means the pcall itself failed (crash or exception).
3. **Always cross-reference** against docs/FINDINGS.md and the dead ends list above before declaring something new.
4. **Update UNTESTED_THEORIES.md** when a theory is tested — mark it confirmed, dead, or partially tested.
5. **Update CHANGELOG.md** with each phase's findings.

## Git Conventions

- **Author:** commit as the contributor doing the work (Rithik Janarthanan
  <janarthananrithik@gmail.com>), never as the repository owner
- **No AI attribution** in commits, PRs, or code.
- Commit messages should be short and descriptive of what changed.
