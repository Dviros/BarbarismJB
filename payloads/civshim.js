// payloads/civshim.js — BarbarismJB console-side bridge (M1/M2).
//
// Purpose: run inside the CivSwitch :9026 JS loader closure (Civ 7 process)
// and expose the game's native primitives (call_rop, read64/write64,
// malloc/free, and the nn::socket helpers) to the host over a framed binary
// protocol on TCP :39381. The host side is engine/lib/bridge.cjs (client) +
// engine/lib/connection.cjs (CIV1 hello); the authoritative protocol spec is
// the comment block below and README.md "The civshim wire protocol".
// Logging: the loader's log() (window.log mirroring — screen + :9026 client
// stream). Status codes below mirror engine/shared/errors.cjs
// PROTOCOL_STATUS (kept as local consts: no require() inside the closure).
// Origin: original — BarbarismJB.
//
// ---------------------------------------------------------------------------
// PROTOCOL (all multi-byte fields LITTLE-ENDIAN; every field is exact)
// ---------------------------------------------------------------------------
//
// Hello (console -> host, immediately after accept; 128 + 256 bytes):
//   offset  0  u32  magic    = 0x31564943 (wire bytes read "CIV1")
//   offset  4  u32  version  = 1
//   offset  8  u32  platform = 2 (Switch 2)
//   offset 12  u32  reserved = 0
//   offset 16  u64  mainBase               (Civ 7 main NSO base)
//   offset 24  u64  mainSize               (0 = unknown until UPD_OFFSETS)
//   offset 32  u64  sdkBase                (nnSdk module base)
//   offset 40  u64  sdkSize                (0 = unknown until UPD_OFFSETS)
//   offset 48  u64  scratchPtr             (civshim-owned staging buffer)
//   offset 56  u64  scratchSize
//   offset 64  u64  svcQueryMemory         (absolute; 0 = unknown)
//   offset 72  u64  svcSendSyncRequest     (absolute; 0 = unknown)
//   offset 80  u64  svcConnectToNamedService (absolute; 0 = unknown)
//   offset 88  u64  svcSleepThread         (absolute; 0 = unknown)
//   offset 96  32 bytes reserved, zero
//   then a 256-byte JSON trailer, NUL-padded: the console's known-offsets dict
//   {"svc":{...},"sdk_offsets":{...}} (module-relative offsets, same
//   keys/groups as offsets/civ7-100.json). Only NON-NULL leaves are included
//   (the dict must fit 256 bytes; absent = unknown on-console). The host's
//   authoritative copy is its offsets file and it cross-checks what is here
//   (lib/connection.cjs + lib/offsets.cjs); svc/sdk_offsets can also arrive
//   later via op 11.
//
// Request (host -> console):
//   u32 magic = 0x43495631 (wire bytes read "1VIC")
//   u32 op
//   u32 id     (echoed in the response; correlation only)
//   u32 payloadLen
//   payloadLen bytes
//
// Response (console -> host):
//   u32 magic = 0x43495631
//   u32 op | 0x80000000
//   u32 id
//   u32 payloadLen          (READ: the streamed byte count)
//   u32 status              (0 = ok; see STATUS_* below)
//   payloadLen bytes        (errors: UTF-8 message; READ: raw memory)
//
// Ops (payload lengths are EXACT unless noted; violations are status 3 and
// keep the connection only when the frame itself was well-formed):
//   1 PING   : payload echoed verbatim (capped at 32 bytes).
//   2 CALL   : { u64 fn; u32 argc; u32 reserved; u64 args[argc] } -> { u64 x0 }.
//              Synchronous call_rop(fn, a1..a6). argc must be 0..6; fn must be
//              a non-zero 4-aligned plausible guest address.
//   3 READ   : { u64 addr; u64 len } -> payloadLen = len raw bytes streamed
//              with call_rop(send, fd, addr+off, remaining, 0) (zero-copy).
//              len must be 1..MAX_STREAM; addr+len must stay < 2^47.
//   4 WRITE  : { u64 addr; u64 len }, then len raw bytes on the same stream;
//              console loops call_rop(recv, fd, addr+off, remaining, 0)
//              (zero-copy) and requires exactly len bytes. Bytes the framing
//              layer already buffered are flushed to the target first.
//   5 QUERY  : { u64 addr } -> { u64 base; u64 size; u64 type; u64 perm } via
//              the svcQueryMemory wrapper (MemoryInfo: type u32@+16,
//              perm u32@+20). Needs OFFSETS.svc.query_memory.
//   6 ALLOC  : { u64 size } -> { u64 ptr }   (game calloc(1, size)).
//              size must be 1..0x40000000.
//   7 FREE   : { u64 ptr }.
//   8 THREAD_CREATE : { u64 jbPtr } -> { u64 pthread_t }.
//              call_rop(pthread_create, &slot, NULL, longjmp, jbPtr). The host
//              prepared jbPtr's forged jmp_buf and ROP chain with WRITE.
//              attr = NULL, so the pthread library allocates the stack itself.
//              Needs OFFSETS.sdk_offsets.{pthread_create, longjmp}.
//   9 THREAD_JOIN   : { u64 thread } -> call_rop(pthread_join, thread, NULL).
//              Blocking on the JS thread is safe: the worker never re-enters
//              JS. Needs OFFSETS.sdk_offsets.pthread_join.
//  10 SLEEP  : { u64 ns } -> svcSleepThread wrapper. Needs
//              OFFSETS.svc.sleep_thread.
//  11 UPD_OFFSETS : { JSON bytes of {"svc":{...},"sdk_offsets":{...},
//              "modules":{...}} } (<= 4096 bytes) -> merged into the runtime
//              offset dict for the rest of the session (M0 discovers the
//              values only after this shim first runs, so the host uploads
//              them here; the reply echoes the merged dict, capped). Only
//              whole-number/null values are accepted; unknown groups/keys
//              are ignored.
//  12 THREAD_CREATE_RAW : { u64 jbPtr; u64 stackTop; u32 priority; u32 core }
//              (24 bytes) -> { u64 handle }.
//              call_rop(svcCreateThread, &slot, longjmp, jbPtr, stackTop,
//              priority, core) then svcStartThread(handle). The raw-kernel
//              thread path: nn::os::CreateThread HANGS and pthread_create
//              silently no-ops on Civ 7 1.0.0 (civswitch-kit
//              thread-code.json, hardware-qualified 2026-11-02), so wave
//              workers must be created with raw svcCreateThread. priority
//              and a mask-valid core come from op 15. Entry is longjmp with
//              the jmp_buf/forged-chain pointer as its argument — the exact
//              entry their hardware probe validated on raw threads.
//              A rejected create (e.g. 0xE001 bad priority/core) returns
//              status 2 with the code in the message so the host can retry
//              another core. Needs OFFSETS.svc.{create_thread,start_thread}
//              + sdk_offsets.longjmp. NOTE: exit inside worker chains must
//              be the svc #0x0A wrapper — svc #0x07 is svcExitProcess and
//              kills the game.
//  13 THREAD_WAIT : { u64 handle; u64 timeoutNs } (16 bytes)
//              -> { u64 result; u64 index } — single-shot
//              svcWaitSynchronization(&index, &handle, 1, timeoutNs).
//              result 0 = signaled (index says which), 0xEA01 = kernel
//              wait timeout (poll again); other codes are the host's to
//              judge. Single-shot by design: the host drives the poll loop
//              (10 ms) so the console JS thread stays free. Needs
//              OFFSETS.svc.wait_synchronization.
//  14 THREAD_CLOSE : { u64 handle } -> { u64 result } — svcCloseHandle on a
//              raw thread handle. Needs OFFSETS.svc.close_handle.
//  15 THREAD_SCHED_BORROW : {} -> { u64 priority; u64 coreMask; u64 manager;
//              u64 nodes } — walk the nn::os thread-manager list on-console
//              (manager = read64(sdk + sdk_offsets.thread_manager_global) +
//              0xF0; sentinel manager+0x1D0; node+0x1B0 holds a real kernel
//              thread handle) and query the first live node with
//              svcGetThreadPriority / svcGetThreadCoreMask. Raw threads have
//              no ThreadType, so a valid priority (observed 43/44/59/28) and
//              the usable-core mask are BORROWED from a live game thread —
//              the kernel query is authoritative; in-struct priority fields
//              are not. Nodes are guarded (plausible+aligned, dedupe, cap
//              32, mapping check via QUERY when the offset is known). Needs
//              OFFSETS.svc.{get_thread_priority,get_thread_core_mask} +
//              sdk_offsets.thread_manager_global.
//
// Status codes: 0 OK, 1 op-unavailable (offset unknown), 2 op-failed (native
// call returned an error), 3 bad request, 4 internal error.
//
// Degradation: with an all-null OFFSETS dict (before M0 finishes / before the
// host's op-11 upload) the shim still serves PING/CALL/READ/WRITE/ALLOC/FREE;
// CALL takes absolute addresses, so the host can bootstrap everything else.
// QUERY, SLEEP, THREAD_* answer status 1 until the svc/sdk_offsets entries
// arrive (baked in below or uploaded via op 11).
// ---------------------------------------------------------------------------

(async () => {
    const CONFIG = {
        PORT: 39381,
        BACKLOG: 1,
        STAGING_BYTES: 0x1000,     // native staging buffer for headers/payloads
        MAX_STREAM: 0x400000,      // per-op READ/WRITE byte cap (host chunks <=512K)
        MAX_ALLOC: 0x40000000,     // ALLOC size cap (1 GiB) — validated before malloc
        MAX_OFFSETS_JSON: 4096,    // UPD_OFFSETS payload cap (matches the trailer budget)
        HELLO_VERSION: 1,
        PLATFORM: 2,
        // Fill these from offsets/civ7-100.json once M0 completes — or leave
        // null and let the host upload the same dict via op 11 UPD_OFFSETS
        // right after connecting (the normal flow: M0 discovers the values
        // only after this shim first runs). Values are module-RELATIVE
        // offsets exactly as in that file: svc + sdk_offsets relative to
        // sdkBase. null = feature disabled (status 1). modules.*.size feed
        // the hello header. jmp_buf/gadgets stay host-side (the host forges
        // chains and jmp_bufs itself; only svc/sdk_offsets run on-console).
        OFFSETS: {
            svc: {
                query_memory: null,             // svc #0x06 wrapper
                connect_to_named_service: null, // svc #0x1F wrapper
                send_sync_request: null,        // svc #0x21 wrapper
                sleep_thread: null,             // svc #0x0B wrapper
                close_handle: null,             // svc #0x16 wrapper
                wait_synchronization: null,     // svc #0x18 wrapper
                create_thread: null,            // svc #0x08 wrapper (raw threads)
                start_thread: null,             // svc #0x09 wrapper
                get_thread_priority: null,      // svc #0x0C wrapper
                get_thread_core_mask: null      // svc #0x0E wrapper
            },
            sdk_offsets: {
                longjmp: null,
                pthread_create: null,
                pthread_join: null,
                pthread_exit: null,
                thread_manager_global: null     // nn::os thread-manager global (op 15)
            },
            modules: {
                main: { size: null },
                sdk: { size: null }
            }
        }
    };

    const OP = { PING: 1, CALL: 2, READ: 3, WRITE: 4, QUERY: 5, ALLOC: 6, FREE: 7,
        THREAD_CREATE: 8, THREAD_JOIN: 9, SLEEP: 10, UPD_OFFSETS: 11,
        THREAD_CREATE_RAW: 12, THREAD_WAIT: 13, THREAD_CLOSE: 14, THREAD_SCHED_BORROW: 15 };
    const STATUS = { OK: 0, UNAVAILABLE: 1, FAILED: 2, BAD_REQUEST: 3, INTERNAL: 4 };
    const HELLO_MAGIC = 0x31564943n;   // LE bytes on the wire read "CIV1"
    const REQUEST_MAGIC = 0x43495631n; // LE bytes on the wire read "1VIC"
    const HELLO_BYTES = 128, TRAILER_BYTES = 256;
    const ADDR_MIN = 0x1000n;          // below this no mapping ever exists
    const ADDR_MAX = 1n << 47n;        // Switch 2 userland never reaches here
    // civswitch-kit thread-code.json rawSvc.managerList layout (hardware-
    // validated on Civ 7 1.0.0): manager = read64(sdk + global) + 0xF0, the
    // intrusive list sentinel sits at manager+0x1D0, and node+0x1B0 holds a
    // real kernel thread handle usable with the priority/core-mask SVCs.
    const MANAGER_LAYOUT = { bias: 0xf0n, sentinel: 0x1d0n, handleOffset: 0x1b0n, maxNodes: 32 };

    // ---- request validation helpers (status 3 on violation) ---------------
    function bad(message) {
        return Object.assign(Error("civshim: " + message), { status: STATUS.BAD_REQUEST });
    }
    // Fixed-size payloads must be exact: a short payload is a malformed
    // frame, a long one would desync the next frame's header parse.
    function exactLen(payload, n, what) {
        if (payload.length !== n)
            throw bad(what + " payload must be exactly " + n + " bytes, got " + payload.length);
    }
    function plausible(addr, what) {
        if (addr < ADDR_MIN || addr >= ADDR_MAX)
            throw bad(what + " address 0x" + addr.toString(16) + " is outside plausible guest memory");
        return addr;
    }
    // Span checks happen BEFORE any allocation or native call: a bad span
    // must fail as status 3, not as a console crash.
    function plausibleSpan(addr, len, what) {
        plausible(addr, what);
        if (len <= 0n) throw bad(what + " length must be positive, got " + len);
        if (len > BigInt(CONFIG.MAX_STREAM))
            throw bad(what + " length " + len + " exceeds the stream cap");
        if (addr + len > ADDR_MAX)
            throw bad(what + " span 0x" + addr.toString(16) + "+0x" + len.toString(16) + " reaches past plausible guest memory");
        return addr;
    }

    // ---- native staging ---------------------------------------------------
    const staging = malloc(CONFIG.STAGING_BYTES);
    if (staging === 0n) throw new Error("civshim: staging malloc failed");
    const scratchSize = BigInt(CONFIG.STAGING_BYTES);

    function store64(addr, value) { write64(addr, BigInt.asUintN(64, BigInt(value))); }

    function storeBytes(addr, bytes) {
        // bytes: JS array of numbers; padded to a full 8-byte word per store.
        // Only for civshim-owned buffers (the padding zeroes tail bytes).
        const padded = bytes.slice();
        while (padded.length % 8) padded.push(0);
        for (let i = 0; i < padded.length; i += 8) {
            let word = 0n;
            for (let b = 7; b >= 0; b--) word = (word << 8n) | BigInt(padded[i + b]);
            store64(addr + BigInt(i), word);
        }
    }

    function storeBytesExact(addr, bytes) {
        // Like storeBytes but never writes past bytes.length: the final
        // partial word is merged with a read-modify-write. Used for WRITE
        // leftovers that must land at a guest address byte-exactly.
        const full = bytes.length - bytes.length % 8;
        for (let i = 0; i < full; i += 8) {
            let word = 0n;
            for (let b = 7; b >= 0; b--) word = (word << 8n) | BigInt(bytes[i + b]);
            store64(addr + BigInt(i), word);
        }
        const tail = bytes.length - full;
        if (tail) {
            let word = BigInt.asUintN(64, read64(addr + BigInt(full)));
            for (let b = 0; b < tail; b++) {
                const position = BigInt(b * 8);
                word = (word & ~(0xffn << position)) | (BigInt(bytes[full + b]) << position);
            }
            store64(addr + BigInt(full), word);
        }
    }

    function le64(value) {
        const out = [];
        let v = BigInt.asUintN(64, BigInt(value));
        for (let i = 0; i < 8; i++) { out.push(Number(v & 0xffn)); v >>= 8n; }
        return out;
    }

    function le32(value) {
        const out = [];
        let v = BigInt.asUintN(32, BigInt(value));
        for (let i = 0; i < 4; i++) { out.push(Number(v & 0xffn)); v >>= 8n; }
        return out;
    }

    function queueToBytes(addr, count) {
        // Read `count` native bytes into a JS array via read64 words.
        const out = [];
        const words = Math.ceil(count / 8);
        for (let i = 0; i < words; i++) {
            let word = BigInt.asUintN(64, read64(addr + BigInt(i * 8)));
            const take = Math.min(8, count - i * 8);
            for (let b = 0; b < take; b++) { out.push(Number(word & 0xffn)); word >>= 8n; }
        }
        return out;
    }

    // ---- framed inbound stream --------------------------------------------
    // Control bytes (headers + small payloads) accumulate in a JS array; bulk
    // WRITE data never enters JS (recv lands directly at the target address).
    let queue = [];
    async function fill(fd, need) {
        while (queue.length < need) {
            const n = Number(recv(fd, staging, BigInt(CONFIG.STAGING_BYTES), 0));
            if (n === 0) throw new Error("civshim: host disconnected");
            if (n < 0) throw new Error("civshim: recv failed: " + n);
            queue.push(...queueToBytes(staging, n));
        }
    }
    async function take(fd, count) { await fill(fd, count); return queue.splice(0, count); }
    function takeU32(bytes, at) { return bytes[at] | bytes[at + 1] << 8 | bytes[at + 2] << 16 | bytes[at + 3] << 24; }
    function takeU64(bytes, at) {
        let v = 0n;
        for (let b = 7; b >= 0; b--) v = (v << 8n) | BigInt(bytes[at + b]);
        return BigInt.asUintN(64, v);
    }

    // ---- outbound -----------------------------------------------------------
    async function sendLoop(fd, addr, len) {
        let total = 0n;
        while (total < len) {
            const n = Number(send(fd, addr + total, len - total, 0));
            if (n <= 0) throw new Error("civshim: send failed: " + n);
            total += BigInt(n);
        }
    }

    async function sendResponse(fd, op, id, status, payloadBytes) {
        const payload = payloadBytes || [];
        if (payload.length + 20 > CONFIG.STAGING_BYTES)
            throw new Error("civshim: response payload exceeds staging buffer");
        const header = [...le32(REQUEST_MAGIC), ...le32(op | 0x80000000),
            ...le32(id), ...le32(payload.length), ...le32(status)];
        storeBytes(staging, header);
        await sendLoop(fd, staging, BigInt(header.length));
        if (payload.length) {
            storeBytes(staging + BigInt(header.length), payload);
            await sendLoop(fd, staging + BigInt(header.length), BigInt(payload.length));
        }
    }

    // ---- offsets ------------------------------------------------------------
    // Absolute native addresses resolved from the (mutable) OFFSETS dict.
    // Rebuilt at startup and again on every successful UPD_OFFSETS (op 11).
    let svc = {}, sdkFn = {};
    function resolveNative() {
        const resolve = group => {
            const out = {};
            for (const name of Object.keys(CONFIG.OFFSETS[group] || {})) {
                const off = CONFIG.OFFSETS[group][name];
                out[name] = off === null || off === undefined ? 0n : sdk_base + BigInt(off);
            }
            return out;
        };
        svc = resolve("svc");
        sdkFn = resolve("sdk_offsets");
    }
    resolveNative();
    const moduleSize = name => {
        const size = CONFIG.OFFSETS.modules?.[name]?.size;
        return size === null || size === undefined || size <= 0 ? 0n : BigInt(size);
    };

    // ---- hello ----------------------------------------------------------------
    async function sendHello(fd) {
        const h = [...le32(HELLO_MAGIC), ...le32(CONFIG.HELLO_VERSION), ...le32(CONFIG.PLATFORM),
            ...le32(0), // reserved
            ...le64(main_base), ...le64(moduleSize("main")),
            ...le64(sdk_base), ...le64(moduleSize("sdk")),
            ...le64(staging), ...le64(scratchSize),
            ...le64(svc.query_memory), ...le64(svc.send_sync_request),
            ...le64(svc.connect_to_named_service), ...le64(svc.sleep_thread)];
        while (h.length < HELLO_BYTES) h.push(0);
        // Trailer: the console's known-offsets dict — NON-NULL leaves only.
        // If even that exceeds the 256-byte budget (a fully-populated dict
        // after an op-11 upload), send empty groups: the host's authoritative
        // copy is offsets/civ7-100.json on its side and it re-uploads the
        // console-consumed groups with op 11 right after connecting anyway.
        const known = {};
        for (const group of ["svc", "sdk_offsets"])
            known[group] = Object.fromEntries(
                Object.entries(CONFIG.OFFSETS[group] || {})
                    .filter(([, value]) => value !== null && value !== undefined));
        let dict = JSON.stringify(known);
        if (dict.length > TRAILER_BYTES) {
            await log("civshim: known-offsets dict (" + dict.length + " B) exceeds the 256 B trailer — sending empty groups");
            dict = JSON.stringify({svc: {}, sdk_offsets: {}});
        }
        const t = [];
        for (let i = 0; i < dict.length; i++) t.push(dict.charCodeAt(i) & 0xff);
        while (t.length < TRAILER_BYTES) t.push(0);
        storeBytes(staging, h);
        await sendLoop(fd, staging, BigInt(HELLO_BYTES));
        storeBytes(staging + BigInt(HELLO_BYTES), t);
        await sendLoop(fd, staging + BigInt(HELLO_BYTES), BigInt(TRAILER_BYTES));
    }

    // ---- op handlers ------------------------------------------------------------
    function requireSvc(name, what) {
        if (!svc[name]) throw Object.assign(
            Error("civshim: " + what + " needs OFFSETS.svc." + name +
                " (fill from offsets/civ7-100.json — bake it in above or send op 11 UPD_OFFSETS)"),
            { status: STATUS.UNAVAILABLE });
    }

    async function handleCall(fd, payload) {
        if (payload.length < 16) throw bad("short CALL");
        const fn = takeU64(payload, 0), argc = takeU32(payload, 8);
        if (argc > 6 || payload.length !== 16 + argc * 8)
            throw bad("CALL argc " + argc + " does not match the " + payload.length + "-byte payload");
        if (fn < ADDR_MIN || fn >= ADDR_MAX || fn % 4n !== 0n)
            throw bad("CALL target 0x" + fn.toString(16) + " is not a plausible function address");
        const args = [];
        for (let i = 0; i < argc; i++) args.push(takeU64(payload, 16 + i * 8));
        const result = call_rop(fn, args[0] || 0n, args[1] || 0n, args[2] || 0n,
            args[3] || 0n, args[4] || 0n, args[5] || 0n);
        return [...le64(result)];
    }

    async function handleQuery(fd, payload) {
        // Frame shape first: a malformed request is bad even when the op is
        // unavailable, so the host can distinguish "broken client" from
        // "offsets not loaded yet" without killing the connection.
        exactLen(payload, 8, "QUERY");
        requireSvc("query_memory", "QUERY");
        const address = plausible(takeU64(payload, 0), "QUERY");
        const out = staging + 0x800n, pageInfo = staging + 0x900n;
        const result = call_rop(svc.query_memory, out, pageInfo, address);
        if (result !== 0n) throw Object.assign(Error("civshim: QueryMemory 0x" + result.toString(16)), { status: STATUS.FAILED });
        const base = read64(out), size = read64(out + 8n);
        // MemoryInfo: u64 base, u64 size, u32 type@+16, u32 perm@+20.
        const words = read64(out + 16n);
        const type = words & 0xffffffffn, perm = words >> 32n;
        return [...le64(base), ...le64(size), ...le64(type), ...le64(perm)];
    }

    async function handleAlloc(fd, payload) {
        exactLen(payload, 8, "ALLOC");
        const size = takeU64(payload, 0);
        if (size <= 0n || size > BigInt(CONFIG.MAX_ALLOC))
            throw bad("ALLOC size 0x" + size.toString(16) + " is outside 1.." + CONFIG.MAX_ALLOC);
        const ptr = malloc(Number(size)); // game calloc(1, size)
        if (ptr === 0n) throw Object.assign(Error("civshim: malloc failed"), { status: STATUS.FAILED });
        return [...le64(ptr)];
    }

    async function handleFree(fd, payload) {
        exactLen(payload, 8, "FREE");
        const ptr = takeU64(payload, 0);
        if (ptr !== 0n) plausible(ptr, "FREE"); // free(NULL) stays a valid no-op
        free(ptr);
        return [];
    }

    let threadSlot = 0n;
    async function handleThreadCreate(fd, payload) {
        // Shape before availability (see handleQuery).
        exactLen(payload, 8, "THREAD_CREATE");
        const jbPtr = plausible(takeU64(payload, 0), "THREAD_CREATE jmp_buf");
        if (!sdkFn.pthread_create || !sdkFn.longjmp) throw Object.assign(
            Error("civshim: THREAD_CREATE needs OFFSETS.sdk_offsets.{pthread_create,longjmp} (bake them in or send op 11 UPD_OFFSETS)"),
            { status: STATUS.UNAVAILABLE });
        if (threadSlot === 0n) {
            threadSlot = malloc(16);
            if (threadSlot === 0n) throw Object.assign(Error("civshim: slot malloc failed"), { status: STATUS.FAILED });
        }
        const result = call_rop(sdkFn.pthread_create, threadSlot, 0n, sdkFn.longjmp, jbPtr);
        if (result !== 0n) throw Object.assign(Error("civshim: pthread_create 0x" + result.toString(16)), { status: STATUS.FAILED });
        const thread = read64(threadSlot);
        if (thread === 0n) throw Object.assign(Error("civshim: null pthread_t"), { status: STATUS.FAILED });
        return [...le64(thread)];
    }

    async function handleThreadJoin(fd, payload) {
        // Shape before availability (see handleQuery).
        exactLen(payload, 8, "THREAD_JOIN");
        const thread = plausible(takeU64(payload, 0), "THREAD_JOIN thread");
        if (!sdkFn.pthread_join) throw Object.assign(
            Error("civshim: THREAD_JOIN needs OFFSETS.sdk_offsets.pthread_join"),
            { status: STATUS.UNAVAILABLE });
        const result = call_rop(sdkFn.pthread_join, thread, 0n);
        if (result !== 0n) throw Object.assign(Error("civshim: pthread_join 0x" + result.toString(16)), { status: STATUS.FAILED });
        return [];
    }

    async function handleSleep(fd, payload) {
        // Shape before availability (see handleQuery).
        exactLen(payload, 8, "SLEEP");
        requireSvc("sleep_thread", "SLEEP");
        call_rop(svc.sleep_thread, takeU64(payload, 0));
        return [];
    }

    // ---- raw-svc thread ops (civswitch-kit hardware recipe; see the header) ----
    let rawSlot = 0n;
    function requireSdkFn(name, what) {
        if (!sdkFn[name]) throw Object.assign(
            Error("civshim: " + what + " needs OFFSETS.sdk_offsets." + name +
                " (fill from offsets/civ7-100.json — bake it in above or send op 11 UPD_OFFSETS)"),
            { status: STATUS.UNAVAILABLE });
    }

    async function handleThreadCreateRaw(fd, payload) {
        // { u64 jbPtr; u64 stackTop; u32 priority; u32 core }
        //   -> { u64 handle; u64 createResult; u64 startResult } (24 bytes).
        // Kernel rejections (0xE001 priority/core) come back as payload values
        // with status OK — the host retries another borrowed core on them; only
        // protocol-shaped problems are errors.
        exactLen(payload, 24, "THREAD_CREATE_RAW");
        requireSvc("create_thread", "THREAD_CREATE_RAW");
        requireSvc("start_thread", "THREAD_CREATE_RAW");
        requireSdkFn("longjmp", "THREAD_CREATE_RAW");
        const jbPtr = plausible(takeU64(payload, 0), "THREAD_CREATE_RAW jmp_buf");
        const stackTop = takeU64(payload, 8);
        if (stackTop < ADDR_MIN || stackTop >= ADDR_MAX || stackTop % 0x1000n !== 0n)
            throw bad("THREAD_CREATE_RAW stackTop 0x" + stackTop.toString(16) +
                " must be a page-aligned plausible guest address");
        const priority = takeU32(payload, 16), core = takeU32(payload, 20);
        if (priority === 0 || priority >= 64)
            throw bad("THREAD_CREATE_RAW priority " + priority + " outside 1..63 (borrow one via op 15)");
        if (core > 255) throw bad("THREAD_CREATE_RAW core " + core + " outside 0..255");
        if (rawSlot === 0n) {
            rawSlot = malloc(16);
            if (rawSlot === 0n) throw Object.assign(Error("civshim: raw slot malloc failed"), { status: STATUS.FAILED });
            store64(rawSlot, 0n);
        }
        const createResult = call_rop(svc.create_thread, rawSlot, sdkFn.longjmp, jbPtr,
            stackTop, BigInt(priority), BigInt(core));
        if (createResult !== 0n) return [...le64(0n), ...le64(createResult), ...le64(0n)];
        const handle = read64(rawSlot) & 0xffffffffn;
        if (handle === 0n || handle >= 0xffff8000n)
            throw Object.assign(Error("civshim: invalid raw thread handle 0x" + handle.toString(16)), { status: STATUS.FAILED });
        const startResult = call_rop(svc.start_thread, handle);
        if (startResult !== 0n) {
            try { call_rop(svc.close_handle, handle); } catch (_) {}
            return [...le64(0n), ...le64(0n), ...le64(startResult)];
        }
        return [...le64(handle), ...le64(0n), ...le64(0n)];
    }

    async function handleThreadWait(fd, payload) {
        // { u64 handle; u64 timeoutNs } -> { u64 result; u64 index }, single-shot.
        exactLen(payload, 16, "THREAD_WAIT");
        requireSvc("wait_synchronization", "THREAD_WAIT");
        const handle = takeU64(payload, 0);
        if (handle === 0n || handle >= 0xffff8000n)
            throw bad("THREAD_WAIT handle 0x" + handle.toString(16) + " is not a kernel thread handle");
        const timeoutNs = takeU64(payload, 8);
        const out = staging + 0xa00n, handles = staging + 0xa80n;
        store64(out, 0n);
        store64(handles, handle); // u32 handle in the first slot; padding zero
        const result = call_rop(svc.wait_synchronization, out, handles, 1n, timeoutNs);
        const index = read64(out) & 0xffffffffn;
        return [...le64(result), ...le64(index)];
    }

    async function handleThreadClose(fd, payload) {
        exactLen(payload, 8, "THREAD_CLOSE");
        requireSvc("close_handle", "THREAD_CLOSE");
        const handle = takeU64(payload, 0);
        if (handle === 0n || handle >= 0xffff8000n)
            throw bad("THREAD_CLOSE handle 0x" + handle.toString(16) + " is not a kernel thread handle");
        const result = call_rop(svc.close_handle, handle);
        return [...le64(result)];
    }

    async function handleThreadSchedBorrow(fd, payload) {
        // Walk the nn::os manager list on-console; borrow priority + core mask
        // from the first node whose kernel handle answers the SVCs. Guards:
        // plausible+aligned nodes, a dedupe set, a node cap, and — when the
        // query_memory wrapper is known — a mapping check before each read.
        exactLen(payload, 0, "THREAD_SCHED_BORROW");
        requireSvc("get_thread_priority", "THREAD_SCHED_BORROW");
        requireSvc("get_thread_core_mask", "THREAD_SCHED_BORROW");
        requireSdkFn("thread_manager_global", "THREAD_SCHED_BORROW");
        const out = staging + 0xb00n;
        const covered = async address => {
            if (!svc.query_memory) return true; // alignment+dedupe guards only
            const result = call_rop(svc.query_memory, staging + 0x800n, staging + 0x900n, address);
            if (result !== 0n) return false;
            const base = read64(staging + 0x800n), size = read64(staging + 0x808n);
            return address >= base && address + 0x608n <= base + size;
        };
        const manager = read64(sdk_base + BigInt(CONFIG.OFFSETS.sdk_offsets.thread_manager_global)) + MANAGER_LAYOUT.bias;
        if (manager < ADDR_MIN || manager >= ADDR_MAX || manager % 8n !== 0n)
            throw Object.assign(Error("civshim: implausible thread-manager pointer 0x" + manager.toString(16)), { status: STATUS.FAILED });
        if (!(await covered(manager))) throw Object.assign(Error("civshim: manager mapping check failed"), { status: STATUS.FAILED });
        const sentinel = manager + MANAGER_LAYOUT.sentinel;
        let node = read64(sentinel);
        const seen = new Set();
        let nodes = 0;
        for (let count = 0; node !== sentinel && count < MANAGER_LAYOUT.maxNodes; count++) {
            if (node < ADDR_MIN || node >= ADDR_MAX || node % 8n !== 0n || seen.has(node.toString()))
                throw Object.assign(Error("civshim: invalid or cyclic manager-list node 0x" + node.toString(16)), { status: STATUS.FAILED });
            seen.add(node.toString());
            nodes++;
            if (!(await covered(node)))
                throw Object.assign(Error("civshim: node mapping check failed at 0x" + node.toString(16)), { status: STATUS.FAILED });
            const handle = (read64(node + MANAGER_LAYOUT.handleOffset)) & 0xffffffffn;
            const next = read64(node);
            if (handle > 0n && handle < 0xffff8000n) {
                const prioResult = call_rop(svc.get_thread_priority, out, handle, 0n);
                if (prioResult === 0n) {
                    const priority = read64(out) & 0xffffffffn;
                    if (priority > 0n && priority < 64n) {
                        const maskResult = call_rop(svc.get_thread_core_mask, out, out + 8n, handle);
                        if (maskResult === 0n) {
                            const coreMask = read64(out + 8n);
                            if (coreMask !== 0n)
                                return [...le64(priority), ...le64(coreMask), ...le64(manager), ...le64(BigInt(nodes))];
                        }
                    }
                }
            }
            node = next;
        }
        throw Object.assign(Error("civshim: no borrowable thread scheduling found (" + nodes + " nodes)"), { status: STATUS.FAILED });
    }

    async function handleUpdOffsets(fd, payload) {
        // op 11: merge a host-uploaded offsets dict into the runtime table.
        // Only known groups are accepted, and only number/null leaf values —
        // anything else is a bad request. The merged dict persists for the
        // rest of the session (the shim process's lifetime).
        if (payload.length > CONFIG.MAX_OFFSETS_JSON)
            throw bad("UPD_OFFSETS payload exceeds " + CONFIG.MAX_OFFSETS_JSON + " bytes");
        let text = "";
        for (let i = 0; i < payload.length; i++) text += String.fromCharCode(payload[i]);
        let uploaded;
        try { uploaded = JSON.parse(text); }
        catch { throw bad("UPD_OFFSETS payload is not valid JSON"); }
        if (!uploaded || typeof uploaded !== "object" || Array.isArray(uploaded))
            throw bad("UPD_OFFSETS payload is not an object");
        const accepted = {svc: 0, sdk_offsets: 0, modules: 0};
        const clean = value => value === null || typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
        for (const group of Object.keys(accepted)) {
            const entries = uploaded[group];
            if (entries === undefined) continue;
            if (!entries || typeof entries !== "object" || Array.isArray(entries))
                throw bad("UPD_OFFSETS group '" + group + "' is not an object");
            const target = group === "modules"
            // modules keeps its {main:{size},sdk:{size}} shape; the leaf
            // objects are merged key-by-key with the same clean() rule.
                ? (() => {
                    for (const name of Object.keys(entries)) {
                        const leaf = entries[name];
                        if (!leaf || typeof leaf !== "object" || Array.isArray(leaf))
                            throw bad("UPD_OFFSETS modules." + name + " is not an object");
                        for (const key of Object.keys(leaf))
                            if (!clean(leaf[key]))
                                throw bad("UPD_OFFSETS modules." + name + "." + key + " is not a non-negative integer or null");
                    }
                    return entries;
                })()
                : (() => {
                    for (const key of Object.keys(entries))
                        if (!clean(entries[key]))
                            throw bad("UPD_OFFSETS " + group + "." + key + " is not a non-negative integer or null");
                    return entries;
                })();
            // Merge rule: null means "unknown on the host" and never downgrades
            // a value the console already has (e.g. from the baked-in dict).
            const keepExisting = (current, incoming) =>
                incoming === null && typeof current === "number" ? current : incoming;
            CONFIG.OFFSETS[group] = CONFIG.OFFSETS[group] || {};
            if (group === "modules")
                for (const name of Object.keys(target)) {
                    CONFIG.OFFSETS.modules[name] = CONFIG.OFFSETS.modules[name] || {};
                    for (const key of Object.keys(target[name]))
                        CONFIG.OFFSETS.modules[name][key] =
                            keepExisting(CONFIG.OFFSETS.modules[name][key], target[name][key]);
                }
            else
                for (const key of Object.keys(target))
                    CONFIG.OFFSETS[group][key] = keepExisting(CONFIG.OFFSETS[group][key], target[key]);
            accepted[group] = Object.keys(target).length;
        }
        resolveNative(); // rebuild absolute addresses; new features go live now
        const reply = JSON.stringify({svc: CONFIG.OFFSETS.svc, sdk_offsets: CONFIG.OFFSETS.sdk_offsets,
            modules: CONFIG.OFFSETS.modules});
        if (reply.length > CONFIG.STAGING_BYTES - 64) // header + reply must fit staging
            throw Object.assign(Error("civshim: merged offsets dict too large"), { status: STATUS.INTERNAL });
        const bytes = [];
        for (let i = 0; i < reply.length; i++) bytes.push(reply.charCodeAt(i) & 0xff);
        await log("civshim: offsets updated (svc:" + accepted.svc + " sdk_offsets:" + accepted.sdk_offsets +
            " modules:" + accepted.modules + ")");
        return bytes;
    }

    // ---- request loop ------------------------------------------------------------
    async function serveConnection(fd) {
        await sendHello(fd);
        let ops = 0;
        for (;;) {
            const header = await take(fd, 16);
            const magic = BigInt(takeU32(header, 0) >>> 0);
            const op = takeU32(header, 4) >>> 0, id = takeU32(header, 8) >>> 0;
            const payloadLen = takeU32(header, 12) >>> 0;
            if (magic !== REQUEST_MAGIC) throw new Error("civshim: bad request magic");
            if (payloadLen > CONFIG.MAX_STREAM) {
                await sendResponse(fd, op, id, STATUS.BAD_REQUEST, []);
                throw new Error("civshim: oversized payload " + payloadLen);
            }
            const payload = payloadLen ? await take(fd, payloadLen) : [];
            try {
                switch (op) {
                    case OP.PING:
                        // Echo; capped so a stray large ping cannot overflow staging.
                        await sendResponse(fd, op, id, STATUS.OK, payload.slice(0, 32));
                        break;
                    case OP.CALL:
                        await sendResponse(fd, op, id, STATUS.OK, await handleCall(fd, payload));
                        break;
                    case OP.READ: {
                        exactLen(payload, 16, "READ");
                        const addr = takeU64(payload, 0), len = takeU64(payload, 8);
                        plausibleSpan(addr, len, "READ");
                        // Header first (payloadLen = len), then the bytes stream
                        // straight out of guest memory with send(2).
                        const head = [...le32(REQUEST_MAGIC), ...le32(op | 0x80000000),
                            ...le32(id), ...le32(Number(len)), ...le32(STATUS.OK)];
                        storeBytes(staging, head);
                        await sendLoop(fd, staging, BigInt(head.length));
                        await sendLoop(fd, addr, len);
                        break;
                    }
                    case OP.WRITE: {
                        exactLen(payload, 16, "WRITE");
                        const addr = takeU64(payload, 0), len = takeU64(payload, 8);
                        plausibleSpan(addr, len, "WRITE");
                        // The framing layer may have buffered past the frame:
                        // those bytes are the first of this WRITE's raw data
                        // (the host serializes ops and sends frame+raw in one
                        // burst). Flush them into the target byte-exactly,
                        // then recv(2) the rest — the bulk never transits JS.
                        const overshoot = queue.splice(0);
                        if (BigInt(overshoot.length) > len)
                            throw new Error("civshim: WRITE stream overrun (" + overshoot.length + " > " + len + ")");
                        let total = 0n;
                        if (overshoot.length) {
                            storeBytesExact(addr, overshoot);
                            total = BigInt(overshoot.length);
                        }
                        while (total < len) {
                            const n = Number(recv(fd, addr + total, len - total, 0));
                            if (n === 0) throw new Error("civshim: host disconnected mid-WRITE");
                            if (n < 0) throw new Error("civshim: WRITE recv failed: " + n);
                            total += BigInt(n);
                        }
                        await sendResponse(fd, op, id, STATUS.OK, []);
                        break;
                    }
                    case OP.QUERY:
                        await sendResponse(fd, op, id, STATUS.OK, await handleQuery(fd, payload));
                        break;
                    case OP.ALLOC:
                        await sendResponse(fd, op, id, STATUS.OK, await handleAlloc(fd, payload));
                        break;
                    case OP.FREE:
                        await sendResponse(fd, op, id, STATUS.OK, await handleFree(fd, payload));
                        break;
                    case OP.THREAD_CREATE:
                        await sendResponse(fd, op, id, STATUS.OK, await handleThreadCreate(fd, payload));
                        break;
                    case OP.THREAD_JOIN:
                        await sendResponse(fd, op, id, STATUS.OK, await handleThreadJoin(fd, payload));
                        break;
                    case OP.SLEEP:
                        await sendResponse(fd, op, id, STATUS.OK, await handleSleep(fd, payload));
                        break;
                    case OP.UPD_OFFSETS:
                        await sendResponse(fd, op, id, STATUS.OK, await handleUpdOffsets(fd, payload));
                        break;
                    case OP.THREAD_CREATE_RAW:
                        await sendResponse(fd, op, id, STATUS.OK, await handleThreadCreateRaw(fd, payload));
                        break;
                    case OP.THREAD_WAIT:
                        await sendResponse(fd, op, id, STATUS.OK, await handleThreadWait(fd, payload));
                        break;
                    case OP.THREAD_CLOSE:
                        await sendResponse(fd, op, id, STATUS.OK, await handleThreadClose(fd, payload));
                        break;
                    case OP.THREAD_SCHED_BORROW:
                        await sendResponse(fd, op, id, STATUS.OK, await handleThreadSchedBorrow(fd, payload));
                        break;
                    default:
                        await sendResponse(fd, op, id, STATUS.BAD_REQUEST, []);
                        throw new Error("civshim: unknown op " + op);
                }
                ops++;
                if (ops % 500 === 0) await log("civshim: " + ops + " ops served");
            } catch (error) {
                if (error.status !== undefined) {
                    // Per-op failure: report and keep the connection.
                    const message = [];
                    const text = String(error.message || error);
                    for (let i = 0; i < text.length && i < 200; i++) message.push(text.charCodeAt(i) & 0xff);
                    await sendResponse(fd, op, id, error.status, message);
                    await log("civshim: op " + op + " failed: " + text);
                } else throw error; // transport-level: drop the connection
            }
        }
    }

    // ---- server -----------------------------------------------------------------
    const sockaddr = malloc(16), addrlen = malloc(8), enable = malloc(4);
    function createListener() {
        const fd = socket(2, 1, 0); // AF_INET, SOCK_STREAM
        if (fd === -1n) throw new Error("civshim: socket failed");
        // sockaddr_in: sin_len=16, sin_family=AF_INET(2), sin_port in network
        // byte order, INADDR_ANY.
        storeBytes(sockaddr, [16, 2, (CONFIG.PORT >> 8) & 0xff, CONFIG.PORT & 0xff,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        store64(enable, 1n);
        setsockopt(fd, 0xffff, 4, enable, 4); // SOL_SOCKET, SO_REUSEADDR
        if (bind(fd, sockaddr, 16) !== 0n) { close(fd); throw new Error("civshim: bind :" + CONFIG.PORT + " failed"); }
        if (listen(fd, CONFIG.BACKLOG) !== 0n) { close(fd); throw new Error("civshim: listen failed"); }
        return fd;
    }

    await log("civshim: listening on :" + CONFIG.PORT +
        (svc.query_memory ? " (svc table loaded)" :
        " (offsets EMPTY - host must send op 11 UPD_OFFSETS for QUERY/SLEEP/THREAD)"));

    for (;;) {
        let listener;
        try { listener = createListener(); } catch (error) { await log("civshim: " + error.message); await sleep(2000); continue; }
        for (;;) {
            try {
                store64(addrlen, 16n);
                const fd = accept(listener, sockaddr, addrlen);
                if (fd === -1n) { await log("civshim: accept failed"); break; }
                try {
                    await serveConnection(fd); // returns only on disconnect/error
                } catch (error) {
                    await log("civshim: connection ended: " + (error.message || error));
                } finally {
                    close(fd);
                }
            } catch (error) {
                await log("civshim: accept loop: " + (error.message || error));
                break;
            }
        }
        close(listener);
        await sleep(500);
    }
})();
