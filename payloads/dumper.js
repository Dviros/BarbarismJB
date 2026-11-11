// payloads/dumper.js — BarbarismJB M0 module dumper for the CivSwitch :9026
// remote JS loader.
//
// Purpose: bootstrap the Civ 7 offset table — phase A scans the sdk text for
// svc wrapper entries, phase B maps the module extents via QueryMemory,
// phase C streams both modules to the host over one TCP connection
// (CIVDUMP1 wire format, received by tools/dump_recv.py). Output feeds
// tools/svc_scan.py + tools/gadget_scan.py -> offsets/civ7-100.json.
// Protocol/docs: offsets/README.md (M0 workflow), DESIGN.md section 3.
// Logging: the loader's log() (window.log mirroring). Edit HOST_IP below
// before sending. Origin: original — BarbarismJB.
//
// Runs inside core.js's remote_js_loader() closure (sent with send_js.py, the
// loader eval()s it there), so it directly reuses the in-scope primitives
// (verified against CivSwitch core.js lines 63-716 / 854-1263):
//   call_rop(addr, a1..a6)  sync native call, BigInt in/out  (core.js:854)
//   malloc(size)/free(addr)  game heap                        (core.js:1084)
//   read64/write64/read32/read8 (+16/32) stable arbitrary RW  (core.js:609+)
//   sdk_base, main_base      module load bases                (core.js:768,776)
//   socket/connect/send/recv/close nn::socket ROP helpers     (core.js:1144+)
//   log(msg)                 screen + :9026 client stream     (core.js:1191)
//   sleep(ms), text_encode(str)                               (core.js:63,690)
// Any helper that is NOT in scope (loader version drift) is re-created from
// core.js's documented nn::socket offsets relative to sdk_base.
//
// Phases:
//   A  scan sdk_base..+SCAN_LIMIT (known-mapped text; memcpy sits at +0x5224E0)
//      for `svc #0` sites (01 00 00 D4) preceded within SVC_LOOKBACK
//      instructions by `movz x8,#imm` (0xD2800008|imm<<5) or `movz w8,#imm`
//      (0x52800008|imm<<5). The movz site is the callable wrapper entry
//      (call_rop sets x0-x5 only; x8 must be loaded by the wrapper itself).
//   B  if a svc 6 (QueryMemory) wrapper was found, walk the address space and
//      derive the true contiguous extents of the main and sdk modules.
//   C  open ONE TCP connection to HOST_IP:HOST_PORT, send a CIVDUMP1 JSON
//      header, then every region zero-copy via call_rop(send, fd, addr, len, 0)
//      in CHUNK-byte pieces, then the CIVEND1 trailer.
//
// CRASH TOLERANCE / RECOVERY
//   Phase A reads blindly: if SCAN_LIMIT crosses past the end of the sdk text
//   mapping the process dies with a data abort. That is not corruption — the
//   XSTRIG.Civ7Save save-game trigger re-arms the :9026 loader at every boot,
//   so recovery is: lower SCAN_LIMIT below the last logged scan offset (the
//   payload logs progress every SCAN_LOG_EVERY bytes), or take the region map
//   produced by phase B of a previous successful run and re-send the payload.
//   Phase B and C only touch addresses validated by QueryMemory first, so they
//   cannot fault on unmapped memory.
//
// Sending: python3 ../repos/CivSwitch/send_js.py <console-ip> payloads/dumper.js
//          (payload limit 500 KB; this file is far below it)

(async function () {

// ---------------------------------------------------------------- config --
// EDIT HOST_IP to your receiving machine's IPv4 before sending.
const HOST_IP   = "";
const HOST_PORT = 39390;      // tools/dump_recv.py default
const SCAN_LIMIT  = 0x530000; // sdk text known-mapped at least this far (memcpy @ +0x5224E0)
const CHUNK       = 0x10000;  // bytes per send() during phase C
const SVC_LOOKBACK = 8;       // instructions searched before `svc` for the movz x8/w8
const SCAN_LOG_EVERY = 0x80000; // phase A progress log interval (bytes)
const DUMP_LOG_CHUNKS = 16;   // phase C progress log interval (chunks)

// ------------------------------------------------- closure-scope checks --
if (typeof call_rop !== "function" || typeof read64 !== "function" ||
    typeof sdk_base !== "bigint" || typeof malloc !== "function") {
    throw new Error("dumper: not running inside the CivSwitch :9026 loader closure");
}
if (!HOST_IP || !/^\d+\.\d+\.\d+\.\d+$/.test(HOST_IP)) {
    await log("dumper: set HOST_IP at the top of payloads/dumper.js first");
    return;
}

const hx = (n) => "0x" + BigInt(n).toString(16);

// --------------------------------------------- socket layer (reuse/fallback)
// core.js nn::socket offsets relative to sdk_base (core.js:1127-1136).
const NN_SOCKET = {
    socket:  0x14d4c0n, connect: 0x14d3c0n, send: 0x14d340n,
    recv:    0x14d310n, close:   0x14d510n
};
const sock = {
    socket:  typeof socket  === "function" ? socket  :
        (d, t, p) => BigInt.asIntN(32, call_rop(sdk_base + NN_SOCKET.socket,  BigInt(d), BigInt(t), BigInt(p))),
    connect: typeof connect === "function" ? connect :
        (fd, a, l) => BigInt.asIntN(32, call_rop(sdk_base + NN_SOCKET.connect, fd, a, BigInt(l))),
    send:    typeof send    === "function" ? send    :
        (fd, b, l, f) => BigInt.asIntN(32, call_rop(sdk_base + NN_SOCKET.send, fd, b, BigInt(l), BigInt(f))),
    close:   typeof close   === "function" ? close   :
        (fd) => BigInt.asIntN(32, call_rop(sdk_base + NN_SOCKET.close, fd))
};

function writeBytes(addr, bytes) {
    for (let i = 0; i < bytes.length; i++) {
        write8(addr + BigInt(i), bytes[i]);
    }
}

function writeNullTerm(addr, bytes) { // alloc-style string write incl. NUL
    writeBytes(addr, bytes);
    write8(addr + BigInt(bytes.length), 0);
}

// ---------------------------------------------------------------- phase A --
// Pure JS over read64: aligned qwords, two u32 lanes each. `svc #0` encodes
// little-endian as 01 00 00 D4 = 0xD4000001.
const SVC_INSN  = 0xD4000001;
const MOVZ_X8   = 0xD2800008; // movz x8, #imm16 (hw=0, Rd=8)
const MOVZ_W8   = 0x52800008; // movz w8, #imm16 (hw=0, Rd=8)
const MOVZ_MASK = 0xFFE0001F; // fixes opcode, hw=0 and Rd

// NOTE: `&` in JS yields a signed 32-bit int — coerce with >>> 0 before
// comparing against the positive 0xD2.. pattern, or movz x8 never matches.
function isMovzX8W8(w) {
    const m = (w & MOVZ_MASK) >>> 0;
    return m === MOVZ_X8 || m === MOVZ_W8;
}

// svc number ground truth: repos/ns2jb/engine/switch2/ro/payload/start.S.
const SVC_NAMES = {
    0x06: "query_memory",            0x0B: "sleep_thread",
    0x16: "close_handle",            0x18: "wait_synchronization",
    0x1E: "get_system_tick",         0x1F: "connect_to_named_service",
    0x21: "send_sync_request",       0x24: "get_process_id",
    0x25: "get_thread_id",           0x29: "get_info",
    0x41: "accept_session",          0x43: "reply_and_receive",
    0x53: "cancel_synchronization",  0x73: "set_process_memory_permission",
    0x74: "map_process_memory",      0x75: "unmap_process_memory",
    0x76: "query_process_memory",    0x77: "map_process_code_memory",
    0x78: "unmap_process_code_memory"
};

async function phaseA() {
    const t0 = Date.now();
    // svcnum -> { sites: [svcOff...], entries: [movzOff...] } (offsets from sdk_base)
    const found = {};
    const win = []; // last SVC_LOOKBACK decoded instructions (Number u32s)
    let nextLog = SCAN_LOG_EVERY;

    const consume = (w, wOff) => {
        if (w === SVC_INSN) {
            // nearest preceding movz x8/w8 owns this site
            for (let k = win.length - 1; k >= 0; k--) {
                if (isMovzX8W8(win[k].w)) {
                    const num = (win[k].w >>> 5) & 0xFFFF;
                    const rec = found[num] || (found[num] = { sites: [], entries: [] });
                    rec.sites.push(wOff);
                    rec.entries.push(win[k].off);
                    break;
                }
            }
        }
        win.push({ w: w, off: wOff });
        if (win.length > SVC_LOOKBACK) win.shift();
    };

    for (let off = 0; off < SCAN_LIMIT; off += 8) {
        const q = read64(sdk_base + BigInt(off));
        consume(Number(q & 0xFFFFFFFFn), off);
        consume(Number((q >> 32n) & 0xFFFFFFFFn), off + 4);

        if (off >= nextLog) {
            nextLog += SCAN_LOG_EVERY;
            await log("dumper[A]: scanned " + hx(off) + " / " + hx(SCAN_LIMIT) +
                      " (" + Object.keys(found).length + " svc nums)");
        }
    }

    const named = {};
    for (const num of Object.keys(SVC_NAMES)) {
        const rec = found[num];
        if (rec && rec.entries.length) {
            named[SVC_NAMES[num]] = {
                num: Number(num),
                entry: rec.entries[0],   // movz site: callable via call_rop
                site: rec.sites[0],
                count: rec.sites.length
            };
        }
    }
    await log("dumper[A]: done in " + (Date.now() - t0) + " ms, " +
              Object.keys(found).length + " svc numbers, " +
              Object.keys(named).length + "/" + Object.keys(SVC_NAMES).length + " named");
    return { found: found, named: named };
}

// ---------------------------------------------------------------- phase B --
// svcQueryMemory(MemoryInfo* x0, PageInfo* x1, addr x2) — kernel layout
// (ns2jb process.c MemoryInfo): +0x00 base, +0x08 size, +0x10 type,
// +0x14 attributes, +0x18 permission (r1 w2 x4), +0x1C ipc_refs,
// +0x20 device_refs, +0x24 pad. 0x28 written; we allocate 0x40 to be safe.
function readMemInfo(mi) {
    return {
        base: read64(mi),
        size: read64(mi + 8n),
        type: Number(read32(mi + 0x10n)),
        attributes: Number(read32(mi + 0x14n)),
        perm: Number(read32(mi + 0x18n)),
        ipc: Number(read32(mi + 0x1cn)),
        device: Number(read32(mi + 0x20n))
    };
}

async function phaseB(namedSvc) {
    const qm = namedSvc.query_memory;
    if (!qm) {
        await log("dumper[B]: no QueryMemory wrapper — module extents unknown, " +
                  "phase C will dump only sdk_base..+SCAN_LIMIT");
        return null;
    }
    const wrapper = sdk_base + BigInt(qm.entry);
    const MI = malloc(0x40);
    const PI = malloc(8);
    const probe = malloc(0x20);
    if (!MI || !PI || !probe) throw new Error("dumper[B]: heap alloc failed");

    // The found wrapper is either a pass-through 3-arg (x0,x1,x2) wrapper or a
    // 2-arg (x0=info, x1=addr ; `mov x2,x1`) one. Detect by probing:
    //  - canonical attempt passes sdk_base in x2 and scratch in x1: a real
    //    3-arg wrapper returns the sdk RX region (perm&4); a 2-arg wrapper
    //    would clobber x2 with x1 (scratch) and answer a heap region (perm 3).
    //  - fallback passes a heap probe as x1: only the 2-arg form puts the
    //    probe into x2 and answers a heap region with type 5 / perm 3.
    // Both attempts only ever expose scratch/probe pointers as x1, so even a
    // kernel that still honors the PageInfo out-pointer (ns2jb queries live
    // mappings the same way, evidence it does not) could not damage anything.
    let mode = 0; // 3 = (info, pageinfo, addr), 2 = (info, addr)
    let r = call_rop(wrapper, MI, PI, sdk_base);
    if (r === 0n) {
        let m = readMemInfo(MI);
        if (m.base <= sdk_base && sdk_base < m.base + m.size && (m.perm & 4)) mode = 3;
    }
    if (!mode) {
        r = call_rop(wrapper, MI, probe);
        if (r === 0n) {
            const m = readMemInfo(MI);
            if (m.base <= probe && probe < m.base + m.size &&
                m.perm === 3 && m.type === 5) mode = 2;
        }
    }
    if (!mode) {
        await log("dumper[B]: QueryMemory wrapper rejected both arg layouts — " +
                  "dumping scan range only");
        return null;
    }
    await log("dumper[B]: QueryMemory arg mode " + mode);

    const query = (addr) => {
        const res = mode === 3 ? call_rop(wrapper, MI, PI, addr)
                               : call_rop(wrapper, MI, addr);
        return res === 0n ? readMemInfo(MI) : null;
    };

    // Full address-space walk (bounded; stops at wrap / unmapped-everywhere).
    const map = [];
    let at = 0n;
    while (at < 0x8000000000n && map.length < 1024) {
        const m = query(at);
        if (!m || m.size === 0n) break;
        map.push(m);
        const next = m.base + m.size;
        if (next <= at) break; // defensive: no forward progress
        at = next;
    }
    await log("dumper[B]: " + map.length + " regions total");

    // Log the interesting parts: executable regions and anything near the
    // two modules (keeps the log channel readable).
    for (const m of map) {
        const nearMod = (m.base + m.size > main_base - 0x2000000n && m.base < main_base + 0x2000000n) ||
                        (m.base + m.size > sdk_base - 0x2000000n && m.base < sdk_base + 0x2000000n);
        if ((m.perm & 4) || nearMod) {
            await log("dumper[B]: map " + hx(m.base) + " + " + hx(m.size) +
                      " type " + m.type + " perm " + m.perm);
        }
    }

    // Module extent: contiguous run of mapped regions starting at module base.
    const extent = (base, name) => {
        const regs = [];
        let cur = base;
        for (let i = 0; i < 64; i++) {
            const m = query(cur);
            if (!m || m.size === 0n || m.type === 0 || m.base !== cur) break;
            regs.push({ name: name + "_" + regs.length, base: m.base, size: m.size,
                        perm: m.perm, type: m.type });
            const next = m.base + m.size;
            if (next <= cur) break;
            cur = next;
        }
        return regs;
    };

    const regions = extent(sdk_base, "sdk").concat(extent(main_base, "main"));
    free(MI); free(PI); free(probe);
    if (!regions.length) throw new Error("dumper[B]: no module regions resolved");
    for (const rg of regions) {
        await log("dumper[B]: dump " + rg.name + " " + hx(rg.base) + " + " + hx(rg.size) +
                  " perm " + rg.perm);
    }
    return { mode: mode, regions: regions, map: map };
}

// ---------------------------------------------------------------- phase C --
function sendAll(fd, addr, len) {
    let off = 0n;
    let zeroStreak = 0;
    while (off < BigInt(len)) {
        const n = Number(sock.send(fd, addr + off, BigInt(len) - off, 0));
        if (n < 0) throw new Error("send failed errno " + n + " after " + off + " bytes");
        if (n === 0) {
            if (++zeroStreak > 64) throw new Error("send stalled");
            continue;
        }
        zeroStreak = 0;
        off += BigInt(n);
    }
}

async function phaseC(namedSvc, moduleMap) {
    const fd = sock.socket(2, 1, 0); // AF_INET, SOCK_STREAM
    if (fd === -1n) throw new Error("socket() failed");

    const sa = malloc(16);
    const ipBytes = HOST_IP.split(".").map(Number);
    writeBytes(sa, new Uint8Array(16));
    write8(sa, 16n);                 // sin_len
    write8(sa + 1n, 2n);             // sin_family = AF_INET
    write8(sa + 2n, BigInt((HOST_PORT >> 8) & 0xFF)); // sin_port, network order
    write8(sa + 3n, BigInt(HOST_PORT & 0xFF));
    write8(sa + 4n, BigInt(ipBytes[0]));
    write8(sa + 5n, BigInt(ipBytes[1]));
    write8(sa + 6n, BigInt(ipBytes[2]));
    write8(sa + 7n, BigInt(ipBytes[3]));

    const cr = sock.connect(fd, sa, 16);
    if (cr === -1n) {
        sock.close(fd);
        throw new Error("connect(" + HOST_IP + ":" + HOST_PORT + ") failed errno " + cr +
                        " — is dump_recv.py listening?");
    }
    await log("dumper[C]: connected to " + HOST_IP + ":" + HOST_PORT);

    // Regions: phase-B module extents when available, else the known-mapped
    // sdk scan range only.
    const regions = moduleMap ? moduleMap.regions :
        [{ name: "sdk_scan", base: sdk_base, size: BigInt(SCAN_LIMIT), perm: 5, type: 3 }];

    const header = {
        magic: "CIVDUMP1", version: 1, created: new Date().toISOString(),
        bases: { main: main_base.toString(16), sdk: sdk_base.toString(16) },
        scan_limit: SCAN_LIMIT, chunk: CHUNK,
        query_mode: moduleMap ? moduleMap.mode : 0,
        map: moduleMap ? moduleMap.map.map((m) => ({
            base: m.base.toString(16), size: m.size.toString(16),
            type: m.type, perm: m.perm
        })) : [],
        svc: {},
        svc_named: {},
        regions: regions.map((rg) => ({
            name: rg.name, base: rg.base.toString(16),
            size: rg.size.toString(16), perm: rg.perm, type: rg.type
        }))
    };
    for (const num of Object.keys(svcFindings.found)) {
        header.svc[Number(num)] = {
            sites: svcFindings.found[num].sites,
            entries: svcFindings.found[num].entries
        };
    }
    for (const name of Object.keys(namedSvc)) header.svc_named[name] = {
        num: namedSvc[name].num,
        entry: namedSvc[name].entry,
        site: namedSvc[name].site,
        count: namedSvc[name].count
    };

    const hb = text_encode(JSON.stringify(header));
    const hbuf = malloc(hb.length + 1);
    if (!hbuf) throw new Error("header alloc failed");
    writeNullTerm(hbuf, hb);

    // 8-byte magic + u32 LE header length + header bytes.
    const pre = new Uint8Array(12);
    pre.set(text_encode("CIVDUMP1"), 0);
    pre[8] = hb.length & 0xFF;        pre[9] = (hb.length >>> 8) & 0xFF;
    pre[10] = (hb.length >>> 16) & 0xFF; pre[11] = (hb.length >>> 24) & 0xFF;
    const prebuf = malloc(12);
    writeBytes(prebuf, pre);
    sendAll(fd, prebuf, 12);
    sendAll(fd, hbuf, hb.length);

    let total = 0;
    for (const rg of regions) {
        const chunks = Math.ceil(Number(rg.size) / CHUNK);
        for (let c = 0; c < chunks; c++) {
            const off = BigInt(c * CHUNK);
            const len = Number(rg.size - off) < CHUNK ? Number(rg.size - off) : CHUNK;
            sendAll(fd, rg.base + off, len);
            total += len;
            if ((c + 1) % DUMP_LOG_CHUNKS === 0 || c === chunks - 1) {
                await log("dumper[C]: " + rg.name + " chunk " + (c + 1) + "/" + chunks +
                          " (" + (total / 1048576).toFixed(1) + " MiB sent)");
            }
        }
    }

    const end = malloc(8);
    writeBytes(end, text_encode("CIVEND1\0"));
    sendAll(fd, end, 8);

    sock.close(fd);
    free(sa); free(prebuf); free(hbuf); free(end);
    await log("dumper[C]: dump complete, " + total + " bytes, " + regions.length + " regions");
}

// ------------------------------------------------------------------ main --
let svcFindings = { found: {}, named: {} };
try {
    await log("dumper: start, main=" + hx(main_base) + " sdk=" + hx(sdk_base) +
              " scan=" + hx(SCAN_LIMIT));
    svcFindings = await phaseA();

    for (const name of Object.keys(svcFindings.named)) {
        const n = svcFindings.named[name];
        await log("dumper[A]: " + name + " (svc " + hx(n.num) + ") entry=+" +
                  hx(n.entry) + " site=+" + hx(n.site) + " x" + n.count);
    }

    let moduleMap = null;
    try {
        moduleMap = await phaseB(svcFindings.named);
    } catch (e) {
        await log("dumper[B]: FAILED (" + e.message + ") — continuing with scan range");
    }

    await phaseC(svcFindings.named, moduleMap);
    await log("dumper: finished OK");
} catch (e) {
    await log("dumper: ERROR: " + e.message);
    await log(e.stack ? String(e.stack) : "");
}

})().catch(function (e) {
    // Outside the inner try (e.g. closure-scope check above): the loader also
    // catches and logs eval errors, but make sure it is visible either way.
    throw e;
});
