# The BarbarismJB shell (M5, v1 — host-driven)

Research date / build: 2026-11-10. Files:

| file | role |
|---|---|
| `engine/lib/shell.cjs` | the command interpreter (zero-dep, Node ≥ 22) |
| `engine/lib/shell-server.cjs` | loopback TCP/JSON front (serialized, 180 s, never-replay) |
| `tools/shell_client.py` | readline client (stdlib only) |
| `tests/shell-sim.cjs` | offline deterministic simulation (injected fakes, no console) |

This is **the first shell on Switch 2** — today's public ecosystem tops out at
FTP servers (OunceCake, ftpd-sb). Version 1 is deliberately **host-driven**:
every command executes on the host computer and fans out to one of the three
post-exploitation primitives the chain already holds. No new code runs on the
console. An autonomous on-console shell is the v2 milestone (§6).

---

## 1. Architecture — who executes what, and where the permissions live

```
┌ you ── tools/shell_client.py ──────────────────────────────────────────┐
│        127.0.0.1:<port>  (newline-delimited JSON)                      │
│  engine/lib/shell-server.cjs   serialized queue, one command in flight │
│  engine/lib/shell.cjs          dispatch + validation + coded errors    │
│        │                │                    │                         │
│   bridge            fsEndpoint            roClient                    │
│   (civshim)         (memory.sock          (ro:dmnt process server,    │
│    :39381 TCP        client)               0x524F0010–0x524F0016)     │
│        │                │                    │                         │
└────────┼────────────────┼────────────────────┼─────────────────────────┘
         ▼                ▼                    ▼
   Civ 7 game        fs sysmodule         RO payload sysmodule
   process           (ARW + PID→1         (KProcess handles to any
   (CALL/READ/        FullPermission       process we can name —
   WRITE/QUERY/       fsp-srv root)        the M7 loader primitive)
   ALLOC/FREE)
```

| subsystem | object injected into `new Shell(bridge, fsEndpoint, roClient, log)` | available after | permission it lends |
|---|---|---|---|
| bridge | `Civshim` from `engine/lib/bridge.cjs` | M1 (`--check` wiring) | the Civ 7 game process: memory R/W, alloc, calls |
| fsEndpoint | the client returned by `engine/switch2/tools/fs-memory.cjs` `connect()` (fronts the run-folder `memory.sock` controller, `engine/switch2/memory/fs-memory-control.cjs`) | `--stage acquire` (+ pid) | fs sysmodule memory, and the **PID→1 FullPermission fsp-srv root** (`root-info`, `root-probe-bis`, `root-read-bis`) |
| `fsEndpoint.files` | optional game-save file session (`list/stat/size/read/write/remove/mkdir/df`) | pending the Civ 7 port of `engine/switch2/app/mounted-save.cjs` (README "Pending Civ 7 ports") | the game's own `save:` mount |
| roClient | `Client` from `engine/switch2/process/client.cjs` (+ two wiring helpers, §4) | `--stage launch` | arbitrary processes via `ro:dmnt` 0x524F00xx: query (0x524F0010), read (0x524F0011/16), map RX (0x524F0012/13), patch (0x524F0014), perm toggle (0x524F0015) |

**Nothing is ever executed "as root" on the host.** The shell is a client of
primitives that already exist; the console-side authority lives where the
chain put it (game process ⇒ fs ⇒ PID 1 ⇒ RO payload), and each command
documents which of those it borrows.

### Path routing

| path form | routes to | v1 status |
|---|---|---|
| `/foo`, `save:/foo` | game save mount (`fsEndpoint.files`) | E_CONFIG until the mounted-save port lands (message says so) |
| `bis:<id>` | rejected in file commands — use `bis-ls` / `bis-get` (raw storage) | works today |
| unprefixed = `save:` | — | documented, tested |

---

## 2. Command reference

`help` prints this table grouped by providing stage. Addresses, lengths and
values accept decimal or `0x`-hex (BigInt-safe to 2^64).

### M1 bridge — civshim (game process memory)
| command | what it does |
|---|---|
| `query <addr>` | `svcQueryMemory` at addr → mapping base/size/type/perm |
| `read64 <addr>` / `write64 <addr> <val>` | one little-endian u64 (8-aligned) |
| `read <addr> <len>` | memory read + hex dump (len ≤ 0x10000; `dataHex` field carries raw bytes) |
| `write <addr> <hex>` | write hex bytes (≤ 0x10000, civshim-stream-chunked) |
| `malloc <size>` / `malloc` | game `calloc`; bare `malloc` lists live shell allocations |
| `free <addr>` | game `free` |

### --stage acquire — fs endpoint + PID 1 root
| command | what it does |
|---|---|
| `ls <path>` / `stat <path>` | list/stat on the routed file session (default `save:`) |
| `cat <path>` | print a file (≤ 0x40000; bigger → use `get`) |
| `put <local> <path>` / `get <path> <local>` | host↔console file transfer, 0x10000-byte chunks; `get` never clobbers, both verify sizes |
| `rm <path>` / `mkdir <path>` | delete / create on the routed session |
| `df` | free/total of every connected storage (save mount + probed BIS) |
| `save-ls <path>` / `save-get <path> <local>` / `save-put <local> <path>` | explicit `save:` route — the donor staging area; the XSTRIG.Civ7Save trigger under `save:/saves/` must be treated read-only |
| `bis-ls [id]` | BIS storage partitions (30 USER, 31 SYSTEM) with sizes — **partition level**; no FAT layer in v1 |
| `bis-get <id> <off> <len> <local>` | raw BIS storage range → host file (0x4000 chunks, per-chunk sha256 verified, id 30\|31) |
| `mount-info` | which subsystems are connected, handles, and what is missing |

### --stage launch — RO payload process server
| command | what it does |
|---|---|
| `ps` | process list via `roClient.processes()` (pm info + RO 0x524F0010 identity); without it, real session rows + an explicit note |
| `proc-read <pid> <addr> <len>` | read another process — RO 0x524F0016 (≤ 4 MiB, one receive window); falls back to 128 B-per-page 0x524F0011 chunks capped at 0x1000 when the wiring has no bulk helper |
| `proc-patch <pid> <addr> <hex16>` | patch exactly 16 bytes — RO 0x524F0014. The shell reads the current 16 bytes first and passes them as the primitive's **expected** value, so the payload's compare-and-swap + `dc cvau`/`ic ivau` publish + readback all stay armed; a racing change is E_VERIFY, not a blind overwrite |
| `exec-map <pid> <src> <dst>` | grant RX to one 0x1000-aligned RW page of the target at a free VA — RO 0x524F0012 (`map_code` + permission 5, rollback on failure). This is the M7 loader primitive: the host puts an image in the target's RW page, then flips it executable |

### always
| command | what it does |
|---|---|
| `help` / `exit` | reference / end the client session (the host-side run stays up) |

### Errors

Every failure carries a stable code from `engine/shared/errors.cjs`:

| code | meaning |
|---|---|
| `E_ARGS` | validation (bad hex, wrong arity, over-cap, unaligned) |
| `E_CONFIG` | subsystem not connected — the message names the stage/port that must run first (e.g. *no fs endpoint → run `--stage acquire`*; *no `files` session → pending mounted-save.cjs port*); the shell never crashes on a missing subsystem |
| `E_PROTOCOL` / `E_VERIFY` | wire-shape mismatch / round-trip, expected-bytes or sha256 mismatch |
| `E_TIMEOUT` / `E_TRANSPORT` | underlying client budget exceeded / socket path died (see §3) |
| `E_INTERNAL` | bug |

---

## 3. The server front and the client

`engine/lib/shell-server.cjs` follows `engine/lib/bridge.cjs` `serve()`
discipline exactly:

- **Loopback only.** Binds `127.0.0.1` (refuses anything else), ephemeral
  port by default.
- **No auth, by design.** Anything that can reach the port already owns the
  host machine and everything the shell can do; adding an auth theater layer
  would only suggest otherwise. Do not port-forward it.
- **Serialized queue.** One shell command in flight at a time across all
  clients — a native op must never interleave.
- **180 s per-command budget.** On timeout the requesting socket is destroyed
  **and the front is poisoned**: a native op may already have completed, so
  nothing is ever replayed — later commands fail fast with `E_TIMEOUT` and a
  restart hint instead of racing a possibly-live operation. Transport
  failures (`E_TRANSPORT`) poison identically.
- **Coded errors on the wire.** `{"ok":false,"code":"E_ARGS","error":"…"}`
  for every failure; uncoded errors surface as `E_INTERNAL`.

Protocol: one JSON request per line — `{"line":"read64 0x7100000000"}` — and
one JSON reply: `{"ok":true,"text":"…","dataHex":"…"}` or the coded error
above. `exit` replies `{"ok":true,"exit":true}` and closes that client.

`tools/shell_client.py` (stdlib, `readline` when available): prompt
`barbarism> `, persistent history (`~/.barbarism_shell_history`,
`--history`/`--no-history`), script mode `-c 'mount-info; ps; bis-ls'`
(stops at the first failing command), exit codes 0/1/2.

```
python3 tools/shell_client.py --port <port>                # interactive
python3 tools/shell_client.py --port <port> -c 'ps; mount-info; bis-ls'
```

---

## 4. Wiring contract — how `run.cjs --shell [port]` will mount it

(Flag surface intended for run.cjs; the wiring itself is done separately.)

```
node run.cjs --shell [port] [--stage …] <console-ip>
```

`--shell` keeps the run alive exactly like `--rpc` does today and, depending
on how far the stages got, constructs:

```js
const {Shell}   = require('./engine/lib/shell.cjs');
const {serve}   = require('./engine/lib/shell-server.cjs');
const {connect} = require('./engine/switch2/tools/fs-memory.cjs');
const {Client}  = require('./engine/switch2/process/client.cjs');

const bridge     = connectedRun.bridge.civshim;        // engine/lib/bridge.cjs serve()
const fsEndpoint = stageReached.acquire ? await connect() : null;   // memory.sock client
const roClient   = stageReached.launch ? await new Client().open() : null;
// two documented wiring helpers (this is the whole roClient surface the
// shell needs beyond the Client class itself):
if (roClient) {
  roClient.bulkRead = async (handle, pid, address, length) => {      // 0x524F0016
    const reply = await roClient.request(0x524f0016, handle,
      [pid, address, length, 0n]);        // worker stages a receive window at
    const bytes = /* bridge-read of the app-session receive buffer */ null;
    return {result: reply.result, bytes};
  };
  roClient.processHandle = async pid => /* 0xffff8001-style retained copy for
    the game pid, per engine/switch2/ro/export-handle.cjs */ 0xffff8001;
  roClient.processes = async () => /* pm:dmnt enumeration via
    root-native-ipc + RO 0x524F0010 identity, ro/runtime.cjs pattern */ [];
}
// optional, once the pending Civ 7 port of switch2/app/mounted-save.cjs lands:
// fsEndpoint.files = saveSessionAdapter(/* cloneMountedFilesystem + fsp-srv IFileSystem */);

const listener = await serve(new Shell(bridge, fsEndpoint, roClient, log), {port});
console.log('shell on 127.0.0.1:' + listener.port);
```

Contract details:

- `--shell` accepts an optional port (default: ephemeral, printed once);
  the listener is loopback-only by construction.
- Subsystems connect lazily per stage progress: `--shell` after `--check`
  gives bridge-only commands; after `--stage acquire` the fs/BIS family;
  after `--stage launch` the `proc-*`/`exec-map` family. Everything not yet
  connected returns `E_CONFIG` naming the stage — never a crash.
- `fsEndpoint.files` is attached only when a real save session exists; its
  adapter surface is the nine methods listed in `shell.cjs`'s header.
- `exit` ends one client session; the run (and the console session) stays up
  until the operator stops `run.cjs`, mirroring `--rpc` lifecycle semantics.

---

## 5. Security notes

1. **Loopback only, ever.** The shell server binds `127.0.0.1` and refuses
   other hosts. It is as powerful as the entire exploit chain; never expose
   it over LAN/SSH tunnels beyond the operating machine.
2. **Live-memory access.** `read`/`write`/`read64`/`write64`/`proc-*`/
   `exec-map` operate on **live process memory** of a running console. A
   wrong write can crash the game or the fs sysmodule; the engine's cleanup
   paths will not run for shell edits. `proc-patch` is compare-and-swap and
   readback-verified for exactly this reason — but it still patches live
   code.
3. **Never-replay.** A timed-out or transport-failed command may have
   completed natively. The front poisons itself rather than retrying
   (`E_TIMEOUT` fast-fail), matching the civshim bridge discipline
   (README.md "Transport discipline").
4. **No persistence, no hiding.** Like the rest of the chain, the shell is
   tethered and in-memory only; a console restart removes everything. It
   writes local files only where the operator names them (`get`, `bis-get`),
   never clobbers (`wx` open), and hashes everything it transfers.
5. **Same research scope as the rest of BarbarismJB** (README licensing):
   your own console, your own saves, your own dumps.

---

## 6. v2 sketch — autonomous on-console shell, and its open dependency

v2 moves the interpreter on-console: a Zig component inside the `ro` payload
(`engine/switch2/ro/payload/`), speaking the same command set over
`nn::socket` on the console's own NIC — a real shell that survives the host
disconnecting (still not a persistent install: it lives in the RO process
launched by the chain and dies on reboot).

Shape (per DESIGN.md §6 and the M7 planning in docs/HOMEBREW.md):

1. **Command loop in the payload** — reuse the existing 0x524F00xx process
   ops plus `nn::fs`/`nn::socket` imports resolved live by SysV hash
   (the IZ2S pattern, docs/HOMEBREW.md §1.3). The shell.cjs dispatch table
   and its validation/coded-error semantics port 1:1 as the wire contract.
2. **The host client stops being the executor** — `tools/shell_client.py`
   connects straight to the console; `shell-server.cjs` remains as an
   offline/batched path.
3. **Storage tiers** — `save:`/`rom:` in-process; BIS + CodeFS through the
   PID→1 root the payload already inherits (the OunceCake pattern).

**NPDM dependency — RESOLVED (docs/STATIC-VALIDATION.md):** the pinned `ro`
NPDM (program 0x0400000000000037, sha256 `f63138f1…98865de`, byte-identical to
this console's own) grants **zero filesystem permissions (FAC mask 0)** and its
SAC allows only `fatal:u`, `spl:`, `set:sys` — **no bsd:/socket access**. An
on-console `nn::socket`/`nn::fs` shell therefore CANNOT run under the donor NPDM
as-is; v2 needs either a different donor NPDM (any ordinary sysmodule whose
policy has the needed caps — a donor-swap research question) or must keep
routing network/fs through the inherited PID→1 channels the way v1 does. The M5
v1 host-driven shell needs no on-console sockets — and it is already strictly
more than the ecosystem's FTP servers (process query/patch/RX-map, fs memory,
BIS ranges).

---

## 7. Verification

```sh
node --check engine/lib/shell.cjs engine/lib/shell-server.cjs
node tests/shell-sim.cjs        # 100 checks, offline, deterministic
python3 -m py_compile tools/shell_client.py
```

`tests/shell-sim.cjs` injects recording fakes for all three subsystems (no
console, no real endpoint sockets; one in-process loopback socket exercises
the TCP front) and covers: full dispatch, E_ARGS validation, E_CONFIG
disconnected-subsystem behavior (message names the missing stage), memory
round-trips, exact hex-dump format, chunking (get/put at 0x10000, bis-get at
0x4000), sha256 verification, RO bulk/fallback reads, proc-patch CAS,
exec-map rollback, serialization order, timeout poisoning, and exit
semantics.
