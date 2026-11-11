// engine/shared/frames.cjs — worker-frame compilers: build() (legacy
// SmileBASIC SDK worker frames, byte-for-byte ns2jb) and buildRop() (the
// BarbarismJB ropchain backend, DESIGN.md section 4).
//
// Purpose: compile a worker's logical call list into a self-contained buffer
// (dispatch tables / ROP chain + forged jmp_buf + SENTINEL result slots) that
// a single THREAD_CREATE lands on via longjmp. Docs: DESIGN.md section 4,
// README.md "Engine adaptation points" (native-worker entry).
// Origin: build() ported verbatim from ns2jb engine/shared/frames.cjs;
// buildRop() original — BarbarismJB.
const PAGE = 4096;
const STEP = 0x140;
const RESULT = 0x800;
const SDK_SIZE = 0x5e1000;
const SENTINEL = 0xfedcba9876543210n;
const align = value => Math.ceil(value / PAGE) * PAGE;

// Each call uses a table entry and a saved register frame. Dynamic arguments
// are loaded by preceding memcpy calls, using the same checked SDK functions.
function build(base, sdk, calls, code, fixed = false) {
  if (base % PAGE || sdk % PAGE || calls.length < 1 || calls.length > (fixed ? 96 : 32768))
    throw Error('Invalid worker address or call count');
  const expanded = [], logicalResultIndices = [], patches = [];
  for (const call of calls) {
    if (call.args.length !== 4) throw Error('Workers require exactly four arguments');
    const loads = [];
    call.args.forEach((argument, index) => {
      if (typeof argument !== 'object') return;
      if (fixed || !argument || Object.keys(argument).join() !== 'u32' ||
          !Number.isSafeInteger(argument.u32) || argument.u32 <= 0 || argument.u32 % 4)
        throw Error('Dynamic arguments require an aligned u32 address');
      loads.push({load: expanded.length, argument: index});
      expanded.push({function: sdk + 0x586fb0, args: [0, argument.u32, 4, 0]});
    });
    const target = expanded.length;
    patches.push(...loads.map(load => ({...load, target})));
    logicalResultIndices.push(target);
    expanded.push({...call, args: call.args.map(value => typeof value === 'object' ? 0 : value)});
  }
  const count = expanded.length;
  const tables = fixed ? 0x1000 : align(RESULT + count * 8);
  const stack = fixed ? 0x28000 : align(tables + count * 0x100) + 0x10000;
  const size = fixed ? 0x30000 : align(stack + count * STEP + 0x4000);
  if (size > 0x2000000 || RESULT + count * 8 > tables || tables + count * 0x100 > stack || stack + count * STEP > size)
    throw Error('Worker regions overlap or exceed the allocation');
  for (const {load, target, argument} of patches) {
    const slot = argument === 0 ? (target === 0 ? 0x30 : stack + (target - 1) * STEP + 0xe8)
      : stack + target * STEP + [0, 0x10, 0x20, 0x28][argument];
    expanded[load].args[0] = base + slot;
  }
  const frame = Buffer.alloc(size);
  function put(offset, value) {
    const word = BigInt(value);
    if (word < 0n || word > 0xffffffffffffffffn) throw Error('Worker word is outside uint64');
    frame.writeBigUInt64LE(word, offset);
  }
  put(0x10, base + tables); // x21: first dispatch table
  put(0x30, expanded[0].args[0]); // x25: first call's x0
  put(0x58, sdk + code.loadTable.offset);
  put(0x68, base + stack);
  expanded.forEach((call, index) => {
    if (!Number.isSafeInteger(call.function) || call.function % 4 ||
        call.function < sdk || call.function >= sdk + SDK_SIZE)
      throw Error('Worker function is outside the qualified SDK');
    const table = tables + index * 0x100, sp = stack + index * STEP;
    put(table, base + table + 0x10);
    put(table + 0x78, call.function);
    put(RESULT + index * 8, SENTINEL);
    put(sp + 8, sdk + code.call4.offset);
    [0x10, 0x20, 0x28].forEach((offset, argument) => put(sp + offset, call.args[argument + 1]));
    put(sp + 0xd8, sdk + code.saveResult64.offset);
    put(sp + 0x118, base + RESULT + index * 8);
    if (index + 1 < count) {
      put(sp + 0x108, base + tables + (index + 1) * 0x100);
      put(sp + 0xe8, expanded[index + 1].args[0]);
      put(sp + 0x128, sdk + code.loadTable.offset);
    } else put(sp + 0x128, sdk + code.exit.offset);
  });
  return {frame, proof: {bytes: size, logicalCalls: calls.length, nativeCalls: count,
    resultOffsets: expanded.map((_, index) => RESULT + index * 8), logicalResultIndices,
    resultOffset: RESULT + (count - 1) * 8, stackOffset: stack, tablesOffset: tables}};
}

// barbarism: ROP-chain worker backend for the Civ 7 host (DESIGN.md section 4).
// The legacy build() above compiles SmileBASIC SDK worker frames; this compiles
// the same logical call list into a linear ROP chain plus a forged jmp_buf.
// THREAD_CREATE starts the thread at pthread_create(&t, NULL, longjmp, jb) and
// longjmp lands directly on the chain — no stack pivot needed because the
// jmp_buf restores sp and pc itself.
//
// Gadget contract (offsets/civ7-100.json gadgets.*, MAIN-module-relative; the
// five default values are CivSwitch core.js's proven call_rop gadgets for this
// exact build — engine/lib/offsets.cjs resolves them to absolute addresses):
//   args_loader    ldp x2,x3,[sp,#0x10]; ldp x0,x1,[sp],#0x20; ldp x4,x5,[sp],#0x10;
//                  mov sp,x29; ldp x29,x30,[sp],#0x10; ret
//   frame_ldp      ldp x20,x19,[sp,#0x10]; ldp x29,x30,[sp],#0x20; ret
//   indirect_call  ldr x8,[x20]; ldp x20,x19,[sp,#0x20]; ldp x22,x21,[sp,#0x10];
//                  ldr x6,[x8,#0x18]; ldp x29,x30,[sp],#0x30; br x6
//   load_x21       ldr x21,[sp,#0x10]; ldp x29,x30,[sp],#0x30; ret
//   store_result   str x0,[x21]; ldp x30,x21,[sp],#0x20; ret
// Per call i (stride 0xE0): args_loader sets x0..x5 from [C+0x10..0x38] and
// pivots to x29=C+0x40; frame_ldp loads x20=C+0x60 (pointer chain) and chains
// to indirect_call at C+0x58; indirect_call branches to the function through
// the host-built cell { [P]=cell, [cell+0x18]=fn } with the function's return
// address set to load_x21 (C+0x78); load_x21 picks up x21=C+0xB0 (result slot)
// and chains to store_result (C+0xA8) which saves x0 there and continues at
// C+0xD0 = the next call's args_loader. The final entry is a pthread_exit tail
// whose result slot is never written (it never returns), so it is excluded
// from the validated resultOffsets.
const ROP_FRAME_STRIDE = 0xe0;
const ROP_CELL_STRIDE = 0x28; // 8-byte pointer slot + 0x20-byte call cell

function buildRop(base, live, calls, jmpBuf, gadgets) {
  if (base % 4096 || calls.length < 1 || calls.length > 32768)
    throw Error('Invalid ropchain worker address or call count');
  for (const name of ['args_loader', 'frame_ldp', 'indirect_call', 'load_x21', 'store_result'])
    if (!Number.isSafeInteger(gadgets?.[name]) || gadgets[name] < 0x10000 || gadgets[name] % 4)
      throw Error('ropchain worker backend lacks gadget: ' + name +
        ' (fill gadgets.' + name + ' in offsets/civ7-100.json, main-module-relative)');
  if (!live.sdkFn?.memcpy) throw Error('ropchain dynamic arguments need sdk_offsets.memcpy');
  if (!live.sdkFn?.pthread_exit) throw Error('ropchain tail needs sdk_offsets.pthread_exit');
  if (!jmpBuf?.fields || !Number.isInteger(jmpBuf.size))
    throw Error('ropchain needs a parsed jmp_buf layout (offsets/civ7-100.json jmp_buf)');
  const sdkBytes = live.sdkSize || 0x8000000;

  // Same expansion as build(): dynamic {u32} arguments become preceding memcpy
  // calls that load the value into the frame's argument slot at run time.
  const expanded = [], logicalResultIndices = [], patches = [];
  for (const call of calls) {
    if (call.args.length !== 4) throw Error('Workers require exactly four arguments');
    const loads = [];
    call.args.forEach((argument, index) => {
      if (typeof argument !== 'object') return;
      if (!argument || Object.keys(argument).join() !== 'u32' ||
          !Number.isSafeInteger(argument.u32) || argument.u32 <= 0 || argument.u32 % 4)
        throw Error('Dynamic arguments require an aligned u32 address');
      loads.push({load: expanded.length, argument: index});
      expanded.push({function: live.sdkFn.memcpy, args: [0, argument.u32, 4, 0]});
    });
    const target = expanded.length;
    patches.push(...loads.map(load => ({...load, target})));
    logicalResultIndices.push(target);
    expanded.push({...call, args: call.args.map(value => typeof value === 'object' ? 0 : value)});
  }
  const count = expanded.length;               // real calls (incl. memcpy loads)
  const total = count + 1;                     // + pthread_exit tail
  const framesOffset = 0x1000;
  const resultsOffset = 0x200;
  const cellsOffset = framesOffset + total * ROP_FRAME_STRIDE;
  const size = cellsOffset + total * ROP_CELL_STRIDE;
  if (size > 0x2000000) throw Error('Ropchain worker exceeds the size bound');
  if (resultsOffset + total * 8 > framesOffset) throw Error('Ropchain results overlap the frames');
  if (jmpBuf.size > resultsOffset) throw Error('jmp_buf.size exceeds the ropchain header area');

  const frame = Buffer.alloc(size);
  const put = (offset, value) => {
    const word = BigInt(value);
    if (word < 0n || word > 0xffffffffffffffffn) throw Error('Worker word is outside uint64');
    frame.writeBigUInt64LE(word, offset);
  };
  const frameAt = index => framesOffset + index * ROP_FRAME_STRIDE;
  const cellAt = index => cellsOffset + index * ROP_CELL_STRIDE;

  for (const {load, target, argument} of patches)
    expanded[load].args[0] = base + frameAt(target) + 0x10 + 8 * argument;

  expanded.forEach((call, index) => {
    if (!Number.isSafeInteger(call.function) || call.function % 4 ||
        call.function < live.sdk || call.function >= live.sdk + sdkBytes)
      throw Error('Worker function is outside the qualified SDK range: 0x' +
        (call.function || 0).toString(16) + ' (' + (call.name || 'unnamed') + ')');
    const at = frameAt(index), next = frameAt(index + 1);
    put(at + 0x10, call.args[0]); put(at + 0x18, call.args[1]);
    put(at + 0x20, call.args[2]); put(at + 0x28, call.args[3]);
    put(at + 0x30, 0); put(at + 0x38, 0);          // x4/x5 stay zero
    put(at + 0x40, 0);                              // frame_ldp x29 (unused)
    put(at + 0x48, gadgets.frame_ldp);
    put(at + 0x50, 0);                              // indirect_call x29 (unused)
    put(at + 0x58, gadgets.indirect_call);
    put(at + 0x60, base + cellAt(index));           // x20 -> pointer chain
    put(at + 0x68, 0);                              // indirect_call x19
    put(at + 0x70, base + next + 0x40);             // next args_loader x29
    put(at + 0x78, gadgets.load_x21);               // function return address
    put(at + 0x80, 0); put(at + 0x88, 0);           // x22/x21 restored zero
    put(at + 0x90, 0); put(at + 0x98, 0);           // x20/x19 restored zero
    put(at + 0xa0, base + next + 0x40);             // load_x21 x29 (chained pivot)
    put(at + 0xa8, gadgets.store_result);
    put(at + 0xb0, base + resultsOffset + 8 * index); // x21 = result slot
    put(at + 0xd0, gadgets.args_loader);            // continue into the next call
    // Pointer chain P: [P] = P+8 (the cell), and the function pointer goes at
    // P+0x20 = cell+0x18, which is where indirect_call's `ldr x6,[x8,#0x18]`
    // reads it (x8 = P+8).
    put(cellAt(index), base + cellAt(index) + 8);   // [P] = cell
    put(cellAt(index) + 0x20, call.function);       // [cell + 0x18] = fn
  });
  // pthread_exit tail (index = count): never returns, so its result slot is
  // the dummy one at resultsOffset + 8*count and is excluded below.
  const tail = frameAt(count);
  put(tail + 0x10, 0); put(tail + 0x18, 0); put(tail + 0x20, 0); put(tail + 0x28, 0);
  put(tail + 0x30, 0); put(tail + 0x38, 0);
  put(tail + 0x40, 0);
  put(tail + 0x48, gadgets.frame_ldp);
  put(tail + 0x50, 0);
  put(tail + 0x58, gadgets.indirect_call);
  put(tail + 0x60, base + cellAt(count));
  put(tail + 0x68, 0);
  put(cellAt(count), base + cellAt(count) + 8);
  put(cellAt(count) + 0x20, live.sdkFn.pthread_exit);

  // Forged jmp_buf: land on args_loader of call 0 with sp on the first frame's
  // argument block. Every field the layout names is written (zero unless set)
  // so an unexpected longjmp consumer still sees a consistent buffer. x29 must
  // be a named field: args_loader pivots through it (mov sp, x29).
  if (jmpBuf.fields.x29 === undefined)
    throw Error('jmp_buf.layout must name x29 for the ropchain backend (args_loader pivots via x29)');
  for (const offset of Object.values(jmpBuf.fields).sort((a, b) => a - b))
    put(offset, 0);
  put(jmpBuf.fields.pc, gadgets.args_loader);
  put(jmpBuf.fields.sp, base + frameAt(0) + 0x10);
  put(jmpBuf.fields.x29, base + frameAt(0) + 0x40);

  for (let index = 0; index < total; index++) put(resultsOffset + 8 * index, SENTINEL);

  return {frame, proof: {bytes: size, logicalCalls: calls.length, nativeCalls: count,
    resultOffsets: expanded.map((_, index) => resultsOffset + 8 * index), logicalResultIndices,
    resultOffset: resultsOffset + 8 * (count - 1), tailResultOffset: resultsOffset + 8 * count,
    framesOffset, cellsOffset, resultsOffset, frameStride: ROP_FRAME_STRIDE,
    cellStride: ROP_CELL_STRIDE, backend: 'ropchain'}};
}

module.exports = {build, buildRop, SENTINEL};
