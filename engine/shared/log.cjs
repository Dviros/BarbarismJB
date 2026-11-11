// engine/shared/log.cjs — zero-dependency leveled, tagged logger.
//
// Usage:
//   const {createLog} = require('<root>/engine/shared/log.cjs');
//   const log = createLog('bridge');
//   log.info('listening on %d', port);   // -> [bridge][INFO] listening on 39381
//
// Level selection: BARBARISM_LOG env (silent|error|warn|info|debug),
// default 'info'. debug/info print to stdout; warn/error to stderr — so
// piping stdout still yields a clean transcript while diagnostics stay
// visible. util.format-style placeholders are supported.
//
// Console payloads (payloads/*.js) do NOT use this module — they run inside
// the CivSwitch loader closure and keep the loader's window.log mirroring.
//
// Origin: original — BarbarismJB 0.1.0.
const util = require('node:util');

const LEVELS = {silent: 0, error: 1, warn: 2, info: 3, debug: 4};

function levelFromEnv(value = process.env.BARBARISM_LOG) {
  const level = LEVELS[value] === undefined ? 'info' : value;
  return LEVELS[level];
}

function createLog(tag, {level = levelFromEnv(), out = process.stdout, err = process.stderr} = {}) {
  const emit = (stream, name, args) => {
    if (LEVELS[name] > level) return;
    stream.write('[' + tag + '][' + name.toUpperCase() + '] ' + util.format(...args) + '\n');
  };
  return {
    debug: (...args) => emit(out, 'debug', args),
    info: (...args) => emit(out, 'info', args),
    warn: (...args) => emit(err, 'warn', args),
    error: (...args) => emit(err, 'error', args)
  };
}

module.exports = {createLog, LEVELS, levelFromEnv};
