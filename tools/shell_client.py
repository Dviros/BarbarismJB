#!/usr/bin/env python3
"""shell_client.py - interactive readline client for the BarbarismJB shell (M5).

Purpose: connect to the BarbarismJB shell server (engine/lib/shell-server.cjs,
loopback TCP/JSON, started by `node run.cjs --shell [port] <console-ip>`),
provide a `barbarism> ` prompt with history, run `-c 'cmd; cmd'` scripts
headlessly, and render hex dumps readably. Python 3 stdlib only.

Protocol: one JSON request per line ({"line": "..."}), one JSON reply per
request: {"ok": true, "text": "...", ...} or {"ok": false, "code": "E_...",
"error": "..."}. The "exit" command replies {"ok": true, "exit": true} and the
server closes the connection.

Exit codes: 0 all commands ok (or interactive session ended cleanly); 1 a
command failed or the connection dropped mid-session; 2 usage error.
Origin: original - BarbarismJB M5. Docs: docs/SHELL.md.
"""

import argparse
import json
import os
import socket
import sys

PROMPT = "barbarism> "
RECV_CAP = 64 << 20  # one reply cap; hex dumps of 4 MiB reads stay well under
DEFAULT_HISTORY = os.path.expanduser("~/.barbarism_shell_history")


def fail(message, code=1):
    print(message, file=sys.stderr)
    raise SystemExit(code)


def connect(host, port, timeout=200.0):
    """One command connection for the whole session (the front serializes)."""
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(timeout)
    return sock


def send_command(sock, line):
    """Send one command line, read one JSON reply. Returns the reply object."""
    payload = json.dumps({"line": line}).encode("utf-8")
    sock.sendall(payload + b"\n")
    chunks = []
    total = 0
    while True:
        part = sock.recv(65536)
        if not part:
            raise ConnectionError("shell server closed the connection")
        total += len(part)
        if total > RECV_CAP:
            raise ConnectionError("reply exceeded the client receive cap")
        chunks.append(part)
        if part.endswith(b"\n"):
            break
    raw = b"".join(chunks).strip()
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        raise ConnectionError("shell server reply was not valid JSON") from None


def show(reply):
    """Print a reply: command text output, or the coded error."""
    if reply.get("ok"):
        text = reply.get("text", "")
        if text:
            print(text)
        return True
    print("error [%s]: %s" % (reply.get("code", "?"), reply.get("error", "")),
          file=sys.stderr)
    return False


def split_script(script):
    """Split on ';' outside quotes — mirrors the shell's tokenizer rules."""
    parts, current, quote = [], "", None
    for char in script:
        if quote:
            if char == quote:
                quote = None
            current += char
        elif char in "'\"":
            quote = char
            current += char
        elif char == ";":
            parts.append(current.strip())
            current = ""
        else:
            current += char
    if quote:
        raise ValueError("unterminated quote in -c script")
    if current.strip() or parts:
        parts.append(current.strip())
    return [part for part in parts if part]


def run_script(sock, commands):
    """Run a -c script sequentially; stop at the first failure."""
    for command in commands:
        reply = send_command(sock, command)
        ok = show(reply)
        if reply.get("exit"):
            return 0
        if not ok:
            return 1
    return 0


def repl(sock, history_path):
    """Interactive loop: prompt, history, Ctrl-D/'exit' to leave."""
    readline = None
    try:
        import readline as readline_module  # registers line editing on import
        readline = readline_module
        try:
            readline.read_history_file(history_path)
        except OSError:
            pass  # first run
    except ImportError:
        pass  # platforms without readline degrade to plain input()

    try:
        while True:
            try:
                line = input(PROMPT)
            except EOFError:
                print()
                break
            except KeyboardInterrupt:
                print()
                continue
            if not line.strip():
                continue
            if readline is not None:
                last = readline.get_current_history_length()
                if line != (readline.get_history_item(last) or ""):
                    readline.add_history(line)
            try:
                reply = send_command(sock, line)
            except (ConnectionError, OSError) as error:
                print("connection lost: %s" % error, file=sys.stderr)
                return 1
            show(reply)
            if reply.get("exit"):
                break
    finally:
        if readline is not None:
            try:
                readline.set_history_length(1000)
                readline.write_history_file(history_path)
            except OSError:
                pass
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="shell_client.py",
        description="BarbarismJB shell client (docs/SHELL.md). "
                    "The server is started by: node run.cjs --shell [port] <console-ip>.")
    parser.add_argument("--host", default="127.0.0.1",
                        help="shell server host (default 127.0.0.1; the server "
                             "binds loopback only)")
    parser.add_argument("--port", type=int, required=True, help="shell server port")
    parser.add_argument("-c", dest="script", metavar="'cmd; cmd'",
                        help="run a ;-separated script and exit (no prompt)")
    parser.add_argument("--history", default=DEFAULT_HISTORY,
                        help="history file (default %s)" % DEFAULT_HISTORY)
    parser.add_argument("--no-history", action="store_true",
                        help="do not read or write the history file")
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        fail("--port must be 1..65535", 2)
    history = os.devnull if args.no_history else args.history

    try:
        commands = split_script(args.script) if args.script is not None else None
        if args.script is not None and not commands:
            fail("-c script contained no commands", 2)
        sock = connect(args.host, args.port)
    except OSError as error:
        fail("cannot reach the shell server at %s:%d: %s" %
             (args.host, args.port, error), 1)
    except ValueError as error:
        fail(str(error), 2)

    try:
        if commands is not None:
            return run_script(sock, commands)
        return repl(sock, history)
    finally:
        sock.close()


if __name__ == "__main__":
    raise SystemExit(main())
