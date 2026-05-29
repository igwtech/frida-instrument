/*
 * frida_re agent — runs INSIDE the Wine prefix as part of
 * frida-gadget.dll (renamed to a DLL the EXE imports).
 *
 * The orchestrator pushes this script after attaching. A preamble
 * injected by the orchestrator sets:
 *
 *   globalThis.__FRIDA_RE_HOOKS__ = [
 *     { name: "udp_cipher_a", offset: 0x160090, purpose: "..." },
 *     ...
 *   ]
 *
 * (the canonical table lives in orchestrator/symbols.py).
 *
 * Responsibilities:
 *   1. Resolve neocronclient.exe module base.
 *   2. Install Interceptor hooks for each entry in the hook table.
 *      The dispatch table below maps hook name -> handler factory.
 *   3. Expose rpc.exports for control:
 *        - getStatus()
 *        - readMem(addr, n)        ->  number[]
 *        - writeMem(addr, bytes[]) ->  number  (bytes written)
 *        - callFunction(addr, args[], retType?)  -> any
 *        - sendUdp(bytes[])        ->  number  (bytes sent post-cipher)
 *
 * Events emitted via send():
 *   { ev: "ready", base: "0x...", hooks: [...] }
 *   { ev: "cipher_enter" | "cipher_leave", hook, seed_lo, seed_hi,
 *     buf_hex, buf_len, tid, ts }
 *   { ev: "hook_error", hook, error }
 */

'use strict';

// ---------------------------------------------------------------------
// Configuration / utility
// ---------------------------------------------------------------------

const MODULE_NAME = 'NeocronClient.exe';

/** Convert a NativePointer-backed buffer to a hex string preview.
 *  The agent never dumps more than DUMP_LIMIT bytes per event to keep
 *  the send() channel from being saturated by huge payloads.
 */
const DUMP_LIMIT = 128;

function bufHex(addr, len) {
    if (addr.isNull() || len === 0) return '';
    const n = Math.min(len, DUMP_LIMIT);
    let bytes;
    try {
        bytes = new Uint8Array(addr.readByteArray(n));
    } catch (e) {
        return `<read-failed:${e.message}>`;
    }
    const parts = new Array(bytes.length);
    for (let i = 0; i < bytes.length; ++i) {
        parts[i] = (bytes[i] < 16 ? '0' : '') + bytes[i].toString(16);
    }
    return parts.join(' ');
}

function nowNs() {
    // Frida exposes a hrtime via the QuickJS runtime; fall back to
    // ms*1e6 if not present (older Frida builds).
    const ms = Date.now();
    return Math.floor(ms * 1e6);
}

/** Resolve the PE module base. Returns null if not loaded yet. */
function findModule() {
    const m = Process.findModuleByName(MODULE_NAME);
    if (m !== null) return m;
    // Case-insensitive fallback — Wine sometimes presents lowercase.
    const all = Process.enumerateModules();
    for (const mod of all) {
        if (mod.name.toLowerCase() === MODULE_NAME.toLowerCase()) {
            return mod;
        }
    }
    return null;
}

// ---------------------------------------------------------------------
// Hook factories
// ---------------------------------------------------------------------
//
// One entry per name registered in orchestrator/symbols.py. Factory
// returns the InterceptorCallback object passed to Interceptor.attach.
//
// First-iteration handlers for the UDP cipher dump:
//   - args[0] (ECX/EAX/stack[0]) is *almost certainly* a pointer to
//     the buffer to (en|de)crypt; we don't know the exact ABI without
//     a control-flow trace, so we read both ESP+4 .. ESP+12 (cdecl)
//     and pass them along as raw register snapshots. Once we see one
//     packet decoded we'll lock the signature.
//   - The buffer's first 2 bytes on the wire are the per-packet LFSR
//     seed (seed_lo, seed_hi); we surface them from the buffer head
//     so the orchestrator can correlate enter/leave by seed.
//

function cipherHandler(hookName) {
    return {
        onEnter(args) {
            try {
                // Heuristic: try args[0] as a pointer first.
                const pBuf = args[0];
                const ctx = this.context;
                const len = (args[1] !== undefined)
                    ? args[1].toInt32() & 0xffff : 0;
                let seedLo = 0, seedHi = 0;
                let hex = '';
                if (pBuf !== undefined && !pBuf.isNull()) {
                    try {
                        const head = new Uint8Array(pBuf.readByteArray(
                            Math.min(2, len > 0 ? len : 2)));
                        if (head.length >= 1) seedLo = head[0];
                        if (head.length >= 2) seedHi = head[1];
                    } catch (_) { /* fall through */ }
                    hex = bufHex(pBuf, len > 0 ? len : DUMP_LIMIT);
                }
                this._pBuf = pBuf;
                this._len = len;
                send({
                    ev: 'cipher_enter',
                    hook: hookName,
                    seed_lo: seedLo,
                    seed_hi: seedHi,
                    buf_hex: hex,
                    buf_len: len,
                    eax: ctx.eax !== undefined
                        ? '0x' + ctx.eax.toString(16) : null,
                    ecx: ctx.ecx !== undefined
                        ? '0x' + ctx.ecx.toString(16) : null,
                    tid: this.threadId,
                    ts: nowNs(),
                });
            } catch (e) {
                send({ ev: 'hook_error', hook: hookName,
                       phase: 'enter', error: String(e) });
            }
        },
        onLeave(retval) {
            try {
                const pBuf = this._pBuf;
                const len = this._len;
                let seedLo = 0, seedHi = 0;
                let hex = '';
                if (pBuf !== undefined && !pBuf.isNull()) {
                    try {
                        const head = new Uint8Array(pBuf.readByteArray(
                            Math.min(2, len > 0 ? len : 2)));
                        if (head.length >= 1) seedLo = head[0];
                        if (head.length >= 2) seedHi = head[1];
                    } catch (_) { /* fall through */ }
                    hex = bufHex(pBuf, len > 0 ? len : DUMP_LIMIT);
                }
                send({
                    ev: 'cipher_leave',
                    hook: hookName,
                    seed_lo: seedLo,
                    seed_hi: seedHi,
                    buf_hex: hex,
                    buf_len: len,
                    retval: retval !== undefined && !retval.isNull()
                        ? '0x' + retval.toString(16) : null,
                    tid: this.threadId,
                    ts: nowNs(),
                });
            } catch (e) {
                send({ ev: 'hook_error', hook: hookName,
                       phase: 'leave', error: String(e) });
            }
        }
    };
}

// ── Winsock UDP capture handlers ─────────────────────────────────────
//
// recvfrom prototype:
//   int recvfrom(SOCKET s, char* buf, int len, int flags,
//                sockaddr* from, int* fromlen)
// onLeave: retval is bytes_read (-1 on error, 0 on graceful close).
// We dump exactly retval bytes from the buf pointer captured onEnter.
//
// sendto prototype:
//   int sendto(SOCKET s, const char* buf, int len, int flags,
//              const sockaddr* to, int tolen)
// onEnter: dump exactly `len` bytes from buf. Truncated at DUMP_LIMIT
// to keep the send() channel sane on jumbo packets.

function udpRecvHandler() {
    return {
        onEnter(args) {
            this._sock = args[0].toInt32();
            this._buf  = args[1];
        },
        onLeave(retval) {
            try {
                const n = retval.toInt32();
                if (n <= 0) return;
                send({
                    ev: 'udp_recv',
                    sock: this._sock,
                    len: n,
                    hex: bufHex(this._buf, Math.min(n, DUMP_LIMIT)),
                    tid: this.threadId,
                    ts: nowNs(),
                });
            } catch (e) {
                send({ ev: 'hook_error', hook: 'udp_recv',
                       phase: 'leave', error: String(e) });
            }
        },
    };
}

function udpSendHandler() {
    return {
        onEnter(args) {
            try {
                const sock = args[0].toInt32();
                const len  = args[2].toInt32();
                if (len <= 0 || len > 0x10000) return;
                send({
                    ev: 'udp_send',
                    sock: sock,
                    len: len,
                    hex: bufHex(args[1], Math.min(len, DUMP_LIMIT)),
                    tid: this.threadId,
                    ts: nowNs(),
                });
            } catch (e) {
                send({ ev: 'hook_error', hook: 'udp_send',
                       phase: 'enter', error: String(e) });
            }
        },
    };
}

// Map from hook-name to a factory. Adding a new hook == adding it to
// orchestrator/symbols.py (with implemented=true) AND registering it
// here. Legacy in-EXE-offset hooks (udp_cipher_a/b) used cipherHandler
// — kept available for future use even though the canonical path is
// now Winsock-based.
const HOOK_FACTORIES = {
    udp_recv: udpRecvHandler,
    udp_send: udpSendHandler,
    udp_cipher_a: cipherHandler,
    udp_cipher_b: cipherHandler,
};

// ---------------------------------------------------------------------
// Installation
// ---------------------------------------------------------------------

const HOOK_TABLE = globalThis.__FRIDA_RE_HOOKS__ || [];
const INSTALLED = [];

function resolveHookAddress(entry, moduleBase) {
    if (entry.mode === 'export') {
        const mod = Process.findModuleByName(entry.module)
                 || Process.findModuleByName(entry.module.toUpperCase());
        if (mod === null) {
            throw new Error(`module not loaded: ${entry.module}`);
        }
        const addr = mod.findExportByName(entry.symbol);
        if (addr === null) {
            throw new Error(`export not found: ${entry.module}!${entry.symbol}`);
        }
        return addr;
    }
    if (entry.mode === 'offset' || entry.offset !== undefined) {
        if (moduleBase === null) {
            throw new Error(`${MODULE_NAME} not loaded — cannot resolve offset`);
        }
        return moduleBase.add(entry.offset);
    }
    throw new Error(`unknown hook mode: ${entry.mode}`);
}

function installHooks(moduleBase) {
    for (const entry of HOOK_TABLE) {
        const factory = HOOK_FACTORIES[entry.name];
        if (factory === undefined) {
            send({ ev: 'hook_error', hook: entry.name,
                   phase: 'install',
                   error: 'no factory registered in agent JS' });
            continue;
        }
        let addr;
        try {
            addr = resolveHookAddress(entry, moduleBase);
        } catch (e) {
            send({ ev: 'hook_error', hook: entry.name,
                   phase: 'resolve', error: String(e) });
            continue;
        }
        try {
            const listener = Interceptor.attach(addr, factory(entry.name));
            INSTALLED.push({ name: entry.name, addr: addr,
                             listener: listener });
        } catch (e) {
            send({ ev: 'hook_error', hook: entry.name,
                   phase: 'install', error: String(e) });
        }
    }
}

const mod = findModule();
if (mod === null) {
    send({ ev: 'ready',
           module: MODULE_NAME, base: null,
           hooks: [],
           error: 'module not loaded yet; agent will idle until first '
                + 'RPC call retries resolution' });
} else {
    installHooks(mod.base);
    send({
        ev: 'ready',
        module: MODULE_NAME,
        base: '0x' + mod.base.toString(16),
        hooks: INSTALLED.map(h => ({
            name: h.name,
            addr: '0x' + h.addr.toString(16),
        })),
    });
}

// ---------------------------------------------------------------------
// RPC surface (control)
// ---------------------------------------------------------------------

function ensureModule() {
    const m = findModule();
    if (m === null) {
        throw new Error('NeocronClient.exe not loaded');
    }
    return m;
}

rpc.exports = {

    // Status / introspection
    getStatus() {
        const m = findModule();
        return {
            module: MODULE_NAME,
            base: m === null ? null : '0x' + m.base.toString(16),
            installed: INSTALLED.map(h => ({
                name: h.name,
                addr: '0x' + h.addr.toString(16),
            })),
            hookTable: HOOK_TABLE,
            frida: Frida.version,
            arch: Process.arch,
            pageSize: Process.pageSize,
        };
    },

    // Memory I/O
    readMem(addr, n) {
        const p = ptr(addr);
        const bytes = new Uint8Array(p.readByteArray(n));
        // Frida marshals typed arrays as plain arrays of ints to
        // Python, which is what we want for the JSONL.
        return Array.from(bytes);
    },

    writeMem(addr, bytes) {
        const p = ptr(addr);
        p.writeByteArray(bytes);
        return bytes.length;
    },

    // Generic function invocation. ``argTypes`` defaults to all
    // 'pointer' (which under x86-32 is just an int passed by value);
    // callers that need ints/floats supply types explicitly.
    callFunction(addr, args, retType, argTypes) {
        ensureModule();
        const types = argTypes || args.map(() => 'pointer');
        const ret = retType || 'pointer';
        const fn = new NativeFunction(ptr(addr), ret, types);
        const native = args.map((a, i) => {
            if (types[i] === 'pointer') return ptr(a);
            return a;
        });
        const result = fn.apply(null, native);
        if (ret === 'pointer') return '0x' + result.toString(16);
        return result;
    },

    // High-level helper that goes through the (still-unconfirmed)
    // cipher path so the client's Winsock layer sees an encrypted
    // datagram identical to what the game would send. Until we
    // pin both arg signatures, this is a placeholder that returns
    // -1 and surfaces a hook_error event.
    sendUdp(_bytes) {
        send({ ev: 'hook_error', hook: 'sendUdp',
               phase: 'rpc',
               error: 'sendUdp not yet wired — pin cipher signature first' });
        return -1;
    },
};
