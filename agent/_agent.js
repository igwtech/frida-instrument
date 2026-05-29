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

// ── TCP capture (NC2 doesn't use ws2_32 recv/send/WSARecv/WSASend) ──
//
// 2026-05-28: hooked all four ws2_32 stream-socket APIs during live
// gameplay, captured zero TCP frames in 20s. NC2 must be reaching
// the socket via a deeper API. Three candidates worth hooking, in
// order of likelihood:
//   1. ntdll!NtDeviceIoControlFile with AFD IOCTL codes (the
//      lowest user-mode socket I/O on Windows / Wine).
//   2. kernel32!ReadFile / WriteFile on the socket handle (some
//      games route through these when overlapped I/O is in use).
//
// We hook all three. Filter on the orchestrator side by content:
// NC2 TCP frames start with the byte 0xfe (FE-framing marker), so
// any chunk where the first byte is 0xfe is interesting.

function tcpReadFileHandler() {
    return {
        onEnter(args) {
            this._handle = args[0];
            this._buf    = args[1];
        },
        onLeave(retval) {
            // ReadFile returns BOOL — but the actual bytes-read is in
            // the lpNumberOfBytesRead OUT param (args[3] on x86).
            try {
                // We don't have args here in onLeave; use captured this.
                // Heuristic: read the first 256 bytes from buf and emit
                // if it looks like an FE-framed packet.
                const head = new Uint8Array(this._buf.readByteArray(256));
                if (head.length >= 3 && head[0] === 0xfe) {
                    const size = head[1] | (head[2] << 8);
                    send({
                        ev: 'tcp_read',
                        handle: '0x' + this._handle.toString(16),
                        hex: bufHex(this._buf, Math.min(size + 3, DUMP_LIMIT)),
                        ts: nowNs(),
                    });
                }
            } catch (e) { /* not a readable buffer */ }
        },
    };
}

function tcpWriteFileHandler() {
    return {
        onEnter(args) {
            const handle = args[0];
            const buf = args[1];
            const len = args[2].toInt32();
            if (len <= 0 || len > 0x10000) return;
            try {
                const head = new Uint8Array(buf.readByteArray(Math.min(len, 3)));
                if (head.length >= 1 && head[0] === 0xfe) {
                    send({
                        ev: 'tcp_write',
                        handle: '0x' + handle.toString(16),
                        len: len,
                        hex: bufHex(buf, Math.min(len, DUMP_LIMIT)),
                        ts: nowNs(),
                    });
                }
            } catch (e) { /* skip */ }
        },
    };
}

// Wine maps NtDeviceIoControlFile via the AFD driver. AFD IOCTL codes
// for socket recv = 0x12017, send = 0x1201f. Newer Wine variants may
// route differently — we accept all IOCTLs and let the orchestrator
// filter.
function tcpIoctlHandler() {
    return {
        onEnter(args) {
            const handle = args[0];
            const ioctl = args[5].toInt32();
            const inBuf = args[6];
            const inLen = args[7].toInt32();
            const outBuf = args[8];
            const outLen = args[9].toInt32();
            // Only emit on plausible buffer sizes.
            this._handle = handle;
            this._ioctl  = ioctl;
            this._inBuf  = inBuf;
            this._inLen  = inLen;
            this._outBuf = outBuf;
            this._outLen = outLen;
        },
        onLeave(retval) {
            try {
                let hex = '';
                let kind = '?';
                if (this._inLen > 0 && this._inLen < 0x10000) {
                    const probe = new Uint8Array(
                        this._inBuf.readByteArray(Math.min(3, this._inLen)));
                    if (probe.length >= 1 && probe[0] === 0xfe) {
                        hex = bufHex(this._inBuf,
                                     Math.min(this._inLen, DUMP_LIMIT));
                        kind = 'send';
                    }
                }
                if (hex === '' && this._outLen > 0 && this._outLen < 0x10000) {
                    const probe = new Uint8Array(
                        this._outBuf.readByteArray(Math.min(3, this._outLen)));
                    if (probe.length >= 1 && probe[0] === 0xfe) {
                        hex = bufHex(this._outBuf,
                                     Math.min(this._outLen, DUMP_LIMIT));
                        kind = 'recv';
                    }
                }
                if (hex !== '') {
                    send({
                        ev: 'tcp_ioctl',
                        ioctl: '0x' + this._ioctl.toString(16),
                        kind: kind,
                        handle: '0x' + this._handle.toString(16),
                        hex: hex,
                        ts: nowNs(),
                    });
                }
            } catch (e) {}
        },
    };
}

// ── DirectInput8 chain hook for input control ────────────────────────
//
// With on_load:wait (gadget v0.4.0+), the agent JS runs BEFORE NC2
// calls DirectInput8Create. We chain-hook the COM creation path so
// we capture the keyboard device's vtable when it's created.
//
// Once captured, rpc.exports.dik_press(dik, on) toggles a key in our
// inject map. Our GetDeviceData / GetDeviceState hook modifies the
// returned state buffer to set/clear that key.

globalThis.__DI8_INJECT = {};   // {dik: 0x80 | 0}
let DI8_DEVICE_VT = null;       // captured at CreateDevice time

function attachDI8Chain() {
    const di8 = Process.findModuleByName('dinput8.dll')
             || Process.findModuleByName('DINPUT8.DLL');
    if (di8 === null) {
        send({ ev: 'di_unavailable' });
        return;
    }
    const DI8Create = di8.findExportByName('DirectInput8Create');
    if (DI8Create === null) return;

    Interceptor.attach(DI8Create, {
        onEnter(args) { this._ppv = args[4]; },
        onLeave(retval) {
            if (retval.toInt32() !== 0) return;
            try {
                const pIDI8 = this._ppv.readPointer();
                if (pIDI8.isNull()) return;
                const vt = pIDI8.readPointer();
                // IDirectInput8 vtable slot 3 = CreateDevice (x86 cdecl).
                const pCD = vt.add(3 * 4).readPointer();
                Interceptor.attach(pCD, {
                    onEnter(args) {
                        // **thiscall**: args[0] = REFGUID rguid (first
                        // STACK arg after `this` in ECX).
                        this._rguid  = args[0];
                        this._ppDev  = args[1];
                    },
                    onLeave(r) {
                        if (r.toInt32() !== 0) return;
                        try {
                            const pDev = this._ppDev.readPointer();
                            if (pDev.isNull()) return;
                            const dvt = pDev.readPointer();
                            // Slot 9 = GetDeviceState; slot 10 = GetDeviceData.
                            // Hook BOTH — whichever NC2 uses for keyboard.
                            const pGDS = dvt.add(9 * 4).readPointer();
                            const pGDD = dvt.add(10 * 4).readPointer();
                            DI8_DEVICE_VT = '0x' + dvt.toString(16);
                            send({ ev: 'di_device_created',
                                   vtable: DI8_DEVICE_VT,
                                   getDeviceState: '0x' + pGDS.toString(16),
                                   getDeviceData:  '0x' + pGDD.toString(16) });
                            installGDSHook(pGDS);
                            installGDDHook(pGDD);
                        } catch (e) {
                            send({ ev: 'di_hook_err', phase: 'CreateDevice',
                                   err: String(e) });
                        }
                    },
                });
                send({ ev: 'di_idi8_hooked' });
            } catch (e) {
                send({ ev: 'di_hook_err', phase: 'DI8Create',
                       err: String(e) });
            }
        },
    });
    send({ ev: 'di_chain_armed' });
}

function installGDSHook(addr) {
    Interceptor.attach(addr, {
        onEnter(args) {
            // thiscall: args[0]=cbData, args[1]=lpvData (this is in ECX).
            this._cb  = args[0].toInt32();
            this._lpv = args[1];
        },
        onLeave(retval) {
            if (retval.toInt32() !== 0) return;
            if (this._cb !== 256) return;   // keyboard state size
            const inj = globalThis.__DI8_INJECT;
            const keys = Object.keys(inj);
            if (keys.length === 0) return;
            try {
                for (const dik of keys) {
                    this._lpv.add(parseInt(dik)).writeU8(inj[dik] ? 0x80 : 0);
                }
            } catch (e) {}
        },
    });
}

function installGDDHook(addr) {
    // GetDeviceData buffer-based — used when the device is in
    // buffered mode. Each element is a DIDEVICEOBJECTDATA (16 bytes).
    // For injection we'd need to ADD events to the buffer, which is
    // more invasive. For v0.4.0 we just observe.
    Interceptor.attach(addr, {
        onLeave(retval) {
            // Just count calls so we know if NC2 uses buffered mode.
            send({ ev: 'di_get_data_called' });
        },
    });
}

attachDI8Chain();

// Map from hook-name to a factory. Adding a new hook == adding it to
// orchestrator/symbols.py (with implemented=true) AND registering it
// here. Legacy in-EXE-offset hooks (udp_cipher_a/b) used cipherHandler
// — kept available for future use even though the canonical path is
// now Winsock-based.
const HOOK_FACTORIES = {
    udp_recv: udpRecvHandler,
    udp_send: udpSendHandler,
    tcp_read: tcpReadFileHandler,
    tcp_write: tcpWriteFileHandler,
    tcp_ioctl: tcpIoctlHandler,
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

    // ── DirectInput keyboard injection ────────────────────────────
    //
    // Press/release a DirectInput key. The keyboard device must have
    // been created AFTER the agent loaded (true under on_load:wait).
    // Common DIK codes:
    //   0x11 = W   0x1F = S   0x1E = A   0x20 = D   0x39 = Space
    //   0x1C = Return  0x01 = Escape
    // See: dinputd.h DIK_* constants.
    dikPress(dik, on) {
        globalThis.__DI8_INJECT[dik] = on ? 1 : 0;
        return {
            device_vtable: DI8_DEVICE_VT,
            active_keys: Object.keys(globalThis.__DI8_INJECT)
                .filter(k => globalThis.__DI8_INJECT[k]),
        };
    },
    dikClear() {
        globalThis.__DI8_INJECT = {};
        return 0;
    },
};
