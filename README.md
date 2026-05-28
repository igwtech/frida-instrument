# frida-instrument — Neocron 2 launcher addon

Injects **Frida** into the running Neocron 2 client process so a
Python orchestrator can hook the game at runtime: dump UDP-cipher
plaintext, log session-dispatcher cases, drive the client through
experiments via RPC, etc.

This is the *companion addon* to the orchestrator in
[ceres-j/tools/frida_re](../). The addon ships the in-process side
(ASI loader + Frida gadget + agent JS + config). The orchestrator
runs on Linux and talks to the gadget over TCP loopback.

## Architecture

Frida is loaded **inside the Wine process** via a two-stage proxy:

1. **`dinput8.dll`** is [Ultimate-ASI-Loader][uasi] — a battle-tested
   proxy DLL that correctly forwards every standard `dinput8` export
   to the real system32 dinput8 (so `DirectInput8Create` and friends
   still work, the game starts normally). On `DllMain` attach the
   loader scans the game directory for `*.asi` files and
   `LoadLibrary`s each one.
2. **`frida-gadget.asi`** is the unmodified Frida gadget renamed to
   `.asi`. When the ASI loader loads it, the gadget's `DllMain`
   initialises Frida's instrumentation engine, binds
   `127.0.0.1:27042`, and waits in resume mode (does **not** block
   startup).

This sidesteps the failure mode of using a bare gadget as a
direct DLL proxy: NC2 actively calls into both `winmm.dll`
(`timeGetTime`) and `dwmapi.dll` (`DwmSetWindowAttribute`) at
startup, so a bare gadget renamed to either name causes the
loader to abort with "unimplemented function". The ASI loader has
all the forwarders.

[uasi]: https://github.com/ThirteenAG/Ultimate-ASI-Loader

## Install via Neocron launcher

In the launcher's Addons tab, click **Install from URL** and paste:

```
https://github.com/igwtech/frida-instrument
```

Enable the addon. The launcher will:

1. Place `dinput8.dll` (ASI loader) next to `neocronclient.exe`.
2. Place `frida-gadget.asi` (Frida gadget) next to it.
3. Place `frida-gadget.config.json` (gadget config: listen
   `127.0.0.1:27042`, resume mode).
4. Compose `dinput8` into `WINEDLLOVERRIDES` automatically.
5. Drop the agent JS at `<game>/.frida_re/agent/_agent.js` and a
   copy of this README at `<game>/.frida_re/README.md` for runtime
   reference.

## Install the Python orchestrator

The orchestrator is not in this repo — it lives in the Neocron
project tree at
[`ceres-j/tools/frida_re/`](https://github.com/igwtech/Ceres-J).

```bash
pip install frida frida-tools                    # or use the project venv
cd /path/to/Neocron/ceres-j/tools/frida_re
python -m orchestrator --trace /tmp/frida_nc2.jsonl
```

## Usage

1. Launch the game via the Neocron launcher.
2. Stop at the login screen — there are no game packets yet.
3. Start the orchestrator (above). It connects to `127.0.0.1:27042`,
   pushes the agent JS, installs hooks.
4. Log in. Every UDP-cipher call now emits `cipher_enter` /
   `cipher_leave` events with plaintext + seed.

## Configuration

Edit `frida-gadget.config.json` in the game dir to change defaults:

```json
{
  "interaction": {
    "type": "listen",
    "address": "127.0.0.1",
    "port": 27042,
    "on_port_conflict": "fail",
    "on_load": "resume"
  }
}
```

* `"on_load": "wait"` — pauses the game at process start until the
  orchestrator connects. Use for investigating early-startup packets
  that fly before the login screen.
* `"port": 27043` — pick another port if 27042 collides with another
  service.
* `"address": "0.0.0.0"` — bind on all interfaces (useful if the
  orchestrator runs in a VM, not on the host).

The launcher does not regenerate `frida-gadget.config.json` after
the first install, so your edits survive addon updates.

## Default behaviour rationale

The gadget runs in **resume** mode (does not block startup) because
NC2 is an MMO: the user must reach the login screen, enter
credentials, and proceed. That window gives ample time to attach the
orchestrator before any meaningful game packets fly. Resume mode
also means the addon is safe to leave enabled by default — forgetting
to start the orchestrator does not hang the game.

## Conflicts and interactions

* **renodx / ReShade**: independent. Those use `d3d9.dll`. No
  shared paths.
* **Any other addon proxying `dinput8.dll`**: declare a `conflicts`
  relationship in that addon's manifest. Two proxies cannot share
  the same DLL slot. The ASI loader DOES forward every standard
  dinput8 export, so games that rely on the input subsystem still
  work — only conflict if another *proxy* is in play.

## Uninstall

Disable + uninstall via the launcher. The launcher's pristine pool
restores the original game dir state — with no local `dinput8.dll`
or `frida-gadget.asi`, Wine falls back to the System32 builtin and
no Frida loads.

## Frida version

The bundled `frida-gadget.asi` is an unmodified release build of
[frida-gadget](https://github.com/frida/frida) (Windows x86). Frida
ships gadgets per `major.minor`; major versions can change the
agent/host protocol, so:

* Keep the Python `frida` package on the same major as the bundled
  gadget.
* To upgrade Frida, re-run
  [`ceres-j/tools/frida_re/setup.sh`](../setup.sh) against the game
  dir to fetch a newer gadget, then update this addon's
  `frida-gadget.asi` via `make addon-sync GADGET=…` from
  `ceres-j/tools/frida_re/`.

## License

See [`LICENSE`](./LICENSE). Three things are bundled, each under
its own license:

* The addon scripts (addon.json, frida-gadget.config.json,
  agent/_agent.js, README.md) are MIT.
* `frida-gadget.asi` is the Frida gadget under the wxWindows
  Library Licence.
* `dinput8.dll` is [Ultimate-ASI-Loader][uasi] under the MIT
  Licence.
