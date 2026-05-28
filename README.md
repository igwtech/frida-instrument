# frida-instrument — Neocron 2 launcher addon

Drops the **Frida gadget DLL** into the Neocron 2 client process so a
Python orchestrator can hook the running game at runtime: dump UDP-cipher
plaintext, log session-dispatcher cases, drive the client through
experiments via RPC, etc.

This is the *companion addon* to the orchestrator in
[ceres-j/tools/frida_re](../). The addon ships the in-process side
(Frida gadget + agent JS + config). The orchestrator runs on Linux and
talks to the gadget over TCP loopback.

## Install via Neocron launcher

In the launcher's Addons tab, click **Install from URL** and paste:

```
https://github.com/igwtech/frida-instrument
```

Enable the addon. The launcher will:

1. Place `dwmapi.dll` (renamed Frida gadget) next to `neocronclient.exe`.
2. Place `dwmapi.config.json` next to it (gadget listens on
   `127.0.0.1:27042` in resume mode — does **not** block startup).
3. Compose `dwmapi` into `WINEDLLOVERRIDES` automatically.
4. Drop the agent JS at `<game>/.frida_re/agent/_agent.js` and a copy
   of this README at `<game>/.frida_re/README.md` for runtime reference.

## Install the Python orchestrator

The orchestrator is not in this repo — it lives in the Neocron project
tree at [`ceres-j/tools/frida_re/`](https://github.com/igwtech/Ceres-J).

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

Edit `dwmapi.config.json` in the game dir to change defaults:

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

The launcher does not regenerate `dwmapi.config.json` after the first
install, so your edits survive addon updates.

## Default behaviour rationale

The gadget runs in **resume** mode (does not block startup) because
NC2 is an MMO: the user must reach the login screen, enter credentials,
and proceed. That window gives ample time to attach the orchestrator
before any meaningful game packets fly. Resume mode also means the
addon is safe to leave enabled by default — forgetting to start the
orchestrator does not hang the game.

## Conflicts and interactions

* **renodx / ReShade**: independent. Those use `d3d9.dll`. No shared
  paths.
* **Any other addon proxying `dwmapi.dll`**: declare a `conflicts`
  relationship in that addon's manifest. Two proxies cannot share the
  same DLL slot.

## Uninstall

Disable + uninstall via the launcher. The launcher's pristine pool
restores the original game dir state — with no local `dwmapi.dll`,
Wine falls back to its System32 builtin again.

## Frida version

The bundled `dwmapi.dll` is an unmodified release build of
[frida-gadget](https://github.com/frida/frida) (Windows x86). Frida
ships gadgets per `major.minor`; major versions can change the
agent/host protocol, so:

* Keep the Python `frida` package on the same major as the bundled
  gadget.
* To upgrade Frida, re-run
  [`ceres-j/tools/frida_re/setup.sh`](../setup.sh) against the game
  dir to fetch a newer gadget, then update this addon's `dwmapi.dll`
  via `make addon-sync` from `ceres-j/tools/frida_re/`.

## License

See [`LICENSE`](./LICENSE). The bundled `dwmapi.dll` is the Frida
gadget under the wxWindows Library Licence (a free-software license,
LGPL-like). The addon scripts themselves are MIT.
