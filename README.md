# Ostiary

SSH for AI coding agents (Claude Code, Codex) without handing them your keys.

- **The agent never sees a private key.** Keys live in an encrypted vault; a local daemon holds them in memory and runs commands for the agent.
- **Every command is classified deterministically (no LLM)** as `read`, `mutate`, `destructive` or `forbidden`, by parsing it with a real shell parser (pipes, `&&`, subshells, `$(...)`, `sudo`/`env`/`xargs` wrappers, `bash -c '...'`).
- **Destructive commands need a human**, who approves in a separate terminal and confirms in the operating system's authentication dialog (or, in code mode, with a code from a desktop notification). The approval screen shows the exact command and the risk the tool computed, never the agent's description of it.
- **Forbidden commands are always blocked**: reading `~/.ssh`, `/etc/shadow` or sudoers, `curl … | sh`, reverse shells.
- **Output is compact.** Long output keeps the first and last 40 lines; the rest is one `ostiary out <id> --grep …` away.
- **Everything is audited** to a JSONL file.

One static Go binary for Linux, macOS and Windows (amd64, arm64). Apache-2.0.

## Install

Get the file for your system from [Releases](https://github.com/ASromancer/ostiary/releases). The builds are not code-signed yet, so each OS warns on first run.

**Windows**: run `Ostiary-Setup-<ver>-x64.exe` (per-user, no admin). SmartScreen: "More info" then "Run anyway". Open Start Menu, Ostiary.

**macOS**: open `Ostiary-<ver>.dmg` and drag Ostiary to Applications. First launch: right-click the app, then Open (unsigned). Optional command-line symlink: `sudo ln -sf /Applications/Ostiary.app/Contents/MacOS/ostiary /usr/local/bin/ostiary`.

**Debian/Ubuntu**: `sudo apt install ./ostiary_<ver>_amd64.deb` (or `arm64`), then open "Ostiary" from the application menu. Optional OS authentication dialog: `sudo "$(command -v ostiary)" install-polkit`.

**Other Linux**: unpack `ostiary-linux-<arch>.tar.gz`, put `ostiary` on your `PATH`, then run `ostiary install-service` (adds the menu entry and autostart).

From source, or to set up from the command line:

```sh
CGO_ENABLED=0 go install github.com/ASromancer/ostiary@latest
ostiary init        # vault + master key in the OS keyring (or --passphrase), imports ~/.ssh/config,
                     # user service, and the skill + hook for each agent it finds
```

The static build (`CGO_ENABLED=0`) ignores `LD_PRELOAD`, which a dynamic binary would load into the daemon.

**Upgrading** from v0.1.x: run `ostiary install-service` once (Linux; it rewrites the user unit to start with your desktop session), then `sudo "$(command -v ostiary)" install-polkit` if you want OS authentication (`sudo` does not search `~/.local/bin`).

`init` imports hosts from `~/.ssh/config`, but agents can't see any of them until you enable each one.

```sh
ostiary key gen web1-agent             # prints a public key: add it to authorized_keys on the server
ostiary host add web1 --host 10.0.0.5 --user deploy --key web1-agent --agent --desc "nginx + app, production"
ostiary host trust web1                # compare the fingerprint, then pin the host key
ostiary doctor
```

Use one key per agent, not your personal key. Admin commands (`host`, `key`, `reload`, `approve`, `trust`) must run in a real terminal, and each one is confirmed in the OS authentication dialog, or with a code in code mode (see [Approvals](#approvals)).

## Moving from agentssh

Ostiary is the new name of agentssh and starts from a clean slate; it does not read agentssh's data.

1. Remove the old agent hooks: delete the `agentssh hook …` entries from `~/.claude/settings.json`, `~/.codex/hooks.json`, `~/.gemini/settings.json` and Antigravity's `hooks.json` (and the agentssh Claude Code plugin, if installed).
2. Stop and disable the old service: `systemctl --user disable --now agentssh` (Linux), `launchctl unload -w ~/Library/LaunchAgents/dev.agentssh.plist` (macOS), `schtasks /Delete /TN agentssh /F` (Windows).
3. Install Ostiary, run `ostiary init` (or open the app), then add your hosts and keys again.
4. When everything works, delete `~/.config/agentssh` and `~/.local/state/agentssh` (on Windows `%APPDATA%\agentssh` and `%LOCALAPPDATA%\agentssh`).

## What the agent uses

```text
ostiary hosts [--json]
ostiary run <host> "<cmd>" [--timeout 60s] [--json]
ostiary out <id> [--grep <regexp>] [--range a:b]
ostiary get <host>:<remote-path> <local-path>
ostiary put <local-path> <host>:<remote-path>
ostiary job start <host> "<cmd>" | job tail <id> [--lines N] | job kill <id>
ostiary explain "<cmd>" [--host <host>]
```

```text
$ ostiary run web1 "df -h /"
web1 exit=0 0.3s level=read id=57
Filesystem      Size  Used Avail Use% Mounted on
/dev/sda1        80G   41G   36G  54% /
```

An ostiary run passes the remote command's exit code through unchanged. ostiary uses three exit codes of its own:

| Code | Meaning |
|---|---|
| 100 | blocked by policy (forbidden, profile doesn't allow it, host not allowed) |
| 101 | denied by the user or the approval timed out (default 120 s) |
| 102 | daemon not running or vault locked |

If ostiary itself produced the exit code, it also prints a stderr line starting with `ostiary:`. If the remote command happens to exit with 100–102, no such line appears.

## Agents

| Agent | Install | What you get |
|---|---|---|
| Claude Code | `/plugin marketplace add ASromancer/ostiary` then `/plugin install ostiary@ostiary`, or `ostiary install-hooks claude` | skill, `PreToolUse` hook (`install-hooks` also adds `Bash(ssh:*)`-style deny rules) |
| Codex | `ostiary install-hooks codex`, then run `/hooks` in Codex once to trust the hook | skill in `~/.agents/skills`, `AGENTS.md` block, `hooks.json`, `rules/ostiary.rules` (forbids `ssh`, `scp`, … and human-only `ostiary` commands) |
| Antigravity (app, IDE, `agy`) | `ostiary install-hooks antigravity` | skill in `~/.gemini/config/skills`, `hooks.json` group, `agy` deny rules. In the app and IDE, also add `ssh`/`scp` to the deny list in Settings. |
| Gemini CLI (legacy) | `ostiary install-hooks gemini` | skill in `~/.agents/skills`, `BeforeTool` hook, `policies/ostiary.toml` |
| Any MCP client | see below | the same tools over MCP |

`ostiary install-hooks all` installs for every agent it detects. All of them install the binary's absolute path as the hook command, so the binary has to stay where it is. The hooks are a soft layer that a same-user agent can work around; see the [threat model](#threat-model--read-this).

Only Claude Code's hook can ask you in chat before a `mutate` command on a `standard` host. Codex and Gemini hooks have no "ask", and MCP has no hooks at all. For those agents (and any caller that isn't Claude Code), the daemon sends `mutate` commands on `standard` hosts through the same out-of-band approval as `destructive` ones. To skip that, use the `full` profile or `allow` patterns.

### MCP

`ostiary mcp` is a stdio MCP server with the tools `hosts`, `run`, `output`, `explain`, `get`, `put`, `job_start`, `job_tail` and `job_kill`. It uses the same daemon, policy and approvals as the CLI.

When a command needs approval, `run` doesn't block past the client's tool timeout. It returns an `approval_id`, and the agent calls `run` again with that id after you approve.

Pass `--cwd <repo>` so the server finds that repo's `.ostiary.toml`.

```jsonc
// Claude Desktop, Cursor, Windsurf, Gemini CLI (~/.gemini/settings.json), Antigravity (~/.gemini/config/mcp_config.json)
{ "mcpServers": { "ostiary": { "command": "ostiary", "args": ["mcp"] } } }
```

```toml
# Codex (~/.codex/config.toml), or: codex mcp add ostiary -- ostiary mcp
[mcp_servers.ostiary]
command = "ostiary"
args = ["mcp"]
```

Agents that have a shell work better with the CLI and skill: no tool schemas sit in every prompt, and the hooks apply.

## Profiles and rules

| Profile | read | mutate | destructive | forbidden |
|---|---|---|---|---|
| `readonly` | run | block | block | block |
| `standard` (default) | run | agent hook asks you | approval via daemon | block |
| `full` | run | run | approval via daemon | block |

Per host in `~/.config/ostiary/hosts.toml`:

```toml
[hosts.web1]
host = "10.0.0.5"
user = "deploy"
key = "web1-agent"
profile = "standard"
agent = true
description = "nginx + app server production"
allow = ["docker compose -f /srv/app/compose.yml restart *"]   # lowered to read
deny  = ["psql *"]                                             # raised to forbidden
```

`allow` can never lower a built-in forbidden rule. A command that matches no rule is `mutate`. The default rules are in [internal/policy/rules.toml](internal/policy/rules.toml). You can add or override rules in `~/.config/ostiary/rules.toml`, using the same format; your rules are checked first.

A repo can narrow access with a `.ostiary.toml` file, which is safe to commit:

```toml
hosts = ["web1", "db-staging"]
max_profile = "standard"
```

The daemon finds this file by walking up from the agent's working directory. It can only narrow access, never widen it. Because the client reports its own working directory, this file is a convenience scope and not a security boundary.

The daemon reads `hosts.toml` and `rules.toml` only at startup and on `ostiary reload` (which you confirm like any admin operation). If the files changed on disk since you last approved them, the daemon refuses every agent request until you run `ostiary reload`.

## Approvals

Approvals and admin operations (key generation, host edits, ...) are confirmed through your operating system's authentication dialog, opened by the daemon itself:

- **Linux (on by default):** polkit (password prompt). Run `sudo "$(command -v ostiary)" install-polkit` once from your own account (plain `sudo ostiary` fails when the binary is in `~/.local/bin`), then `systemctl --user restart ostiary`. It needs a local graphical session (a forwarded X display does not count); the user service starts with that session (`graphical-session.target`).
- **macOS (off by default):** Touch ID, or your macOS password.
- **Windows (off by default):** your Windows password.

On macOS and Windows the daemon uses codes until these backends have been verified on real machines. To try OS authentication there, set `OSTIARY_OS_AUTH=1` in the daemon's environment. `OSTIARY_OS_AUTH=0` forces codes on every OS.

The daemon chooses the mode when it starts; `ostiary reload` can switch codes to OS authentication (after you fix the setup), never back. If the dialog later cannot be shown, approvals fail with an error until you fix it (`ostiary doctor`) or restart the daemon with `OSTIARY_OS_AUTH=0`; you can still deny with `n`.

When the agent runs something destructive:

1. The agent's command blocks. It prints `waiting approval #12 — run 'ostiary approve' in another terminal`.
2. You get a desktop notification, for example `web1: rm -rf /var/log/old [destructive]`.
3. You run `ostiary approve`. It shows the exact command with the risky parts highlighted and the reasons. Choose:
   - `y`: allow once
   - `s`: allow the identical command on that host for 30 minutes
   - `n`: deny
   - `m`: deny with a message that is passed back to the agent

   For `y`, `s` and `m` the OS dialog appears and shows the request number, host and command (and your message for `m`); cancelling it leaves the request pending. Denials (`n`) need no authentication. Only one dialog is open at a time.

**Fallback: codes.** Without OS authentication (turned off, no local graphical session, polkit action missing or installed for another user), the notification carries a 4-character code that you type after choosing. Three wrong codes deny the request. A daemon that started in OS mode never switches to codes by itself (see above). `ostiary doctor` shows which mode is active.

## GUI

The daemon serves a local page on `127.0.0.1` with a random port. Open it with `ostiary ui` or from the tray icon. Clicking an approval notification (Linux, Windows) opens it at that request.

- **Duyệt:** pending requests with the exact command (risky parts highlighted), approve once, approve 30 minutes, deny, or deny with a message. Approving shows the OS authentication dialog, as in the terminal.
- **Host:** add, edit, delete, trust a host key, reload the config.
- **Vault & key:** lock and unlock; generate, import and delete keys. Private keys are never shown; exporting stays in the terminal (`ostiary key export`).
- **Nhật ký & trạng thái:** the `doctor` checks and the audit log, with each command's full output.

Login links are single use (10 minutes): `ostiary ui` asks the daemon for one over its socket (`ostiary ui --print` prints it), and the tray and notifications mint their own. The page then keeps a session cookie that expires after 8 hours idle. It refuses other hosts and cross-origin requests. In OS-auth mode, approving and admin changes go through the OS dialog; in code mode they need the approval code, and deny and lock need neither. Clickable notifications exist only in OS-auth mode. Flags: `ostiary daemon --no-ui`, `--no-tray`, `--ui-port N`. On GNOME the tray icon needs the AppIndicator extension (preinstalled on Ubuntu).

## Threat model — read this

- **Default mode: the daemon runs as your user.** It protects against an agent that has been prompt-injected and uses its normal tools (Bash, Edit, Write) to:
  - steal keys
  - run destructive commands without approval
  - approve its own requests

  It does **not** protect against a malicious process running as your user that attacks deliberately. Such a process can read the OS keyring, debug the daemon, or read your screen.
- **The web UI login stops websites and other local users, not a same-user agent.** A process of your user can call the daemon's socket (`ostiary ui --print`) and get a login link, as it can do anything else you can. Login links are single-use and expire in 10 minutes; another local user who reads one from a process list before the browser opens it could race the browser (you would then see a 401: run `ostiary ui` again).
- **Hardened mode (planned for V1.1):** the daemon runs as a separate system user, so agents cannot read the vault, the config or the daemon's memory. This is a real security boundary.
- Approvals and admin operations are confirmed through the operating system's authentication dialog, triggered by the daemon itself; a caller of the daemon (including an agent) cannot complete them without the human passing that dialog. **Authenticate only dialogs you started yourself**, and check that the request number and command match what `approve` shows: an agent can start a dialog too, and authenticating it approves what it names.
- The mode is chosen when the daemon starts (and on an approved `ostiary reload`); ostiary never falls back to codes on its own. A dialog that is cancelled, times out or cannot be shown is a refusal, and the request stays pending.
- System helpers (`pkcheck`, `notify-send`, `osascript`, `powershell`) are run from fixed paths that must be owned by root and not writable by others (on Windows: under System32), never looked up in `PATH`. `pkcheck` runs with an empty environment and notifiers with a short allowlist (session bus, display, `HOME`, locale), so variables such as `LD_PRELOAD` set in the daemon's environment never reach them. Without a trusted notifier, codes are shown in the terminal.
- Restarting the daemon with `OSTIARY_OS_AUTH=0` is a deliberate human action. On a best-effort basis, the agent hooks deny `ostiary daemon`; shell commands that mention `OSTIARY_OS_AUTH` or `ostiary.service`; `systemctl`/`launchctl`/`kill`/`pkill`/`killall` commands whose text mentions ostiary (including `kill $(pgrep ostiary)`); `systemctl --user` `set-environment`, `unset-environment`, `import-environment`, `daemon-reload`, `edit` and `revert`; `launchctl` `setenv`, `unsetenv`, `kickstart`, `bootout`, `load` and `unload`; and edits to the ostiary unit and its drop-ins, `~/.config/environment.d` and the launch agent plist. An approved `ostiary reload` can switch codes to OS authentication, never the other way.
- Code mode uses codes from desktop notifications, which a same-user process could read. In code mode, when a notification cannot be sent, the code is shown in the terminal and is also exposed to any process of your user that calls the daemon's socket. `ostiary doctor` shows which mode is active.
- Locking a keyring-mode vault (`ostiary lock`) is not a security boundary against processes of your user: they can read the master key from the OS keyring themselves.
- **Agent hooks are a soft layer.** They deny direct `ssh`/`scp`/`rsync`, deny human-only `ostiary` subcommands, and keep agents out of ostiary's own files. In Claude Code they also ask you before `mutate` commands. The daemon enforces forbidden commands, profiles and approvals whether or not a hook is installed. A same-user agent can work around the hooks: it can edit its own agent settings to remove them, restart the daemon with an altered environment by a route the hooks do not recognize, or replace the ostiary binary. OS authentication raises the bar, but it is not a boundary against a process running as your user. The real boundary is hardened mode (planned for V1.1).
- **The agent name is self-reported.** The CLI derives it from environment variables such as `CLAUDECODE`, `CODEX_*` and `GEMINI_CLI`, so a caller can claim to be Claude Code. That only affects whether a `mutate` command on a `standard` host gets an in-chat ask or an out-of-band approval. It never bypasses forbidden commands or destructive approvals.
- **Classification is best-effort static analysis.** It handles quoting, escapes, wrappers, nested shells, globs on sensitive paths and dynamic command names; dynamic or unknown constructs are classified upward. Interpreters such as `python -c` count as plain `mutate`.

## Windows

- Needs Windows 10 1803 or later (AF_UNIX sockets). The daemon only accepts connections from processes running as the same Windows user; it checks the peer's token SID.
- `ostiary init` registers a logon task (`schtasks`) that starts `ostiary daemon --detach` with no console window. The master key goes into Windows Credential Manager.
- OS authentication is off by default on Windows (see [Approvals](#approvals)); in code mode the codes arrive as toast notifications sent through Windows PowerShell. Admin commands read from the console (`CONIN$`).
- Claude Code on Windows runs Bash through Git Bash. The hook also recognizes `ssh.exe`, `C:\` paths and the `%APPDATA%` directories.
- Config lives in `%APPDATA%\ostiary`. State, logs and the socket live in `%LOCALAPPDATA%\ostiary`. Both are protected by the per-user ACL of your profile.

## Files

Locations on Linux and macOS (see the Windows section above for Windows):

| Path | Contents |
|---|---|
| `~/.config/ostiary/hosts.toml` | hosts, profiles, allow/deny (no secrets) |
| `~/.config/ostiary/rules.toml` | optional rule overrides |
| `~/.config/ostiary/vault.bin` | keys, encrypted with nacl/secretbox |
| `~/.config/ostiary/known_hosts` | pinned host keys |
| `~/.local/state/ostiary/audit.jsonl` | audit log (no command output) |
| `~/.local/state/ostiary/out/<id>` | full output, deleted after 7 days |

Background jobs live in the daemon and are lost if it restarts. Their output stays in `out/`.

## Development

```sh
go test ./...                                         # unit tests + in-process SSH server test
go build -tags e2efake -o /tmp/ostiary-e2e . && python3 scripts/e2e.py /tmp/ostiary-e2e   # real sshd, real CLI (Linux/macOS)
```

CI runs both on Linux, macOS and Windows (unit tests only on Windows).
