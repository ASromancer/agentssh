# agentssh

SSH for AI coding agents (Claude Code, Codex) without handing them your keys.

- **The agent never sees a private key.** Keys live in an encrypted vault; a local daemon holds them in memory and runs commands for the agent.
- **Every command is classified deterministically (no LLM)** as `read`, `mutate`, `destructive` or `forbidden`, by parsing it with a real shell parser (pipes, `&&`, subshells, `$(...)`, `sudo`/`env`/`xargs` wrappers, `bash -c '...'`).
- **Destructive commands need a human**, who approves in a separate terminal and confirms in the operating system's authentication dialog (or, in code mode, with a code from a desktop notification). The approval screen shows the exact command and the risk the tool computed, never the agent's description of it.
- **Forbidden commands are always blocked**: reading `~/.ssh`, `/etc/shadow` or sudoers, `curl … | sh`, reverse shells.
- **Output is compact.** Long output keeps the first and last 40 lines; the rest is one `agentssh out <id> --grep …` away.
- **Everything is audited** to a JSONL file.

One static Go binary for Linux, macOS and Windows (amd64, arm64). Apache-2.0.

## Install

Download a binary from [Releases](https://github.com/ASromancer/agentssh/releases) and put it on your `PATH`, or:

```sh
go install github.com/ASromancer/agentssh@latest
agentssh init        # vault + master key in the OS keyring (or --passphrase), imports ~/.ssh/config,
                     # user service, and the skill + hook for each agent it finds
```

`init` imports hosts from `~/.ssh/config`, but agents can't see any of them until you enable each one.

```sh
agentssh key gen web1-agent             # prints a public key: add it to authorized_keys on the server
agentssh host add web1 --host 10.0.0.5 --user deploy --key web1-agent --agent --desc "nginx + app, production"
agentssh host trust web1                # compare the fingerprint, then pin the host key
agentssh doctor
```

Use one key per agent, not your personal key. Admin commands (`host`, `key`, `reload`, `approve`, `trust`) must run in a real terminal, and each one is confirmed in the OS authentication dialog, or with a code in code mode (see [Approvals](#approvals)).

## What the agent uses

```text
agentssh hosts [--json]
agentssh run <host> "<cmd>" [--timeout 60s] [--json]
agentssh out <id> [--grep <regexp>] [--range a:b]
agentssh get <host>:<remote-path> <local-path>
agentssh put <local-path> <host>:<remote-path>
agentssh job start <host> "<cmd>" | job tail <id> [--lines N] | job kill <id>
agentssh explain "<cmd>" [--host <host>]
```

```text
$ agentssh run web1 "df -h /"
web1 exit=0 0.3s level=read id=57
Filesystem      Size  Used Avail Use% Mounted on
/dev/sda1        80G   41G   36G  54% /
```

An agentssh run passes the remote command's exit code through unchanged. agentssh uses three exit codes of its own:

| Code | Meaning |
|---|---|
| 100 | blocked by policy (forbidden, profile doesn't allow it, host not allowed) |
| 101 | denied by the user or the approval timed out (default 120 s) |
| 102 | daemon not running or vault locked |

If agentssh itself produced the exit code, it also prints a stderr line starting with `agentssh:`. If the remote command happens to exit with 100–102, no such line appears.

## Agents

| Agent | Install | What you get |
|---|---|---|
| Claude Code | `/plugin marketplace add ASromancer/agentssh` then `/plugin install agentssh@agentssh`, or `agentssh install-hooks claude` | skill, `PreToolUse` hook (`install-hooks` also adds `Bash(ssh:*)`-style deny rules) |
| Codex | `agentssh install-hooks codex`, then run `/hooks` in Codex once to trust the hook | skill in `~/.agents/skills`, `AGENTS.md` block, `hooks.json`, `rules/agentssh.rules` (forbids `ssh`, `scp`, … and human-only `agentssh` commands) |
| Antigravity (app, IDE, `agy`) | `agentssh install-hooks antigravity` | skill in `~/.gemini/config/skills`, `hooks.json` group, `agy` deny rules. In the app and IDE, also add `ssh`/`scp` to the deny list in Settings. |
| Gemini CLI (legacy) | `agentssh install-hooks gemini` | skill in `~/.agents/skills`, `BeforeTool` hook, `policies/agentssh.toml` |
| Any MCP client | see below | the same tools over MCP |

`agentssh install-hooks all` installs for every agent it detects. All of them install the binary's absolute path as the hook command, so the binary has to stay where it is.

Only Claude Code's hook can ask you in chat before a `mutate` command on a `standard` host. Codex and Gemini hooks have no "ask", and MCP has no hooks at all. For those agents (and any caller that isn't Claude Code), the daemon sends `mutate` commands on `standard` hosts through the same out-of-band approval as `destructive` ones. To skip that, use the `full` profile or `allow` patterns.

### MCP

`agentssh mcp` is a stdio MCP server with the tools `hosts`, `run`, `output`, `explain`, `get`, `put`, `job_start`, `job_tail` and `job_kill`. It uses the same daemon, policy and approvals as the CLI.

When a command needs approval, `run` doesn't block past the client's tool timeout. It returns an `approval_id`, and the agent calls `run` again with that id after you approve.

Pass `--cwd <repo>` so the server finds that repo's `.agentssh.toml`.

```jsonc
// Claude Desktop, Cursor, Windsurf, Gemini CLI (~/.gemini/settings.json), Antigravity (~/.gemini/config/mcp_config.json)
{ "mcpServers": { "agentssh": { "command": "agentssh", "args": ["mcp"] } } }
```

```toml
# Codex (~/.codex/config.toml), or: codex mcp add agentssh -- agentssh mcp
[mcp_servers.agentssh]
command = "agentssh"
args = ["mcp"]
```

Agents that have a shell work better with the CLI and skill: no tool schemas sit in every prompt, and the hooks apply.

## Profiles and rules

| Profile | read | mutate | destructive | forbidden |
|---|---|---|---|---|
| `readonly` | run | block | block | block |
| `standard` (default) | run | agent hook asks you | approval via daemon | block |
| `full` | run | run | approval via daemon | block |

Per host in `~/.config/agentssh/hosts.toml`:

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

`allow` can never lower a built-in forbidden rule. A command that matches no rule is `mutate`. The default rules are in [internal/policy/rules.toml](internal/policy/rules.toml). You can add or override rules in `~/.config/agentssh/rules.toml`, using the same format; your rules are checked first.

A repo can narrow access with a `.agentssh.toml` file, which is safe to commit:

```toml
hosts = ["web1", "db-staging"]
max_profile = "standard"
```

The daemon finds this file by walking up from the agent's working directory. It can only narrow access, never widen it. Because the client reports its own working directory, this file is a convenience scope and not a security boundary.

The daemon reads `hosts.toml` and `rules.toml` only at startup and on `agentssh reload` (which you confirm like any admin operation). If the files changed on disk since you last approved them, the daemon refuses every agent request until you run `agentssh reload`.

## Approvals

Approvals and admin operations (key generation, host edits, ...) are confirmed through your operating system's authentication dialog, opened by the daemon itself:

- **Linux (on by default):** polkit (password prompt). Run `sudo agentssh install-polkit` once from your own account, then `systemctl --user restart agentssh`. It needs a local graphical session (a forwarded X display does not count).
- **macOS (off by default):** Touch ID, or your macOS password.
- **Windows (off by default):** your Windows password.

On macOS and Windows the daemon uses codes until these backends have been verified on real machines. To try OS authentication there, set `AGENTSSH_OS_AUTH=1` in the daemon's environment. `AGENTSSH_OS_AUTH=0` forces codes on every OS.

The daemon chooses the mode when it starts (and again on `agentssh reload`). If the dialog later cannot be shown, approvals fail with an error until you fix it (`agentssh doctor`) or restart the daemon with `AGENTSSH_OS_AUTH=0`; you can still deny with `n`.

When the agent runs something destructive:

1. The agent's command blocks. It prints `waiting approval #12 — run 'agentssh approve' in another terminal`.
2. You get a desktop notification, for example `web1: rm -rf /var/log/old [destructive]`.
3. You run `agentssh approve`. It shows the exact command with the risky parts highlighted and the reasons. Choose:
   - `y`: allow once
   - `s`: allow the identical command on that host for 30 minutes
   - `n`: deny
   - `m`: deny with a message that is passed back to the agent

   For `y`, `s` and `m` the OS dialog appears and shows the request number, host and command (and your message for `m`); cancelling it leaves the request pending. Denials (`n`) need no authentication. Only one dialog is open at a time.

**Fallback: codes.** Without OS authentication (turned off, no local graphical session, polkit action missing or installed for another user), the notification carries a 4-character code that you type after choosing. Three wrong codes deny the request. If the OS dialog fails to appear (for example, the polkit agent is gone), the daemon switches to codes until it restarts and sends a code for every pending request; `approve` asks you to choose again and enter it, and an admin command asks you to run it again. `agentssh doctor` shows which mode is active.

## Threat model — read this

- **Default mode: the daemon runs as your user.** It protects against an agent that has been prompt-injected and uses its normal tools (Bash, Edit, Write) to:
  - steal keys
  - run destructive commands without approval
  - approve its own requests

  It does **not** protect against a malicious process running as your user that attacks deliberately. Such a process can read the OS keyring, debug the daemon, or read your screen.
- **Hardened mode (planned for V1.1):** the daemon runs as a separate system user, so agents cannot read the vault, the config or the daemon's memory. This is a real security boundary.
- Approvals and admin operations are confirmed through the operating system's authentication dialog, triggered by the daemon itself; a caller of the daemon (including an agent) cannot complete them without the human passing that dialog. **Authenticate only dialogs you started yourself**, and check that the request number and command match what `approve` shows: an agent can start a dialog too, and authenticating it approves what it names.
- The mode is chosen when the daemon starts (and on an approved `agentssh reload`); agentssh never falls back to codes on its own. A dialog that is cancelled, times out or cannot be shown is a refusal, and the request stays pending.
- System helpers such as `pkcheck` are run from fixed paths that must be owned by root and not writable by others, never looked up in `PATH`.
- Restarting the daemon with `AGENTSSH_OS_AUTH=0` is a deliberate human action; the agent hooks block `agentssh daemon` and shell commands that mention `AGENTSSH_OS_AUTH` or `agentssh.service`.
- Code mode uses codes from desktop notifications, which a same-user process could read. In code mode, when a notification cannot be sent, the code is shown in the terminal and is also exposed to any process of your user that calls the daemon's socket. `agentssh doctor` shows which mode is active.
- Locking a keyring-mode vault (`agentssh lock`) is not a security boundary against processes of your user: they can read the master key from the OS keyring themselves.
- **Agent hooks are a soft layer.** They deny direct `ssh`/`scp`/`rsync`, deny human-only `agentssh` subcommands, and keep agents out of agentssh's own files. In Claude Code they also ask you before `mutate` commands. The daemon enforces forbidden commands, profiles and approvals whether or not a hook is installed.
- **The agent name is self-reported.** The CLI derives it from environment variables such as `CLAUDECODE`, `CODEX_*` and `GEMINI_CLI`, so a caller can claim to be Claude Code. That only affects whether a `mutate` command on a `standard` host gets an in-chat ask or an out-of-band approval. It never bypasses forbidden commands or destructive approvals.
- **Classification is best-effort static analysis.** It handles quoting, escapes, wrappers, nested shells, globs on sensitive paths and dynamic command names; dynamic or unknown constructs are classified upward. Interpreters such as `python -c` count as plain `mutate`.

## Windows

- Needs Windows 10 1803 or later (AF_UNIX sockets). The daemon only accepts connections from processes running as the same Windows user; it checks the peer's token SID.
- `agentssh init` registers a logon task (`schtasks`) that starts `agentssh daemon --detach` with no console window. The master key goes into Windows Credential Manager.
- OS authentication is off by default on Windows (see [Approvals](#approvals)); in code mode the codes arrive as toast notifications sent through Windows PowerShell. Admin commands read from the console (`CONIN$`).
- Claude Code on Windows runs Bash through Git Bash. The hook also recognizes `ssh.exe`, `C:\` paths and the `%APPDATA%` directories.
- Config lives in `%APPDATA%\agentssh`. State, logs and the socket live in `%LOCALAPPDATA%\agentssh`. Both are protected by the per-user ACL of your profile.

## Files

Locations on Linux and macOS (see the Windows section above for Windows):

| Path | Contents |
|---|---|
| `~/.config/agentssh/hosts.toml` | hosts, profiles, allow/deny (no secrets) |
| `~/.config/agentssh/rules.toml` | optional rule overrides |
| `~/.config/agentssh/vault.bin` | keys, encrypted with nacl/secretbox |
| `~/.config/agentssh/known_hosts` | pinned host keys |
| `~/.local/state/agentssh/audit.jsonl` | audit log (no command output) |
| `~/.local/state/agentssh/out/<id>` | full output, deleted after 7 days |

Background jobs live in the daemon and are lost if it restarts. Their output stays in `out/`.

## Development

```sh
go test ./...                                         # unit tests + in-process SSH server test
go build -o /tmp/agentssh . && python3 scripts/e2e.py /tmp/agentssh   # real sshd, real CLI (Linux/macOS)
```

CI runs both on Linux, macOS and Windows (unit tests only on Windows).
