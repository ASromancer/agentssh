# agentssh

SSH for AI coding agents (Claude Code, Codex) without handing them your keys.

- **The agent never sees a private key.** Keys live in an encrypted vault; a local daemon holds them in memory and runs commands for the agent.
- **Every command is classified deterministically (no LLM)** as `read`, `mutate`, `destructive` or `forbidden`, by parsing it with a real shell parser (pipes, `&&`, subshells, `$(...)`, `sudo`/`env`/`xargs` wrappers, `bash -c '...'`).
- **Destructive commands need a human**, who approves in a separate terminal with a code from a desktop notification. The approval screen shows the exact command and the risk the tool computed, never the agent's description of it.
- **Forbidden commands are always blocked**: reading `~/.ssh`, `/etc/shadow` or sudoers, `curl … | sh`, reverse shells.
- **Output is compact.** Long output keeps the first and last 40 lines; the rest is one `agentssh out <id> --grep …` away.
- **Everything is audited** to a JSONL file.

One static Go binary for Linux, macOS and Windows (amd64, arm64). Apache-2.0.

## Install

```sh
go install github.com/ASromancer/agentssh@latest   # or download a release binary
agentssh init        # vault + master key in the OS keyring, imports ~/.ssh/config, user service, Claude hook
```

`init` imports hosts from `~/.ssh/config`, but agents can't see any of them until you enable each one.

```sh
agentssh key gen web1-agent             # prints a public key: add it to authorized_keys on the server
agentssh host add web1 --host 10.0.0.5 --user deploy --key web1-agent --agent --desc "nginx + app, production"
agentssh host trust web1                # compare the fingerprint, then pin the host key
agentssh doctor
```

Use one key per agent, not your personal key. Admin commands (`host`, `key`, `reload`, `approve`, `trust`) must run in a real terminal, and each one asks for a 4-character code sent as a desktop notification.

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

`init` / `install-hooks claude` installs a skill at `~/.claude/skills/agentssh/SKILL.md` and a `PreToolUse` hook. `install-hooks codex` adds instructions to `~/.codex/AGENTS.md`.

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

The daemon reads `hosts.toml` and `rules.toml` only at startup and on `agentssh reload` (which needs a code). If the files changed on disk since you last approved them, the daemon refuses every agent request until you run `agentssh reload`.

## Approvals

When the agent runs something destructive:

1. The agent's command blocks. It prints `waiting approval #12 — run 'agentssh approve' in another terminal`.
2. You get a desktop notification, for example `web1: rm -rf /var/log/old [destructive] code: K7Q4`.
3. You run `agentssh approve`. It shows the exact command with the risky parts highlighted and the reasons. Type the code, then choose:
   - `y`: allow once
   - `s`: allow the identical command on that host for 30 minutes
   - `n`: deny
   - `m`: deny with a message that is passed back to the agent

Three wrong codes deny the request.

## Threat model — read this

- **Default mode: the daemon runs as your user.** It protects against an agent that has been prompt-injected and uses its normal tools (Bash, Edit, Write) to:
  - steal keys
  - run destructive commands without approval
  - approve its own requests

  It does **not** protect against a malicious process running as your user that attacks deliberately. Such a process can read the OS keyring, debug the daemon, or read your screen.
- **Hardened mode (planned for V1.1):** the daemon runs as a separate system user, so agents cannot read the vault, the config or the daemon's memory. This is a real security boundary.
- **If desktop notifications don't work**, the approval code is shown in the terminal instead. An agent that can fake a TTY could then approve its own requests. `agentssh doctor` warns about this.
- **The agent hook is a soft layer.** It asks you about `mutate` commands, denies direct `ssh`/`scp`/`rsync`, and denies human-only `agentssh` subcommands. The daemon enforces forbidden commands, profiles and approvals whether or not the hook is installed.
- **Classification is best-effort static analysis.** It handles quoting, escapes, wrappers, nested shells, globs on sensitive paths and dynamic command names; dynamic or unknown constructs are classified upward. Interpreters such as `python -c` count as plain `mutate`.

## Windows

- Needs Windows 10 1803 or later (AF_UNIX sockets). The daemon only accepts connections from processes running as the same Windows user; it checks the peer's token SID.
- `agentssh init` registers a logon task (`schtasks`) that starts `agentssh daemon --detach` with no console window. The master key goes into Windows Credential Manager.
- Approval codes arrive as toast notifications sent through Windows PowerShell. Admin commands read from the console (`CONIN$`).
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
