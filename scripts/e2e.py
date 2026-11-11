#!/usr/bin/env python3
"""End-to-end test: the real ostiary binary against a real OpenSSH sshd.

Linux/macOS only. Everything lives in a temp dir (HOME, XDG dirs, sshd), so
it never touches your keyring, ~/.claude or services. init runs in
passphrase mode.

The binary must be built with -tags e2efake: its notifier appends each
notification to $OSTIARY_E2E_NOTES (where this script reads the approval
codes) and its OS dialog is answered through $OSTIARY_E2E_HUMANOK. The
first part runs in code mode (OSTIARY_OS_AUTH=0), the last part in OS mode.

usage: go build -tags e2efake -o /tmp/ostiary-e2e . && python3 scripts/e2e.py /tmp/ostiary-e2e
"""
import fcntl, http.client, http.server, json, threading, os, re, select, shutil, signal, socket, subprocess, sys, tempfile, termios, time, urllib.parse

BIN = os.path.abspath(sys.argv[1])  # built with -tags e2efake
SSHD = shutil.which("sshd") or "/usr/sbin/sshd"
TMP = tempfile.mkdtemp(prefix="ostiary-e2e-")
HOME = os.path.join(TMP, "home")
PASS = "correct horse battery"
os.makedirs(HOME)

ENV = {k: v for k, v in os.environ.items() if k not in ("DISPLAY", "WAYLAND_DISPLAY", "CLAUDECODE")}
ENV.update(HOME=HOME, XDG_CONFIG_HOME=f"{HOME}/.config", XDG_STATE_HOME=f"{HOME}/.local/state",
           XDG_RUNTIME_DIR=f"{TMP}/run", OSTIARY_SOCKET=f"{TMP}/s.sock",
           DBUS_SESSION_BUS_ADDRESS="unix:path=/nonexistent", TERM="dumb",
           CLAUDECODE="1",  # agent calls come from Claude Code unless a test says otherwise
           OSTIARY_OS_AUTH="0")  # code mode first; the OS-mode part turns it on
os.makedirs(ENV["XDG_RUNTIME_DIR"], mode=0o700)
NOTES = os.path.join(TMP, "notifications.log")
ENV["OSTIARY_E2E_NOTES"] = NOTES

ENV["OSTIARY_NO_TRAY"] = "1"


class UI:
    """Talks to the daemon's web UI like a browser would."""

    def __init__(self):
        rc, out, err = run("ui", "--print")
        assert rc == 0, err
        self.url = out.strip()  # one-time login link from the daemon
        u = urllib.parse.urlsplit(self.url)
        self.host, self.port = u.hostname, u.port
        self.cookie = None

    def req(self, method, path, body=None, host=None, origin="same", cookie=True, ctype="application/json"):
        c = http.client.HTTPConnection(self.host, self.port, timeout=30)
        h = {"Host": host or f"127.0.0.1:{self.port}"}
        if cookie and self.cookie:
            h["Cookie"] = self.cookie
        data = None
        if method != "GET":
            h["Content-Type"] = ctype
            if origin == "same":
                h["Origin"] = f"http://127.0.0.1:{self.port}"
            elif origin:
                h["Origin"] = origin
            data = json.dumps(body or {})
        c.request(method, path, body=data, headers=h)
        r = c.getresponse()
        return r.status, r.getheader("Set-Cookie"), r.read().decode()

    def loginpath(self):
        u = urllib.parse.urlsplit(self.url)
        return u.path + "?" + u.query

    def login(self):
        status, setc, _ = self.req("GET", self.loginpath(), cookie=False)
        self.cookie = setc.split(";")[0] if setc else None
        return status


passed = 0


def check(cond, what, detail=""):
    global passed
    if not cond:
        print(f"FAIL {what}\n{detail}")
        sys.exit(1)
    passed += 1
    print(f"ok   {what}")


def run(*args, timeout=60):
    """Run without a terminal, the way an agent does."""
    p = subprocess.run([BIN, *args], env=ENV, stdin=subprocess.DEVNULL, capture_output=True,
                       text=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr


class Tty:
    """A child process whose controlling terminal is a pty we drive."""

    def __init__(self, *args):
        m, s = os.openpty()

        def pre():
            os.setsid()
            fcntl.ioctl(s, termios.TIOCSCTTY, 0)

        self.p = subprocess.Popen([BIN, *args], stdin=s, stdout=s, stderr=s, env=ENV, preexec_fn=pre)
        os.close(s)
        self.m, self.buf = m, ""

    def expect(self, pattern, timeout=20):
        rx = re.compile(pattern)
        end = time.time() + timeout
        while True:
            mt = rx.search(self.buf)
            if mt:
                self.buf = self.buf[mt.end():]
                return mt
            left = end - time.time()
            if left <= 0:
                raise AssertionError(f"timeout waiting for {pattern!r}; got:\n{self.buf}")
            r, _, _ = select.select([self.m], [], [], left)
            if r:
                try:
                    data = os.read(self.m, 4096)
                except OSError:
                    data = b""
                if not data and self.p.poll() is not None:
                    raise AssertionError(f"process exited waiting for {pattern!r}; got:\n{self.buf}")
                self.buf += data.decode(errors="replace")

    def send(self, line):
        os.write(self.m, (line + "\n").encode())

    def wait(self, timeout=30):
        rest = ""
        end = time.time() + timeout
        while self.p.poll() is None and time.time() < end:
            r, _, _ = select.select([self.m], [], [], 0.2)
            if r:
                try:
                    rest += os.read(self.m, 4096).decode(errors="replace")
                except OSError:
                    break
        self.buf += rest
        return self.p.wait(timeout=5)


def last_code():
    """The code from the most recent desktop notification."""
    for _ in range(50):
        codes = re.findall(r"code: ([A-Z0-9]{4})", open(NOTES).read()) if os.path.exists(NOTES) else []
        if codes:
            return codes[-1]
        time.sleep(0.1)
    raise AssertionError("no notification with a code")


def admin(*args):
    """Run a code-protected admin command with the code from the notification."""
    t = Tty(*args)
    t.expect(r"approval code \(from the desktop notification\): ")
    t.send(last_code())
    rc = t.wait()
    return rc, t.buf


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def start_sshd():
    d = os.path.join(TMP, "sshd")
    os.makedirs(d)
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", f"{d}/host_key"], check=True)
    open(f"{d}/authorized_keys", "w").close()
    port = free_port()
    with open(f"{d}/sshd_config", "w") as f:
        f.write(f"""Port {port}
ListenAddress 127.0.0.1
HostKey {d}/host_key
PidFile {d}/sshd.pid
AuthorizedKeysFile {d}/authorized_keys
StrictModes no
UsePAM no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
Subsystem sftp internal-sftp
""")
    p = subprocess.Popen([SSHD, "-D", "-e", "-f", f"{d}/sshd_config"], stderr=open(f"{d}/log", "w"))
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", port), 0.2).close()
            return p, port, d
        except OSError:
            time.sleep(0.1)
    raise SystemExit("sshd did not start:\n" + open(f"{d}/log").read())


def main():
    sshd, port, sshd_dir = start_sshd()
    daemon_pid = None
    user = os.environ.get("USER") or subprocess.check_output(["id", "-un"], text=True).strip()
    remote = os.path.join(TMP, "remote")
    os.makedirs(remote)
    try:
        # ~/.ssh/config to import (hidden from agents by default)
        os.makedirs(f"{HOME}/.ssh")
        open(f"{HOME}/.ssh/config", "w").write("Host imported\n  HostName 10.9.9.9\n  User bob\n")
        os.makedirs(f"{HOME}/.claude")
        os.makedirs(f"{HOME}/.codex")

        rc, _, err = run("approve")
        check(rc == 2 and "real terminal" in err, "approve refuses to run without a terminal")

        t = Tty("init", "--passphrase")
        t.expect("new vault passphrase: ")
        t.send(PASS)
        t.expect("repeat passphrase: ")
        t.send(PASS)
        t.expect(r"user service\? \[Y/n\] ")
        t.send("n")
        t.expect(r"skill and hook for claude\? \[Y/n\] ")
        t.send("y")
        t.expect(r"skill and hook for codex\? \[Y/n\] ")
        t.send("y")
        check(t.wait() == 0, "init (passphrase mode, imports ~/.ssh/config)", t.buf)
        settings = json.load(open(f"{HOME}/.claude/settings.json"))
        check("hook claude" in json.dumps(settings) and "Bash(ssh:*)" in settings["permissions"]["deny"],
              "init installs the Claude hook and ssh deny rules")
        check(os.path.exists(f"{HOME}/.claude/skills/ostiary/SKILL.md"), "init installs the skill")
        check("hook codex" in open(f"{HOME}/.codex/hooks.json").read() and os.path.exists(f"{HOME}/.codex/rules/ostiary.rules"),
              "init installs the Codex hook and rules")

        rc, _, err = run("hosts")
        check(rc == 102 and err.startswith("ostiary:"), "agent gets 102 while the daemon is down")

        rc, out, _ = run("daemon", "--detach")
        daemon_pid = int(re.search(r"pid (\d+)", out).group(1))
        for _ in range(50):
            if os.path.exists(ENV["OSTIARY_SOCKET"]):
                break
            time.sleep(0.1)
        check(rc == 0, "daemon --detach starts")

        rc, _, err = run("run", "imported", "ls")
        check(rc == 102 and "locked" in err, "vault starts locked in passphrase mode")
        t = Tty("unlock")
        t.expect("vault passphrase: ")
        t.send(PASS)
        check(t.wait() == 0 and "unlocked" in t.buf, "unlock with passphrase", t.buf)

        rc, out = admin("key", "gen", "e2e")
        pub = re.search(r"(ssh-ed25519 \S+)", out)
        check(rc == 0 and pub, "key gen with approval code", out)
        open(f"{sshd_dir}/authorized_keys", "w").write(pub.group(1) + "\n")

        rc, out = admin("host", "add", "e2e", "--host", "127.0.0.1", "--port", str(port), "--user", user,
                        "--key", "e2e", "--agent", "--desc", "e2e test box")
        check(rc == 0, "host add with approval code", out)

        rc, _, err = run("run", "e2e", "echo hi")
        check(rc == 255 and "unknown host key" in err, "unknown host key is refused", err)
        fp = subprocess.check_output(["ssh-keygen", "-lf", f"{sshd_dir}/host_key.pub"], text=True).split()[1]
        rc, out = admin("host", "trust", "e2e")
        check(rc == 0 and fp in out, "host trust shows the right fingerprint", out)

        rc, out, _ = run("hosts")
        check(rc == 0 and out.startswith("e2e\tstandard\te2e test box") and "imported" not in out,
              "hosts lists only agent-enabled hosts", out)

        rc, out, err = run("run", "e2e", "echo hello; uname -s")
        check(rc == 0 and re.match(r"e2e exit=0 [\d.]+s level=read id=\d+\nhello\n", out), "run read command", out + err)

        rc, out, err = run("run", "e2e", "sh -c 'exit 7'")
        check(rc == 7 and not err, "remote exit code passes through", out + err)

        codex_env = {k: v for k, v in ENV.items() if k != "CLAUDECODE"}
        codex_env["CODEX_SANDBOX"] = "seatbelt"
        p = subprocess.Popen([BIN, "run", "e2e", "touch /tmp/x-ostiary-e2e"], env=codex_env, stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        line = p.stderr.readline()
        p.kill()
        check("waiting approval #" in line, "mutate from Codex needs out-of-band approval (no soft ask)", line)
        t = Tty("approve")
        t.expect(r"agent=codex")
        t.expect(r"\[y\] once")
        t.send("n")
        t.expect("denied")
        check(t.wait() == 0, "approve: plain deny")

        rc, _, err = run("run", "e2e", "cat ~/.ssh/id_rsa")
        check(rc == 100 and "forbidden" in err, "forbidden command blocked with 100", err)
        rc, _, err = run("run", "e2e", "top")
        check(rc == 100 and "top -bn1" in err, "interactive command refused with a hint", err)

        rc, out, _ = run("run", "e2e", "seq 1 200")
        oid = re.search(r"id=(\d+)", out).group(1)
        check(rc == 0 and f"120 lines omitted, full: ostiary out {oid}" in out, "long output summarized", out)
        rc, out, _ = run("out", oid, "--grep", "^15[0-2]$")
        check(out == "150: 150\n151: 151\n152: 152\n", "out --grep", out)
        rc, out, _ = run("out", oid, "--range", "199:")
        check(out == "199\n200\n", "out --range", out)

        rc, out, err = run("run", "e2e", "sleep 5", "--timeout", "1s")
        check(rc == 124 and "timed out" in err, "timeout gives 124", out + err)

        # Destructive: agent blocks, human approves in a terminal.
        victim = os.path.join(remote, "victim")
        open(victim, "w").write("x")
        agent = subprocess.Popen([BIN, "run", "e2e", f"rm {victim}"], env=ENV, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        t = Tty("approve")
        t.expect(r"level: .*DESTRUCTIVE")
        t.expect(r"rm " + re.escape(victim))
        code = last_code()
        t.expect(r"\[y\] once")
        t.send("y")
        t.expect(r"approval code \(from the desktop notification\): ")
        t.send("ZZZZ")
        t.expect(r"tries left")
        t.expect(r"\[y\] once")
        t.send("y")
        t.expect(r"approval code \(from the desktop notification\): ")
        t.send(code)
        t.expect("approved once")
        out, err = agent.communicate(timeout=30)
        check(agent.returncode == 0 and "waiting approval #" in err and not os.path.exists(victim),
              "destructive command runs after approval (wrong code first)", out + err)
        t.p.kill()

        victim2 = os.path.join(remote, "victim2")
        open(victim2, "w").write("x")
        agent = subprocess.Popen([BIN, "run", "e2e", f"rm {victim2}"], env=ENV, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        t = Tty("approve")
        t.expect(r"DESTRUCTIVE")
        code = last_code()
        t.expect(r"\[y\] once")
        t.send("m")
        t.expect("message for the agent: ")
        t.send("use logrotate instead")
        t.expect(r"approval code \(from the desktop notification\): ")
        t.send(code)
        out, err = agent.communicate(timeout=30)
        check(agent.returncode == 101 and "use logrotate instead" in err and os.path.exists(victim2),
              "denial with message gives 101", out + err)
        t.p.kill()

        local = os.path.join(TMP, "up.txt")
        open(local, "w").write("payload\n")
        rc, out, err = run("put", local, f"e2e:{remote}/up.txt")
        check(rc == 0 and open(f"{remote}/up.txt").read() == "payload\n", "put", out + err)
        rc, out, err = run("get", f"e2e:{remote}/up.txt", os.path.join(TMP, "down.txt"))
        check(rc == 0 and open(os.path.join(TMP, "down.txt")).read() == "payload\n", "get", out + err)
        rc, _, err = run("put", f"{HOME}/.config/ostiary/vault.bin", f"e2e:{remote}/v")
        check(rc == 100, "uploading the vault is blocked", err)

        rc, out, _ = run("job", "start", "e2e", "for i in 1 2 3; do echo tick $i; sleep 0.2; done")
        jid = re.search(r"id=(\d+)", out).group(1)
        time.sleep(1.5)
        rc, out, _ = run("job", "tail", jid)
        check(f"job {jid} exit=0" in out and "tick 3" in out, "job start + tail", out)
        rc, out, _ = run("job", "start", "e2e", "sleep 30")
        jid = re.search(r"id=(\d+)", out).group(1)
        run("job", "kill", jid)
        time.sleep(0.5)
        rc, out, _ = run("job", "tail", jid)
        check("running" not in out, "job kill", out)

        rc, out, _ = run("explain", "ls; sudo rm -rf /var/log/old", "--host", "e2e")
        check("level=destructive" in out and "action=approve" in out, "explain", out)

        def hook(cmd):
            p = subprocess.run([BIN, "hook", "claude"], env=ENV, capture_output=True, text=True,
                               input=json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd}, "cwd": TMP}))
            return json.loads(p.stdout)["hookSpecificOutput"]["permissionDecision"] if p.stdout else ""
        check(hook("ssh e2e uptime") == "deny", "hook denies direct ssh")
        check(hook('ostiary run e2e "uptime"') == "allow", "hook allows read via the daemon")
        check(hook('ostiary run e2e "systemctl restart nginx"') == "ask", "hook asks for mutate on standard")
        check(hook('ostiary run e2e "cat /etc/shadow"') == "deny", "hook denies forbidden")
        check(hook("ostiary approve") == "deny", "hook denies human-only commands")
        p = subprocess.run([BIN, "hook", "gemini"], env=ENV, capture_output=True, text=True, input=json.dumps(
            {"hook_event_name": "BeforeTool", "tool_name": "run_shell_command", "cwd": TMP, "tool_input": {"command": "scp a e2e:/tmp"}}))
        check(json.loads(p.stdout)["decision"] == "deny", "gemini hook denies scp")
        p = subprocess.run([BIN, "hook", "antigravity"], env=ENV, capture_output=True, text=True, input=json.dumps(
            {"toolCall": {"name": "run_command", "args": {"CommandLine": 'ostiary run e2e "uptime"', "Cwd": TMP}}}))
        check(json.loads(p.stdout)["decision"] == "allow", "antigravity hook allows a read via the daemon")

        # MCP server over stdio, same daemon and policy.
        mcp = subprocess.Popen([BIN, "mcp", "--cwd", TMP], env=ENV, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        def rpc(i, method, params=None):
            mcp.stdin.write(json.dumps({"jsonrpc": "2.0", "id": i, "method": method, "params": params or {}}) + "\n")
            mcp.stdin.flush()
            return json.loads(mcp.stdout.readline())
        def tool(i, name, **args):
            r = rpc(i, "tools/call", {"name": name, "arguments": args})["result"]
            return r["content"][0]["text"], r["isError"]
        init = rpc(1, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "e2e", "version": "0"}})
        mcp.stdin.write('{"jsonrpc":"2.0","method":"notifications/initialized"}\n')
        check(init["result"]["serverInfo"]["name"] == "ostiary" and len(rpc(2, "tools/list")["result"]["tools"]) == 9,
              "mcp initialize + tools/list")
        text, err = tool(3, "run", host="e2e", command="echo via-mcp")
        check(not err and "level=read" in text and "via-mcp" in text, "mcp run read", text)
        text, err = tool(4, "run", host="e2e", command="cat /etc/shadow")
        check(err and "code 100" in text, "mcp blocks forbidden", text)
        victim3 = os.path.join(remote, "victim3")
        open(victim3, "w").write("x")
        text, err = tool(5, "run", host="e2e", command=f"rm {victim3}")
        aid = int(re.search(r"approval_id=(\d+)", text).group(1))
        check(not err and "approval required" in text, "mcp returns approval id instead of blocking", text)
        t = Tty("approve")
        t.expect(r"DESTRUCTIVE")
        t.expect(r"\[y\] once")
        t.send("y")
        t.expect(r"approval code \(from the desktop notification\): ")
        t.send(last_code())
        t.expect("approved once")
        t.p.kill()
        text, err = tool(6, "run", host="e2e", command=f"rm {victim3}", approval_id=aid)
        check(not err and "exit=0" in text and not os.path.exists(victim3), "mcp run after approval", text)
        mcp.stdin.close()
        check(mcp.wait(timeout=10) == 0, "mcp exits on EOF")

        rc, out, _ = run("log", "-n", "100")
        check("approved" in out and "forbidden" in out and "denied" in out and "payload" not in out,
              "audit log has decisions and no output", out)

        rc, out, _ = run("doctor")
        check("ok    daemon is running" in out and "ok    desktop notification sent" in out, "doctor", out)

        # Config edited behind the daemon's back.
        with open(f"{HOME}/.config/ostiary/hosts.toml", "a") as f:
            f.write('\n[hosts.sneaky]\nhost = "1.2.3.4"\nagent = true\n')
        run("lock")
        t = Tty("unlock")
        t.expect("vault passphrase: ")
        t.send(PASS)
        t.wait()
        rc, _, err = run("run", "e2e", "echo hi")
        check(rc == 100 and "reload" in err, "tampered config refuses agent requests", err)
        rc, out = admin("reload")
        rc2, _, _ = run("run", "e2e", "echo hi")
        check(rc == 0 and rc2 == 0, "reload with code accepts the config again", out)

        t = Tty("key", "export", "e2e")
        t.expect(r"approval code \(from the desktop notification\): ")
        t.send(last_code())
        t.expect("vault passphrase: ")
        t.send(PASS)
        t.wait()
        check("BEGIN OPENSSH PRIVATE KEY" in t.buf, "key export needs code + passphrase")

        run("lock")
        rc, _, err = run("run", "e2e", "echo hi")
        check(rc == 102 and "locked" in err, "lock wipes keys: 102")

        # OS mode, with the fake dialog of the e2efake build.
        os.kill(daemon_pid, signal.SIGTERM)
        time.sleep(0.5)
        gate = os.path.join(TMP, "humanok")
        open(gate, "w").write("deny")
        ENV["OSTIARY_E2E_HUMANOK"] = gate
        ENV["OSTIARY_OS_AUTH"] = "1"  # OS mode on every OS for the fake confirmer
        out = subprocess.run([BIN, "daemon", "--detach"], env=ENV, capture_output=True, text=True).stdout
        daemon_pid = int(re.search(r"pid (\d+)", out).group(1))
        for _ in range(50):
            if os.path.exists(ENV["OSTIARY_SOCKET"]):
                break
            time.sleep(0.1)
        t = Tty("unlock")
        t.expect("vault passphrase: ")
        t.send(PASS)
        t.wait()
        rc, out, _ = run("doctor")
        check("approvals use OS authentication" in out, "doctor reports OS authentication", out)
        ui = UI()
        check(ui.login() == 303 and ui.cookie and ui.cookie.startswith("ostiary="), "UI login exchanges the nonce for a cookie")
        check(ui.req("GET", ui.loginpath(), cookie=False)[0] == 401, "a login link works only once")
        check(not os.path.exists(os.path.join(HOME, ".local", "state", "ostiary", "ui.url")), "no ui.url file is written")
        check(ui.req("GET", "/api/pending", cookie=False)[0] == 401, "UI refuses requests without the cookie")
        check(ui.req("GET", "/api/pending", host="evil.example")[0] == 421, "UI refuses a foreign Host header")
        check(ui.req("POST", "/api/lock", origin="http://evil.example")[0] == 403, "UI refuses a cross-origin POST")
        st, _, body = ui.req("GET", "/api/hosts")
        check(st == 200 and '"e2e"' in body, "UI lists hosts", body)
        victimui = os.path.join(remote, "victimui")
        open(victimui, "w").write("x")
        open(gate, "w").write("allow")
        agent = subprocess.Popen([BIN, "run", "e2e", f"rm {victimui}"], env=ENV, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        rid = None
        for _ in range(50):
            pend = json.loads(ui.req("GET", "/api/pending")[2])
            if pend:
                rid = pend[0]["id"]
                break
            time.sleep(0.2)
        st, _, body = ui.req("POST", "/api/decide", {"id": rid, "choice": "y"})
        out, err = agent.communicate(timeout=30)
        check(st == 200 and agent.returncode == 0 and not os.path.exists(victimui),
              "approve from the UI (OS authentication) runs the command", body + out + err)
        st, _, body = ui.req("GET", "/api/audit?host=e2e&limit=5")
        check(st == 200 and f"rm {victimui}" in body, "UI shows the audit log", body)
        notes = open(NOTES).read()
        check(f"#req={rid}" in notes, "approval notification links to the UI request", notes[-300:])
        open(gate, "w").write("deny")
        victimd = os.path.join(remote, "victimd")
        open(victimd, "w").write("x")
        agent = subprocess.Popen([BIN, "run", "e2e", f"rm {victimd}"], env=ENV, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        rid = None
        for _ in range(50):
            pend = json.loads(ui.req("GET", "/api/pending")[2])
            if pend:
                rid = pend[0]["id"]
                break
            time.sleep(0.2)
        check(rid is not None, "UI deny path: the request appeared in pending")
        st, _, body = ui.req("POST", "/api/decide", {"id": rid, "choice": "y"})
        check(st == 400 and os.path.exists(victimd), "UI approve is refused when the OS dialog denies", body)
        st, _, body = ui.req("POST", "/api/decide", {"id": rid, "choice": "n"})
        out, err = agent.communicate(timeout=30)
        check(st == 200 and agent.returncode == 101 and os.path.exists(victimd), "UI deny needs no authentication", body + out + err)
        victim4 = os.path.join(remote, "victim4")
        open(victim4, "w").write("x")
        agent = subprocess.Popen([BIN, "run", "e2e", f"rm {victim4}"], env=ENV, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        t = Tty("approve")
        t.expect(r"DESTRUCTIVE")
        t.expect(r"\[y\] once")
        t.send("y")
        t.expect("not confirmed")          # OS dialog refused
        open(gate, "w").write("allow")
        t.expect(r"\[y\] once")
        t.send("y")
        t.expect("approved once")
        out, err = agent.communicate(timeout=30)
        log = open(gate + ".log").read()
        check(agent.returncode == 0 and not os.path.exists(victim4) and f"rm {victim4}" in log,
              "approve via OS authentication (no code), dialog shows the command", out + err + log)
        t.p.kill()
        t = Tty("key", "gen", "osauth")
        t.expect(r"ssh-ed25519 ")
        check(t.wait() == 0 and "key-gen osauth" in open(gate + ".log").read(), "admin op via OS authentication")
        # The OS dialog breaks: the daemon stays in OS mode; the human can still deny.
        open(gate, "w").write("unavailable")
        victim5 = os.path.join(remote, "victim5")
        open(victim5, "w").write("x")
        agent = subprocess.Popen([BIN, "run", "e2e", f"rm {victim5}"], env=ENV, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        t = Tty("approve")
        t.expect(r"DESTRUCTIVE")
        t.expect(r"\[y\] once")
        t.send("y")
        t.expect("OSTIARY_OS_AUTH=0")
        t.expect(r"\[y\] once")
        t.send("n")
        t.expect("denied")
        out, err = agent.communicate(timeout=30)
        check(agent.returncode == 101 and os.path.exists(victim5),
              "OS dialog breaks: error names OSTIARY_OS_AUTH=0, deny still works", out + err)
        t.p.kill()
        rc, out, _ = run("doctor")
        check("approvals use OS authentication" in out, "a broken dialog does not switch to codes", out)
        ENV.pop("OSTIARY_E2E_HUMANOK")
        # upgrade --check against a fake release server (never the real network)
        class Rel(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                body = json.dumps({"tag_name": "v99.0.0", "html_url": "https://example.invalid/r", "body": "", "assets": []}).encode()
                self.send_response(200 if self.path.endswith("/releases/latest") else 404)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass
        rel = http.server.HTTPServer(("127.0.0.1", 0), Rel)
        threading.Thread(target=rel.serve_forever, daemon=True).start()
        ENV["OSTIARY_E2E_RELEASES_URL"] = f"http://127.0.0.1:{rel.server_port}"
        rc, out, err = run("upgrade", "--check")
        rel.shutdown()
        ENV.pop("OSTIARY_E2E_RELEASES_URL")
        check(rc == 10 and "99.0.0" in out, "upgrade --check reports a newer release (exit 10)", out + err)
        os.kill(daemon_pid, signal.SIGTERM)
        daemon_pid = None
        time.sleep(0.5)
        rc, _, _ = run("hosts")
        check(rc == 102 and not os.path.exists(ENV["OSTIARY_SOCKET"]), "daemon stops cleanly")
        print(f"\nall {passed} checks passed")
    finally:
        if daemon_pid:
            os.kill(daemon_pid, signal.SIGTERM)
        sshd.terminate()
        shutil.rmtree(TMP, ignore_errors=True)


if __name__ == "__main__":
    main()
