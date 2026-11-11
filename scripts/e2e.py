#!/usr/bin/env python3
"""End-to-end test: the real agentssh binary against a real OpenSSH sshd.

Linux/macOS only. Everything lives in a temp dir (HOME, XDG dirs, sshd), so
it never touches your keyring, ~/.claude or services. The D-Bus session is
hidden, which forces passphrase mode and makes desktop notifications fail,
so approval codes are shown in the terminal where this script can read them.

usage: go build -o /tmp/agentssh . && python3 scripts/e2e.py /tmp/agentssh
"""
import fcntl, json, os, re, select, shutil, signal, socket, subprocess, sys, tempfile, termios, time

BIN = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "agentssh")
SSHD = shutil.which("sshd") or "/usr/sbin/sshd"
TMP = tempfile.mkdtemp(prefix="agentssh-e2e-")
HOME = os.path.join(TMP, "home")
PASS = "correct horse battery"
os.makedirs(HOME)

ENV = {k: v for k, v in os.environ.items() if k not in ("DISPLAY", "WAYLAND_DISPLAY", "CLAUDECODE")}
ENV.update(HOME=HOME, XDG_CONFIG_HOME=f"{HOME}/.config", XDG_STATE_HOME=f"{HOME}/.local/state",
           XDG_RUNTIME_DIR=f"{TMP}/run", AGENTSSH_SOCKET=f"{TMP}/s.sock",
           DBUS_SESSION_BUS_ADDRESS="unix:path=/nonexistent", TERM="dumb")
os.makedirs(ENV["XDG_RUNTIME_DIR"], mode=0o700)

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


def admin(*args, extra=None):
    """Run a code-protected admin command, reading the fallback code from the screen."""
    t = Tty(*args)
    code = t.expect(r"approval code: ([A-Z0-9]{4})").group(1)
    if extra:
        extra(t)
    t.expect(r"approval code \(from the desktop notification\): ")
    t.send(code)
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

        rc, _, err = run("approve")
        check(rc == 2 and "real terminal" in err, "approve refuses to run without a terminal")

        t = Tty("init", "--passphrase")
        t.expect("new vault passphrase: ")
        t.send(PASS)
        t.expect("repeat passphrase: ")
        t.send(PASS)
        t.expect(r"user service\? \[Y/n\] ")
        t.send("n")
        t.expect(r"skill and hook\? \[Y/n\] ")
        t.send("y")
        check(t.wait() == 0, "init (passphrase mode, imports ~/.ssh/config)", t.buf)
        settings = json.load(open(f"{HOME}/.claude/settings.json"))
        check("hook claude" in json.dumps(settings) and "Bash(ssh:*)" in settings["permissions"]["deny"],
              "init installs the Claude hook and ssh deny rules")
        check(os.path.exists(f"{HOME}/.claude/skills/agentssh/SKILL.md"), "init installs the skill")

        rc, _, err = run("hosts")
        check(rc == 102 and err.startswith("agentssh:"), "agent gets 102 while the daemon is down")

        rc, out, _ = run("daemon", "--detach")
        daemon_pid = int(re.search(r"pid (\d+)", out).group(1))
        for _ in range(50):
            if os.path.exists(ENV["AGENTSSH_SOCKET"]):
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

        rc, _, err = run("run", "e2e", "cat ~/.ssh/id_rsa")
        check(rc == 100 and "forbidden" in err, "forbidden command blocked with 100", err)
        rc, _, err = run("run", "e2e", "top")
        check(rc == 100 and "top -bn1" in err, "interactive command refused with a hint", err)

        rc, out, _ = run("run", "e2e", "seq 1 200")
        oid = re.search(r"id=(\d+)", out).group(1)
        check(rc == 0 and f"120 lines omitted, full: agentssh out {oid}" in out, "long output summarized", out)
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
        code = t.expect(r"approval code: ([A-Z0-9]{4})").group(1)
        t.expect(r"approval code \(from the desktop notification\): ")
        t.send("ZZZZ")
        t.expect(r"\[y\] once")
        t.send("y")
        t.expect(r"tries left")
        t.expect(r"approval code \(from the desktop notification\): ")
        t.send(code)
        t.expect(r"\[y\] once")
        t.send("y")
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
        code = t.expect(r"approval code: ([A-Z0-9]{4})").group(1)
        t.expect(r"approval code \(from the desktop notification\): ")
        t.send(code)
        t.expect(r"\[y\] once")
        t.send("m")
        t.expect("message for the agent: ")
        t.send("use logrotate instead")
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
        rc, _, err = run("put", f"{HOME}/.config/agentssh/vault.bin", f"e2e:{remote}/v")
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
        check(hook('agentssh run e2e "uptime"') == "allow", "hook allows read via the daemon")
        check(hook('agentssh run e2e "systemctl restart nginx"') == "ask", "hook asks for mutate on standard")
        check(hook('agentssh run e2e "cat /etc/shadow"') == "deny", "hook denies forbidden")
        check(hook("agentssh approve") == "deny", "hook denies human-only commands")

        rc, out, _ = run("log", "-n", "100")
        check("approved" in out and "forbidden" in out and "denied" in out and "payload" not in out,
              "audit log has decisions and no output", out)

        rc, out, _ = run("doctor")
        check("ok    daemon is running" in out and "WARN  desktop notifications do not work" in out, "doctor", out)

        # Config edited behind the daemon's back.
        with open(f"{HOME}/.config/agentssh/hosts.toml", "a") as f:
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
        code = t.expect(r"approval code: ([A-Z0-9]{4})").group(1)
        t.expect(r"approval code \(from the desktop notification\): ")
        t.send(code)
        t.expect("vault passphrase: ")
        t.send(PASS)
        t.wait()
        check("BEGIN OPENSSH PRIVATE KEY" in t.buf, "key export needs code + passphrase")

        run("lock")
        rc, _, err = run("run", "e2e", "echo hi")
        check(rc == 102 and "locked" in err, "lock wipes keys: 102")

        os.kill(daemon_pid, signal.SIGTERM)
        daemon_pid = None
        time.sleep(0.5)
        rc, _, _ = run("hosts")
        check(rc == 102 and not os.path.exists(ENV["AGENTSSH_SOCKET"]), "daemon stops cleanly")
        print(f"\nall {passed} checks passed")
    finally:
        if daemon_pid:
            os.kill(daemon_pid, signal.SIGTERM)
        sshd.terminate()
        shutil.rmtree(TMP, ignore_errors=True)


if __name__ == "__main__":
    main()
