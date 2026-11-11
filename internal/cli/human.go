package cli

import (
	"bufio"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ASromancer/agentssh/internal/approval"
	"github.com/ASromancer/agentssh/internal/audit"
	"github.com/ASromancer/agentssh/internal/daemon"
	"github.com/ASromancer/agentssh/internal/hosts"
	"github.com/ASromancer/agentssh/internal/humanok"
	"github.com/ASromancer/agentssh/internal/paths"
	"github.com/ASromancer/agentssh/internal/policy"
	"github.com/ASromancer/agentssh/internal/vault"
)

const approvalTimeout = 120 * time.Second

func cmdDaemon(args []string) int {
	fs := newFlags("daemon")
	detach := fs.Bool("detach", false, "start the daemon in the background and return")
	logFile := fs.String("log", "", "append logs to this file")
	if _, err := parse(fs, args); err != nil {
		return 2
	}
	if *detach {
		if err := startDetached(filepath.Join(paths.State(), "daemon.log")); err != nil {
			return errf(1, "%v", err)
		}
		return 0
	}
	if *logFile != "" {
		os.MkdirAll(filepath.Dir(*logFile), 0o700)
		f, err := os.OpenFile(*logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return errf(1, "%v", err)
		}
		log.SetOutput(f)
	}
	d, err := daemon.New(approval.Notify, approvalTimeout)
	if err != nil {
		return errf(1, "%v", err)
	}
	if err := d.Serve(); err != nil {
		log.Print(err)
		return 1
	}
	return 0
}

// admin runs an admin operation confirmed by OS authentication or, when
// the daemon started in code mode, a code.
func admin(t *term, a daemon.AdminArgs) (string, int) {
	c, code := dial()
	if c == nil {
		return "", code
	}
	defer c.Close()
	var b daemon.BeginReply
	if err := c.Call("A.Begin", &daemon.BeginArgs{Op: a.Op, Name: a.Name}, &b); err != nil {
		return "", errf(1, "%v", err)
	}
	if b.Info != "" {
		t.printf("%s\n", b.Info)
	}
	if b.Code != "" {
		t.printf("desktop notification failed; approval code: %s\n", b.Code)
	}
	a.Ticket = b.Ticket
	if b.OSAuth {
		t.printf("confirm in the system authentication dialog…\n")
		var r daemon.AdminReply
		if err := c.Call("A.Admin", &a, &r); err != nil {
			return "", errf(1, "%v", err)
		}
		return r.Out, 0
	}
	for {
		a.Code = t.prompt("approval code (from the desktop notification): ")
		var r daemon.AdminReply
		err := c.Call("A.Admin", &a, &r)
		if err == nil {
			return r.Out, 0
		}
		if strings.Contains(err.Error(), approval.ErrBadCode.Error()) && strings.Contains(err.Error(), "tries left") {
			t.printf("%v\n", err)
			continue
		}
		return "", errf(1, "%v", err)
	}
}

func adminSimple(what string, a daemon.AdminArgs) int {
	t, code := openTTY(what)
	if t == nil {
		return code
	}
	out, code := admin(t, a)
	if code != 0 {
		return code
	}
	if out != "" {
		fmt.Println(out)
	}
	return 0
}

func cmdReload(args []string) int {
	return adminSimple("reload", daemon.AdminArgs{Op: "reload"})
}

func cmdUnlock(args []string) int {
	c, code := dial()
	if c == nil {
		return code
	}
	defer c.Close()
	var st daemon.StatusReply
	if err := c.Call("A.Status", &daemon.Empty{}, &st); err != nil {
		return callErr(err)
	}
	a := daemon.UnlockArgs{}
	if st.Passphrase {
		t, code := openTTY("unlock")
		if t == nil {
			return code
		}
		a.Pass = t.secret("vault passphrase: ")
	}
	if err := c.Call("A.Unlock", &a, &daemon.Empty{}); err != nil {
		return errf(1, "%v", err)
	}
	fmt.Println("vault unlocked")
	return 0
}

func cmdLock(args []string) int {
	c, code := dial()
	if c == nil {
		return code
	}
	defer c.Close()
	if err := c.Call("A.Lock", &daemon.Empty{}, &daemon.Empty{}); err != nil {
		return callErr(err)
	}
	fmt.Println("vault locked; keys removed from daemon memory")
	return 0
}

const (
	red   = "\x1b[1;31m"
	bold  = "\x1b[1m"
	reset = "\x1b[0m"
)

func highlight(cmd string, reasons []policy.Reason, min policy.Level) string {
	mark := make([]bool, len(cmd))
	for _, r := range reasons {
		if r.Level < min {
			continue
		}
		for i := max(r.Start, 0); i < r.End && i < len(cmd); i++ {
			mark[i] = true
		}
	}
	var b strings.Builder
	on := false
	for i := 0; i < len(cmd); i++ {
		if mark[i] != on {
			on = mark[i]
			b.WriteString(map[bool]string{true: red, false: reset}[on])
		}
		b.WriteByte(cmd[i])
	}
	if on {
		b.WriteString(reset)
	}
	return b.String()
}

func cmdApprove(args []string) int {
	t, code := openTTY("approve")
	if t == nil {
		return code
	}
	c, code := dial()
	if c == nil {
		return code
	}
	defer c.Close()
	var st daemon.StatusReply
	if err := c.Call("A.Status", &daemon.Empty{}, &st); err != nil {
		return callErr(err)
	}
	osAuth := st.Auth == "os"
	handled, waiting := 0, false
	for {
		var reqs []approval.Request
		if err := c.Call("A.Pending", &daemon.Empty{}, &reqs); err != nil {
			return callErr(err)
		}
		if len(reqs) == 0 {
			if handled > 0 {
				return 0
			}
			if !waiting {
				t.printf("no pending requests; waiting… (Ctrl-C to quit)\n")
				waiting = true
			}
			time.Sleep(time.Second)
			continue
		}
		for _, r := range reqs {
			decideOne(t, c, r, osAuth)
			handled++
		}
	}
}

func decideOne(t *term, c interface {
	Call(string, any, any) error
}, r approval.Request, osAuth bool) {
	t.printf("\n%s#%d%s  %s  agent=%s  kind=%s\n", bold, r.ID, reset, r.Time.Format("2006-01-02 15:04:05"), orDash(r.Agent), r.Kind)
	t.printf("host:  %s (user %s)\ncwd:   %s\nrepo:  %s\n", r.Host, orDash(r.User), orDash(r.Cwd), orDash(r.Repo))
	t.printf("level: %s%s%s\n", red, strings.ToUpper(r.Level), reset)
	cmd := r.Cmd
	if r.Kind == "run" || r.Kind == "job" {
		cmd = highlight(r.Cmd, r.Reasons, policy.Destructive)
	}
	t.printf("command (exactly what will run):\n  %s\nreasons:\n", cmd)
	for _, x := range r.Reasons {
		if x.Level >= policy.Mutate {
			t.printf("  - [%s] %s\n", x.Level, x.Text)
		}
	}
	if r.Code != "" {
		t.printf("desktop notification failed; approval code: %s\n", r.Code)
	}
	for {
		choice := ""
		for choice == "" {
			switch a := strings.ToLower(t.prompt("[y] once  [s] same command 30 min  [n] deny  [m] deny with message: ")); a {
			case "y", "s", "n", "m":
				choice = a
			}
		}
		note, code := "", ""
		if choice == "m" {
			note = t.prompt("message for the agent: ")
		}
		switch {
		case choice == "n":
		case osAuth:
			t.printf("confirm in the system authentication dialog…\n")
		default:
			code = t.prompt("approval code (from the desktop notification): ")
		}
		err := c.Call("A.Decide", &daemon.DecideArgs{ID: r.ID, Code: code, Choice: choice, Note: note}, &daemon.Empty{})
		if err == nil {
			t.printf("#%d: %s\n", r.ID, map[string]string{"y": "approved once", "s": "approved for 30 minutes", "n": "denied", "m": "denied"}[choice])
			return
		}
		t.printf("%v\n", err)
		// Back to the choice prompt: the user can retry, or deny with n.
		if !strings.Contains(err.Error(), "tries left") && !strings.Contains(err.Error(), "not confirmed") &&
			!strings.Contains(err.Error(), "already in progress") && !strings.Contains(err.Error(), "OS authentication failed") {
			return
		}
	}
}

func cmdInstallPolkit(args []string) int {
	if err := humanok.InstallPolicy(); err != nil {
		return errf(1, "%v", err)
	}
	fmt.Println("installed", humanok.PolicyPath, "— restart the daemon: systemctl --user restart agentssh")
	return 0
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func hostFlags(fs *flag.FlagSet, h *hosts.Host) (allow, deny *multi) {
	fs.StringVar(&h.Host, "host", h.Host, "hostname or IP")
	fs.StringVar(&h.User, "user", h.User, "remote user")
	fs.IntVar(&h.Port, "port", h.Port, "port (default 22)")
	fs.StringVar(&h.Key, "key", h.Key, "name of the key in the vault")
	fs.StringVar(&h.Profile, "profile", h.Profile, "readonly|standard|full")
	fs.BoolVar(&h.Agent, "agent", h.Agent, "visible to agents")
	fs.StringVar(&h.Description, "desc", h.Description, "description shown to agents")
	allow, deny = &multi{}, &multi{}
	fs.Var(allow, "allow", "pattern lowered to read (repeatable; replaces the list)")
	fs.Var(deny, "deny", "pattern raised to forbidden (repeatable; replaces the list)")
	return allow, deny
}

func cmdHost(args []string) int {
	if len(args) == 0 {
		return errf(2, "usage: agentssh host add|edit|ls|rm|trust ...")
	}
	sub := args[0]
	cfg, err := hosts.Load(paths.Hosts())
	if err != nil {
		return errf(1, "%v", err)
	}
	switch sub {
	case "ls":
		for name, h := range cfg.Hosts {
			fmt.Printf("%s\t%s@%s\tprofile=%s\tagent=%v\tkey=%s\t%s\n", name, orDash(h.User), h.Addr(), h.EffectiveProfile(), h.Agent, orDash(h.Key), h.Description)
		}
		return 0
	case "add", "edit":
		h := &hosts.Host{Profile: policy.ProfileStandard}
		if len(args) > 1 && cfg.Hosts[args[1]] != nil {
			cp := *cfg.Hosts[args[1]]
			h = &cp
		}
		fs := newFlags("host " + sub)
		allow, deny := hostFlags(fs, h)
		pos, err := parse(fs, args[1:])
		if err != nil {
			return 2
		}
		if len(pos) != 1 {
			return errf(2, "usage: agentssh host %s <name> [--host H --user U --port P --key K --profile P --agent --desc D --allow PAT --deny PAT]", sub)
		}
		name := pos[0]
		if sub == "add" && cfg.Hosts[name] != nil {
			return errf(1, "host %q exists; use 'agentssh host edit'", name)
		}
		if sub == "edit" && cfg.Hosts[name] == nil {
			return errf(1, "unknown host %q", name)
		}
		fs.Visit(func(f *flag.Flag) {
			switch f.Name {
			case "allow":
				h.Allow = *allow
			case "deny":
				h.Deny = *deny
			}
		})
		if err := h.Validate(); err != nil {
			return errf(2, "%v", err)
		}
		return adminSimple("host "+sub, daemon.AdminArgs{Op: "host-set", Name: name, Host: h})
	case "rm", "trust":
		if len(args) != 2 {
			return errf(2, "usage: agentssh host %s <name>", sub)
		}
		op := map[string]string{"rm": "host-rm", "trust": "trust"}[sub]
		return adminSimple("host "+sub, daemon.AdminArgs{Op: op, Name: args[1]})
	}
	return errf(2, "unknown host subcommand %q", sub)
}

func cmdKey(args []string) int {
	if len(args) == 0 {
		return errf(2, "usage: agentssh key gen|import|export|ls|rm ...")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "ls":
		c, code := dial()
		if c == nil {
			return code
		}
		defer c.Close()
		var r daemon.KeysReply
		if err := c.Call("A.Keys", &daemon.Empty{}, &r); err != nil {
			return callErr(err)
		}
		for _, k := range r.Keys {
			fmt.Println(k)
		}
		return 0
	case "gen":
		if len(rest) != 1 {
			return errf(2, "usage: agentssh key gen <name>")
		}
		t, code := openTTY("key gen")
		if t == nil {
			return code
		}
		out, code := admin(t, daemon.AdminArgs{Op: "key-gen", Name: rest[0]})
		if code != 0 {
			return code
		}
		fmt.Println(out)
		fmt.Fprintln(os.Stderr, "Add this public key to ~/.ssh/authorized_keys on the server (one key per agent; not your personal key).")
		return 0
	case "rm":
		if len(rest) != 1 {
			return errf(2, "usage: agentssh key rm <name>")
		}
		return adminSimple("key rm", daemon.AdminArgs{Op: "key-rm", Name: rest[0]})
	case "import":
		fs := newFlags("key import")
		pw := fs.Bool("password", false, "store a password instead of a key file")
		pos, err := parse(fs, rest)
		if err != nil {
			return 2
		}
		if (*pw && len(pos) != 1) || (!*pw && len(pos) != 2) {
			return errf(2, "usage: agentssh key import <name> <private-key-path> | agentssh key import <name> --password")
		}
		t, code := openTTY("key import")
		if t == nil {
			return code
		}
		a := daemon.AdminArgs{Op: "key-import", Name: pos[0]}
		if *pw {
			a.Password = []byte(t.secret("password: "))
		} else {
			b, err := os.ReadFile(pos[1])
			if err != nil {
				return errf(1, "%v", err)
			}
			raw, err := ssh.ParseRawPrivateKey(b)
			var missing *ssh.PassphraseMissingError
			if errors.As(err, &missing) {
				raw, err = ssh.ParseRawPrivateKeyWithPassphrase(b, []byte(t.secret("key passphrase: ")))
			}
			if err != nil {
				return errf(1, "parse key: %v", err)
			}
			block, err := ssh.MarshalPrivateKey(raw, "agentssh-"+pos[0])
			if err != nil {
				return errf(1, "%v", err)
			}
			a.PEM = pem.EncodeToMemory(block)
		}
		out, code := admin(t, a)
		if code != 0 {
			return code
		}
		fmt.Println(out)
		return 0
	case "export":
		if len(rest) != 1 {
			return errf(2, "usage: agentssh key export <name>")
		}
		t, code := openTTY("key export")
		if t == nil {
			return code
		}
		if _, code := admin(t, daemon.AdminArgs{Op: "key-export", Name: rest[0]}); code != 0 {
			return code
		}
		// Decrypt locally: no RPC ever returns key material.
		d, err := openVaultLocally(t)
		if err != nil {
			return errf(1, "%v", err)
		}
		defer d.Wipe()
		os.Stdout.Write(d.Keys[rest[0]])
		return 0
	}
	return errf(2, "unknown key subcommand %q", sub)
}

func openVaultLocally(t *term) (*vault.Data, error) {
	salt, err := vault.Salt(paths.Vault())
	if err != nil {
		return nil, err
	}
	var key *[32]byte
	if salt == nil {
		if key, err = vault.KeyringGet(); err != nil {
			return nil, err
		}
	} else {
		key = vault.DeriveKey([]byte(t.secret("vault passphrase: ")), salt)
	}
	return vault.Open(paths.Vault(), key)
}

func cmdLog(args []string) int {
	fs := newFlags("log")
	follow := fs.Bool("follow", false, "keep printing new entries")
	n := fs.Int("n", 50, "number of recent entries")
	if _, err := parse(fs, args); err != nil {
		return 2
	}
	f, err := os.Open(paths.Audit())
	if err != nil {
		return errf(1, "no audit log yet (%v)", err)
	}
	defer f.Close()
	br := bufio.NewReader(f)
	var recent []string
	for {
		l, err := br.ReadString('\n')
		if err != nil {
			break
		}
		recent = append(recent, l)
		if len(recent) > *n {
			recent = recent[1:]
		}
	}
	for _, l := range recent {
		printEntry(l)
	}
	for *follow {
		l, err := br.ReadString('\n')
		if err == io.EOF {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		if err != nil {
			return errf(1, "%v", err)
		}
		printEntry(l)
	}
	return 0
}

func printEntry(line string) {
	var e audit.Entry
	if json.Unmarshal([]byte(line), &e) != nil {
		return
	}
	exit := ""
	if e.Exit != nil {
		exit = fmt.Sprintf(" exit=%d %.1fs", *e.Exit, float64(e.DurationMs)/1000)
	}
	note := ""
	if e.Note != "" {
		note = "  (" + e.Note + ")"
	}
	fmt.Printf("%s #%d %s %s %s %s%s  %s%s\n", e.Time.Local().Format("2006-01-02 15:04:05"), e.ID, e.Kind,
		orDash(e.Host), orDash(e.Level), e.Decision, exit, e.Cmd, note)
}

func cmdDoctor(args []string) int {
	problems := 0
	ok := func(s string) { fmt.Println("ok    " + s) }
	warn := func(s string) { problems++; fmt.Println("WARN  " + s) }

	if c, err := daemon.Dial(); err != nil {
		warn("daemon is not running (systemctl --user start agentssh, or agentssh daemon --detach)")
	} else {
		var st daemon.StatusReply
		if err := c.Call("A.Status", &daemon.Empty{}, &st); err != nil {
			warn("daemon status: " + err.Error())
		} else {
			ok("daemon is running")
			switch {
			case st.VaultMissing:
				warn("no vault; run 'agentssh init'")
			case st.Locked:
				warn("vault is locked; run 'agentssh unlock'")
			default:
				ok("vault is unlocked")
			}
			if st.UserOnly {
				warn("config changed on disk; agent requests are refused until 'agentssh reload'")
			}
			if st.Auth == "os" {
				ok("approvals use OS authentication")
			} else {
				warn("approvals use codes from desktop notifications (" + st.AuthNote + ")")
			}
		}
		c.Close()
	}

	home, _ := os.UserHomeDir()
	for _, in := range installers {
		if !in.detect(home) {
			continue
		}
		b, _ := os.ReadFile(hookFile(in.name, home))
		if strings.Contains(string(b), "hook "+in.name) || (in.name == "claude" && strings.Contains(string(b), "agentssh@")) {
			ok(in.name + ": agentssh hook installed")
		} else {
			warn(in.name + ": agentssh hook not installed; direct ssh is not blocked (agentssh install-hooks " + in.name + ")")
		}
	}

	if err := approval.Notify("agentssh doctor", "test notification"); err != nil {
		warn("desktop notifications do not work (" + err.Error() + "): approval codes will be shown in the terminal, " +
			"so an agent that can fake a TTY could approve itself; prefer hardened mode on this machine")
	} else {
		ok("desktop notification sent (check that you saw it)")
	}

	keys, _ := filepath.Glob(filepath.Join(home, ".ssh", "id_*"))
	for _, k := range keys {
		if strings.HasSuffix(k, ".pub") {
			continue
		}
		b, err := os.ReadFile(k)
		if err != nil {
			continue
		}
		if _, err := ssh.ParseRawPrivateKey(b); err == nil {
			warn(k + " has no passphrase: agents running as you can read it")
		}
	}
	if problems == 0 {
		fmt.Println("all good")
		return 0
	}
	return 1
}

func cmdInit(args []string) int {
	fs := newFlags("init")
	usePass := fs.Bool("passphrase", false, "protect the vault with a passphrase instead of the OS keyring")
	if _, err := parse(fs, args); err != nil {
		return 2
	}
	t, code := openTTY("init")
	if t == nil {
		return code
	}
	if _, err := os.Stat(paths.Vault()); err == nil {
		return errf(1, "already initialized (%s exists)", paths.Vault())
	}
	for _, d := range []string{paths.Config(), paths.State(), paths.Out()} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return errf(1, "%v", err)
		}
	}

	key, salt := vault.NewKey(), []byte(nil)
	keyringErr := errors.New("--passphrase given")
	if !*usePass {
		keyringErr = vault.KeyringSet(key)
	}
	if err := keyringErr; err != nil {
		t.printf("not using the OS keyring (%v); the vault will use a passphrase.\n", err)
		for {
			p1 := t.secret("new vault passphrase: ")
			if len(p1) < 8 {
				t.printf("use at least 8 characters\n")
				continue
			}
			if t.secret("repeat passphrase: ") == p1 {
				salt = vault.NewSalt()
				key = vault.DeriveKey([]byte(p1), salt)
				break
			}
			t.printf("passphrases differ\n")
		}
	} else {
		t.printf("master key stored in the OS keyring\n")
	}

	if _, err := os.Stat(paths.Hosts()); errors.Is(err, os.ErrNotExist) {
		cfg := &hosts.Config{Hosts: map[string]*hosts.Host{}}
		home, _ := os.UserHomeDir()
		if imported, err := hosts.ImportSSHConfig(filepath.Join(home, ".ssh", "config")); err == nil {
			cfg.Hosts = imported
			t.printf("imported %d hosts from ~/.ssh/config (hidden from agents until 'agentssh host edit <name> --agent --key <key>')\n", len(imported))
		}
		if err := cfg.Save(paths.Hosts()); err != nil {
			return errf(1, "%v", err)
		}
	}
	if err := vault.Save(paths.Vault(), key, salt, &vault.Data{ConfigHash: daemon.ConfigHash()}); err != nil {
		return errf(1, "%v", err)
	}
	t.printf("vault created: %s\n", paths.Vault())

	if t.yes("install and start the agentssh user service?", true) {
		if err := installService(); err != nil {
			t.printf("service: %v\n", err)
		}
	}
	home, _ := os.UserHomeDir()
	for _, in := range installers {
		if !in.detect(home) || !t.yes("install the agentssh skill and hook for "+in.name+"?", true) {
			continue
		}
		cmd, err := hookCommand(in.name)
		if err == nil {
			err = in.install(home, cmd)
		}
		if err != nil {
			t.printf("%s: %v\n", in.name, err)
		}
	}
	if salt != nil {
		t.printf("\nThe daemon starts locked in passphrase mode: run 'agentssh unlock'.\n")
	}
	t.printf(`
Next steps:
  agentssh key gen web1-agent                       # then add the public key on the server
  agentssh host add web1 --host 10.0.0.5 --user deploy --key web1-agent --agent --desc "..."
  agentssh host trust web1                          # verify and pin the host key
  agentssh doctor
`)
	return 0
}

func writeFile(p, content string) error {
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	return os.WriteFile(p, []byte(content), 0o644)
}
