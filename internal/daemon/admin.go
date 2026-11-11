package daemon

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"sort"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/ASromancer/agentssh/internal/audit"
	"github.com/ASromancer/agentssh/internal/hosts"
	"github.com/ASromancer/agentssh/internal/humanok"
	"github.com/ASromancer/agentssh/internal/paths"
	"github.com/ASromancer/agentssh/internal/sshconn"
	"github.com/ASromancer/agentssh/internal/vault"
)

func vaultSalt() ([]byte, error) { return vault.Salt(paths.Vault()) }

// Admin operations that need an out-of-band code (spec 5.2).
var adminOps = map[string]bool{
	"reload": true, "host-set": true, "host-rm": true, "trust": true,
	"key-gen": true, "key-import": true, "key-rm": true, "key-export": true,
}

func (s *Service) Unlock(a *UnlockArgs, _ *Empty) error {
	salt, err := vaultSalt()
	if err != nil {
		return err
	}
	var key *[32]byte
	auth := "passphrase"
	if salt == nil {
		auth = "none"
		if s.d.osAuth() {
			auth = "os"
			if err := s.d.confirm("unlock the agentssh vault"); err != nil {
				s.d.log.Write(audit.Entry{Kind: "admin", Cmd: "unlock", Auth: auth, Decision: "denied", Note: err.Error()})
				return err
			}
		}
		if key, err = vault.KeyringGet(); err != nil {
			return fmt.Errorf("keyring: %w", err)
		}
	} else {
		key = vault.DeriveKey([]byte(a.Pass), salt)
	}
	err = s.d.unlock(key, salt)
	s.d.log.Write(audit.Entry{Kind: "admin", Cmd: "unlock", Auth: auth, Decision: map[bool]string{true: "allow", false: "denied"}[err == nil]})
	return err
}

func (s *Service) Begin(a *BeginArgs, r *BeginReply) error {
	if !adminOps[a.Op] {
		return fmt.Errorf("unknown admin op %q", a.Op)
	}
	var data any
	detail := a.Name
	if a.Op == "trust" {
		cfg, _, _, _ := s.d.snapshot()
		h := cfg.Hosts[a.Name]
		if h == nil {
			return fmt.Errorf("unknown host %q", a.Name)
		}
		key, err := sshconn.FetchHostKey(h.Addr())
		if err != nil {
			return fmt.Errorf("fetch host key from %s: %w", h.Addr(), err)
		}
		fp := ssh.FingerprintSHA256(key)
		r.Info = fmt.Sprintf("%s (%s) host key: %s %s", a.Name, h.Addr(), key.Type(), fp)
		detail = a.Name + " " + fp
		data = key
	}
	r.Ticket, r.Code = s.d.q.Ticket(a.Op+" "+a.Name, detail, data)
	r.OSAuth = s.d.osAuth()
	return nil
}

func (s *Service) Admin(a *AdminArgs, r *AdminReply) error {
	d := s.d
	op := a.Op + " " + a.Name
	e := audit.Entry{Kind: "admin", Cmd: strings.TrimSpace(op), Auth: "code"}
	var data any
	var err error
	if d.osAuth() {
		e.Auth = "os"
		if data, err = d.q.Take(a.Ticket, op); err == nil {
			err = d.confirm(d.adminMessage(a, data))
		}
		if errors.Is(err, humanok.ErrUnavailable) {
			err = fmt.Errorf("%w; start the operation again and enter the code", err)
		}
	} else {
		data, err = d.q.Check(a.Ticket, op, a.Code)
	}
	ok := err == nil
	e.CodeOK = &ok
	if err != nil {
		e.Decision, e.Note = "denied", err.Error()
		d.log.Write(e)
		return err
	}
	e.Decision = "approved"
	if err := d.admin(a, data, r); err != nil {
		e.Decision, e.Note = "error", err.Error()
		d.log.Write(e)
		return err
	}
	d.log.Write(e)
	return nil
}

// adminMessage is the OS dialog text for an admin operation. It shows
// every field that takes effect.
func (d *Daemon) adminMessage(a *AdminArgs, data any) string {
	switch a.Op {
	case "trust":
		if k, ok := data.(ssh.PublicKey); ok {
			return fmt.Sprintf("trust host key %s for %s", ssh.FingerprintSHA256(k), a.Name)
		}
	case "host-set":
		if h := a.Host; h != nil {
			key := h.Key
			d.mu.Lock()
			if d.data != nil && d.data.Passwords[key] != nil {
				key += " (password)"
			}
			d.mu.Unlock()
			return fmt.Sprintf("save host %s (%s@%s, profile %s, agent access %v, key=%s, allow=%q, deny=%q)",
				a.Name, h.User, h.Addr(), h.EffectiveProfile(), h.Agent, key, h.Allow, h.Deny)
		}
	}
	return strings.TrimSpace("agentssh " + a.Op + " " + a.Name)
}

func (d *Daemon) admin(a *AdminArgs, data any, r *AdminReply) error {
	if a.Op == "reload" {
		if err := d.loadConfig(); err != nil {
			return err
		}
	}
	if a.Op == "trust" {
		cfg, _, _, _ := d.snapshot()
		h := cfg.Hosts[a.Name]
		key, _ := data.(ssh.PublicKey)
		if h == nil || key == nil {
			return errors.New("host or key missing")
		}
		if err := sshconn.Trust(paths.KnownHosts(), h.Addr(), key); err != nil {
			return err
		}
		d.pool.Drop(a.Name)
		r.Out = "trusted " + ssh.FingerprintSHA256(key)
		return nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	if d.data == nil {
		return errors.New("vault is locked; run 'agentssh unlock' first")
	}
	switch a.Op {
	case "reload":
		d.data.ConfigHash = ConfigHash()
		d.userOnly = false
		r.Out = fmt.Sprintf("reloaded %d hosts", len(d.cfg.Hosts))
	case "host-set", "host-rm":
		if d.userOnly || ConfigHash() != d.data.ConfigHash {
			return errors.New("hosts.toml or rules.toml changed on disk; review the change and run 'agentssh reload' first")
		}
		cfg := &hosts.Config{Hosts: map[string]*hosts.Host{}}
		for k, v := range d.cfg.Hosts {
			cfg.Hosts[k] = v
		}
		if a.Op == "host-rm" {
			if cfg.Hosts[a.Name] == nil {
				return fmt.Errorf("unknown host %q", a.Name)
			}
			delete(cfg.Hosts, a.Name)
		} else {
			if a.Host == nil || a.Name == "" {
				return errors.New("missing host")
			}
			if err := a.Host.Validate(); err != nil {
				return err
			}
			cfg.Hosts[a.Name] = a.Host
		}
		if err := cfg.Save(paths.Hosts()); err != nil {
			return err
		}
		d.cfg = cfg
		d.data.ConfigHash = ConfigHash()
		r.Out = "saved " + paths.Hosts()
	case "key-gen":
		if _, exists := d.data.Keys[a.Name]; exists {
			return fmt.Errorf("key %q already exists", a.Name)
		}
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		block, err := ssh.MarshalPrivateKey(priv, "agentssh-"+a.Name)
		if err != nil {
			return err
		}
		sp, err := ssh.NewPublicKey(pub)
		if err != nil {
			return err
		}
		d.data.Keys[a.Name] = pem.EncodeToMemory(block)
		r.Out = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp))) + " agentssh-" + a.Name
	case "key-import":
		if len(a.PEM) > 0 {
			signer, err := ssh.ParsePrivateKey(a.PEM)
			if err != nil {
				return fmt.Errorf("parse key: %w", err)
			}
			d.data.Keys[a.Name] = a.PEM
			r.Out = "imported " + ssh.FingerprintSHA256(signer.PublicKey())
		} else if len(a.Password) > 0 {
			d.data.Passwords[a.Name] = a.Password
			r.Out = "stored password " + a.Name
		} else {
			return errors.New("nothing to import")
		}
	case "key-rm":
		_, k := d.data.Keys[a.Name]
		_, p := d.data.Passwords[a.Name]
		if !k && !p {
			return fmt.Errorf("unknown key %q", a.Name)
		}
		delete(d.data.Keys, a.Name)
		delete(d.data.Passwords, a.Name)
		r.Out = "removed " + a.Name
	case "key-export":
		// The code check is the whole point: the CLI decrypts the vault
		// itself. No RPC ever returns key material.
		_, k := d.data.Keys[a.Name]
		if !k {
			return fmt.Errorf("unknown key %q", a.Name)
		}
		return nil
	}
	return d.saveVault()
}

func (s *Service) Keys(_ *Empty, r *KeysReply) error {
	d := s.d
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.data == nil {
		return errors.New("vault is locked")
	}
	for name, p := range d.data.Keys {
		line := name + "\t(unparseable)"
		if signer, err := ssh.ParsePrivateKey(p); err == nil {
			line = fmt.Sprintf("%s\t%s %s", name, signer.PublicKey().Type(), ssh.FingerprintSHA256(signer.PublicKey()))
		}
		r.Keys = append(r.Keys, line)
	}
	for name := range d.data.Passwords {
		r.Keys = append(r.Keys, name+"\tpassword")
	}
	sort.Strings(r.Keys)
	return nil
}
