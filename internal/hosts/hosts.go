// Package hosts loads hosts.toml, the per-repo .agentssh.toml and imports
// ~/.ssh/config. None of these files contain secrets.
package hosts

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/ASromancer/agentssh/internal/policy"
)

type Host struct {
	Host        string   `toml:"host" json:"host"`
	User        string   `toml:"user" json:"user"`
	Port        int      `toml:"port,omitempty" json:"port,omitempty"`
	Key         string   `toml:"key,omitempty" json:"key,omitempty"` // name of a key or password in the vault
	Profile     string   `toml:"profile,omitempty" json:"profile,omitempty"`
	Agent       bool     `toml:"agent" json:"agent"`
	Description string   `toml:"description,omitempty" json:"description,omitempty"`
	Allow       []string `toml:"allow,omitempty" json:"allow,omitempty"`
	Deny        []string `toml:"deny,omitempty" json:"deny,omitempty"`
}

func (h *Host) Addr() string {
	port := h.Port
	if port == 0 {
		port = 22
	}
	return net.JoinHostPort(h.Host, strconv.Itoa(port))
}

func (h *Host) EffectiveProfile() string {
	if h.Profile == "" {
		return policy.ProfileStandard
	}
	return h.Profile
}

type Config struct {
	Hosts map[string]*Host `toml:"hosts"`
}

func Load(path string) (*Config, error) {
	c := &Config{}
	if _, err := toml.DecodeFile(path, c); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if c.Hosts == nil {
		c.Hosts = map[string]*Host{}
	}
	for name, h := range c.Hosts {
		if err := h.Validate(); err != nil {
			return nil, fmt.Errorf("%s: host %s: %w", path, name, err)
		}
	}
	return c, nil
}

func (h *Host) Validate() error {
	if h.Host == "" {
		return errors.New("missing host")
	}
	if h.Profile != "" && !policy.ValidProfile(h.Profile) {
		return fmt.Errorf("unknown profile %q (readonly|standard|full)", h.Profile)
	}
	return nil
}

func (c *Config) Save(path string) error {
	var b bytes.Buffer
	b.WriteString("# agentssh hosts. Edit, then run 'agentssh reload' to apply.\n\n")
	if err := toml.NewEncoder(&b).Encode(c); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b.Bytes(), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Repo is a .agentssh.toml found in the working directory or above.
// It can only narrow what agents see, never widen it.
type Repo struct {
	Hosts      []string `toml:"hosts"`
	MaxProfile string   `toml:"max_profile"`
	Dir        string   `toml:"-"`
}

const RepoFile = ".agentssh.toml"

// FindRepo walks up from cwd looking for .agentssh.toml. nil means none.
func FindRepo(cwd string) (*Repo, error) {
	if cwd == "" {
		return nil, nil
	}
	for dir := filepath.Clean(cwd); ; dir = filepath.Dir(dir) {
		p := filepath.Join(dir, RepoFile)
		r := &Repo{Dir: dir}
		_, err := toml.DecodeFile(p, r)
		if err == nil {
			if r.MaxProfile != "" && !policy.ValidProfile(r.MaxProfile) {
				return nil, fmt.Errorf("%s: unknown max_profile %q", p, r.MaxProfile)
			}
			return r, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		if dir == filepath.Dir(dir) {
			return nil, nil
		}
	}
}

// Visible returns the hosts an agent may use, with their effective profile.
func (c *Config) Visible(r *Repo) map[string]string {
	out := map[string]string{}
	for name, h := range c.Hosts {
		if !h.Agent {
			continue
		}
		p := h.EffectiveProfile()
		if r != nil {
			listed := false
			for _, n := range r.Hosts {
				listed = listed || n == name
			}
			if !listed {
				continue
			}
			p = policy.Stricter(p, r.MaxProfile)
		}
		out[name] = p
	}
	return out
}

// ImportSSHConfig reads concrete Host entries from an OpenSSH client config.
// Wildcard patterns, Match blocks and Include are skipped. Imported hosts
// are never visible to agents (agent = false) until the user enables them.
func ImportSSHConfig(path string) (map[string]*Host, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string]*Host{}
	var cur []*Host
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, _ := strings.Cut(strings.Replace(line, "=", " ", 1), " ")
		val = strings.Trim(strings.TrimSpace(val), `"`)
		switch strings.ToLower(key) {
		case "host":
			cur = nil
			for _, n := range strings.Fields(val) {
				if strings.ContainsAny(n, "*?!") {
					continue
				}
				h := &Host{Host: n, Profile: policy.ProfileStandard}
				out[n], cur = h, append(cur, h)
			}
		case "match":
			cur = nil
		case "hostname":
			for _, h := range cur {
				h.Host = val
			}
		case "user":
			for _, h := range cur {
				h.User = val
			}
		case "port":
			p, _ := strconv.Atoi(val)
			for _, h := range cur {
				h.Port = p
			}
		}
	}
	return out, sc.Err()
}
