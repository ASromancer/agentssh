package hosts

import (
	"os"
	"path/filepath"
	"testing"
)

func TestVisibleAndRepo(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "hosts.toml")
	os.WriteFile(cfgPath, []byte(`
[hosts.web1]
host = "10.0.0.5"
profile = "full"
agent = true
[hosts.db]
host = "10.0.0.6"
agent = true
[hosts.secret]
host = "10.0.0.7"
`), 0o600)
	c, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	v := c.Visible(nil)
	if len(v) != 2 || v["web1"] != "full" || v["db"] != "standard" {
		t.Fatalf("global: %v", v)
	}
	repo := filepath.Join(dir, "repo")
	os.MkdirAll(filepath.Join(repo, "sub"), 0o700)
	os.WriteFile(filepath.Join(repo, RepoFile), []byte(`hosts = ["web1", "secret"]
max_profile = "standard"`), 0o600)
	r, err := FindRepo(filepath.Join(repo, "sub"))
	if err != nil || r == nil || r.Dir != repo {
		t.Fatalf("repo %v %v", r, err)
	}
	v = c.Visible(r)
	// secret is listed but agent=false: the repo file can't widen access.
	if len(v) != 1 || v["web1"] != "standard" {
		t.Fatalf("repo: %v", v)
	}
}

func TestImportSSHConfig(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config")
	os.WriteFile(p, []byte(`
Host *
  User nobody
Host web1 web1-alias
  HostName 10.0.0.5
  User deploy
  Port 2222
Host db
  HostName=db.internal
`), 0o600)
	m, err := ImportSSHConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 3 || m["web1"].Host != "10.0.0.5" || m["web1"].Port != 2222 || m["db"].Host != "db.internal" || m["web1"].Agent {
		t.Fatalf("%+v", m)
	}
}
