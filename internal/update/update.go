// Package update looks up the latest GitHub release, verifies its ed25519-signed
// SHA256SUMS and replaces the running install in a way that fits how it was installed.
package update

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	defaultBase  = "https://api.github.com"
	maxDownload  = 200 << 20
	maxNotes     = 2000
	assetPrefix  = "https://github.com/ASromancer/ostiary/releases/download/"
	objectsHost  = "https://objects.githubusercontent.com/"
	metaTimeout  = 15 * time.Second
	downloadTime = 5 * time.Minute
)

type Release struct {
	Version string            // "0.3.0" (tag without "v")
	URL     string            // html_url
	Notes   string            // body, trimmed to 2000 bytes
	Assets  map[string]string // asset name -> browser_download_url
}

type Kind int

const (
	Standalone       Kind = iota // a bare binary the user can overwrite
	WindowsInstaller             // installed by Ostiary-Setup (unins000.exe next to the exe)
	MacApp                       // inside Ostiary.app/Contents/MacOS
	Deb                          // /usr/bin/ostiary from the .deb
)

// Latest fetches the newest release. base "" means https://api.github.com.
func Latest(ctx context.Context, base, current string) (*Release, error) {
	if base == "" {
		base = defaultBase
	}
	ctx, cancel := context.WithTimeout(ctx, metaTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base, "/")+"/repos/ASromancer/ostiary/releases/latest", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "ostiary/"+current)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("release lookup: HTTP %d", resp.StatusCode)
	}
	var j struct {
		Tag    string `json:"tag_name"`
		URL    string `json:"html_url"`
		Body   string `json:"body"`
		Assets []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&j); err != nil {
		return nil, fmt.Errorf("release lookup: %w", err)
	}
	r := &Release{Version: strings.TrimPrefix(j.Tag, "v"), URL: j.URL, Notes: j.Body, Assets: map[string]string{}}
	if len(r.Notes) > maxNotes {
		r.Notes = r.Notes[:maxNotes]
	}
	for _, a := range j.Assets {
		r.Assets[a.Name] = a.URL
	}
	if r.Version == "" {
		return nil, errors.New("release lookup: empty tag")
	}
	return r, nil
}

// parse returns numeric core, prerelease, ok. Non-semver (e.g. "dev") gives ok=false.
func parse(v string) (core [3]int, pre string, ok bool) {
	v = strings.TrimPrefix(v, "v")
	v, _, _ = strings.Cut(v, "+")
	v, pre, _ = strings.Cut(v, "-")
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return core, pre, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return core, pre, false
		}
		core[i] = n
	}
	return core, pre, true
}

// Newer reports whether a is a newer version than b. Unparseable ("dev") is older than anything.
func Newer(a, b string) bool {
	ac, ap, aok := parse(a)
	bc, bp, bok := parse(b)
	switch {
	case !aok:
		return false
	case !bok:
		return true
	}
	if ac != bc {
		for i := range ac {
			if ac[i] != bc[i] {
				return ac[i] > bc[i]
			}
		}
	}
	switch {
	case ap == bp:
		return false
	case ap == "":
		return true
	case bp == "":
		return false
	}
	return ap > bp // ponytail: lexical prerelease compare, not full semver precedence
}

// Verify checks a base64 ed25519 signature over sums.
func Verify(sums, sig []byte, pub ed25519.PublicKey) error {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig)))
	if err != nil || len(raw) != ed25519.SignatureSize {
		return errors.New("signature missing or malformed")
	}
	if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, sums, raw) {
		return errors.New("signature verification failed")
	}
	return nil
}

// SumFor returns the hex sha256 listed for name in a sha256sum-format file.
func SumFor(sums []byte, name string) (string, error) {
	for _, line := range strings.Split(string(sums), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == name {
			return strings.ToLower(f[0]), nil
		}
	}
	return "", fmt.Errorf("no checksum for %s", name)
}

// DetectKind classifies how the binary at exe was installed. It only inspects paths and files.
func DetectKind(exe, goos string) Kind {
	p := filepath.ToSlash(exe)
	switch goos {
	case "darwin":
		if strings.Contains(p, ".app/Contents/MacOS/") {
			return MacApp
		}
	case "windows":
		if _, err := os.Stat(filepath.Join(filepath.Dir(exe), "unins000.exe")); err == nil {
			return WindowsInstaller
		}
	case "linux":
		if p == "/usr/bin/ostiary" {
			return Deb
		}
	}
	return Standalone
}

// AssetName is the release asset to fetch for this install.
func AssetName(k Kind, goos, goarch, version string) string {
	switch k {
	case Deb:
		return fmt.Sprintf("ostiary_%s_%s.deb", version, goarch)
	case WindowsInstaller:
		return fmt.Sprintf("Ostiary-Setup-%s-x64.exe", version)
	case MacApp:
		return "ostiary-darwin-universal.tar.gz"
	}
	switch goos {
	case "windows":
		return "ostiary-windows-" + goarch + ".zip"
	case "darwin":
		return "ostiary-darwin-universal.tar.gz"
	}
	return "ostiary-" + goos + "-" + goarch + ".tar.gz"
}

// Apply verifies and installs release r over the install at exe.
func Apply(ctx context.Context, r *Release, k Kind, exe, goos, goarch string, client *http.Client) (string, error) {
	return apply(ctx, r, k, exe, goos, goarch, client, nil, PublicKey)
}

// apply is Apply with injectable extra allowed hosts and key (tests only).
func apply(ctx context.Context, r *Release, k Kind, exe, goos, goarch string, client *http.Client, allowHosts []string, pub ed25519.PublicKey) (string, error) {
	name := AssetName(k, goos, goarch, r.Version)
	if k == Deb {
		return "", fmt.Errorf("installed from a .deb; update with: sudo apt install ./%s (download: %s)", name, r.Assets[name])
	}
	if client == nil {
		client = &http.Client{Timeout: downloadTime}
	}
	get := func(n string) ([]byte, error) {
		u, ok := r.Assets[n]
		if !ok {
			return nil, fmt.Errorf("release has no asset %s", n)
		}
		return download(ctx, client, u, allowHosts)
	}
	sums, err := get("SHA256SUMS")
	if err != nil {
		return "", err
	}
	sig, err := get("SHA256SUMS.sig")
	if err != nil {
		return "", err
	}
	if err := Verify(sums, sig, pub); err != nil {
		return "", err
	}
	want, err := SumFor(sums, name)
	if err != nil {
		return "", err
	}
	data, err := get(name)
	if err != nil {
		return "", err
	}
	if h := sha256.Sum256(data); hex.EncodeToString(h[:]) != want {
		return "", fmt.Errorf("checksum mismatch for %s", name)
	}
	if k == WindowsInstaller {
		return runInstaller(data, name)
	}
	names := []string{"ostiary"}
	if goos == "windows" {
		names = []string{"ostiary.exe", "ostiary-app.exe"}
	}
	files, err := extract(data, name, names)
	if err != nil {
		return "", err
	}
	if err := install(filepath.Dir(exe), files, goos == "windows"); err != nil {
		return "", err
	}
	return fmt.Sprintf("updated to %s; restart Ostiary to use it", r.Version), nil
}

func allowed(u string, extra []string) bool {
	if strings.HasPrefix(u, assetPrefix) || strings.HasPrefix(u, objectsHost) {
		return true
	}
	pu, err := url.Parse(u)
	if err != nil {
		return false
	}
	for _, h := range extra {
		if pu.Host == h {
			return true
		}
	}
	return false
}

func download(ctx context.Context, c *http.Client, u string, extra []string) ([]byte, error) {
	if !allowed(u, extra) {
		return nil, fmt.Errorf("refusing download from untrusted URL %s", u)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "ostiary/update")
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: HTTP %d", u, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxDownload+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxDownload {
		return nil, errors.New("download exceeds size limit")
	}
	return b, nil
}

// extract pulls the named files (matched by base name) out of a tar.gz or zip.
func extract(data []byte, archive string, names []string) (map[string][]byte, error) {
	out := map[string][]byte{}
	want := func(n string) bool {
		n = filepath.Base(n)
		for _, w := range names {
			if n == w {
				return true
			}
		}
		return false
	}
	readAll := func(r io.Reader) ([]byte, error) {
		b, err := io.ReadAll(io.LimitReader(r, maxDownload+1))
		if err == nil && len(b) > maxDownload {
			err = errors.New("archive member exceeds size limit")
		}
		return b, err
	}
	if strings.HasSuffix(archive, ".zip") {
		zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return nil, err
		}
		for _, f := range zr.File {
			if f.FileInfo().IsDir() || !want(f.Name) {
				continue
			}
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			b, err := readAll(rc)
			rc.Close()
			if err != nil {
				return nil, err
			}
			out[filepath.Base(f.Name)] = b
		}
	} else {
		gz, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		tr := tar.NewReader(gz)
		for {
			h, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, err
			}
			if h.Typeflag != tar.TypeReg || !want(h.Name) {
				continue
			}
			b, err := readAll(tr)
			if err != nil {
				return nil, err
			}
			out[filepath.Base(h.Name)] = b
		}
	}
	for _, n := range names {
		if len(out[n]) == 0 {
			return nil, fmt.Errorf("%s missing from %s", n, archive)
		}
	}
	return out, nil
}

// install writes every file to a temp file in dir, then renames each into place.
func install(dir string, files map[string][]byte, windows bool) error {
	tmps := map[string]string{}
	cleanup := func() {
		for _, t := range tmps {
			os.Remove(t)
		}
	}
	for n, b := range files {
		f, err := os.CreateTemp(dir, "."+n+".new-*")
		if err != nil {
			cleanup()
			return err
		}
		tmps[n] = f.Name()
		_, werr := f.Write(b)
		cerr := f.Close()
		if err := errors.Join(werr, cerr, os.Chmod(f.Name(), 0o755)); err != nil {
			cleanup()
			return err
		}
	}
	for n, t := range tmps {
		dst := filepath.Join(dir, n)
		if windows { // a running exe can be renamed but not overwritten
			os.Remove(dst + ".old")
			if err := os.Rename(dst, dst+".old"); err != nil && !os.IsNotExist(err) {
				cleanup()
				return err
			}
		}
		if err := os.Rename(t, dst); err != nil {
			cleanup()
			return err
		}
		delete(tmps, n)
	}
	return nil
}

func runInstaller(data []byte, name string) (string, error) {
	d, err := os.MkdirTemp("", "ostiary-update-")
	if err != nil {
		return "", err
	}
	p := filepath.Join(d, name)
	if err := os.WriteFile(p, data, 0o755); err != nil {
		return "", err
	}
	cmd := exec.Command(p, "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART")
	if err := cmd.Start(); err != nil {
		return "", err
	}
	go cmd.Wait()
	return "installer is running; Ostiary will restart when it finishes", nil
}
