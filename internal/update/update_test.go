package update

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestNewer(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"0.3.0", "0.2.9", true}, {"0.2.0", "0.2.0", false}, {"0.10.0", "0.9.1", true},
		{"0.2.0", "dev", true}, {"0.2.0", "0.0.0-dev.abc", true}, {"0.2.0-rc1", "0.2.0", false},
		{"v0.3.0", "0.2.0", true}, {"dev", "0.2.0", false},
	} {
		if got := Newer(c.a, c.b); got != c.want {
			t.Errorf("Newer(%q,%q)=%v want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestPublicKey(t *testing.T) {
	if len(PublicKey) != ed25519.PublicKeySize {
		t.Fatal("bad key size")
	}
}

func TestVerifyAndSumFor(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	sums := []byte("abc123  ostiary-linux-amd64.tar.gz\n")
	sig := []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, sums)) + "\n")
	if err := Verify(sums, sig, pub); err != nil {
		t.Fatal(err)
	}
	bad := append([]byte(nil), sums...)
	bad[0] ^= 1
	if Verify(bad, sig, pub) == nil {
		t.Error("flipped byte passed")
	}
	if Verify(sums, nil, pub) == nil {
		t.Error("empty sig passed")
	}
	if Verify(sums, sig, other) == nil {
		t.Error("other key passed")
	}
	if h, err := SumFor(sums, "ostiary-linux-amd64.tar.gz"); err != nil || h != "abc123" {
		t.Errorf("SumFor=%q,%v", h, err)
	}
	if _, err := SumFor(sums, "nope"); err == nil {
		t.Error("unknown name ok")
	}
}

func TestDetectKind(t *testing.T) {
	if k := DetectKind("/Applications/Ostiary.app/Contents/MacOS/ostiary", "darwin"); k != MacApp {
		t.Errorf("mac=%v", k)
	}
	if k := DetectKind("/usr/bin/ostiary", "linux"); k != Deb {
		t.Errorf("deb=%v", k)
	}
	if k := DetectKind("/home/u/bin/ostiary", "linux"); k != Standalone {
		t.Errorf("standalone=%v", k)
	}
	d := t.TempDir()
	exe := filepath.Join(d, "ostiary.exe")
	if k := DetectKind(exe, "windows"); k != Standalone {
		t.Errorf("win standalone=%v", k)
	}
	os.WriteFile(filepath.Join(d, "unins000.exe"), nil, 0o644)
	if k := DetectKind(exe, "windows"); k != WindowsInstaller {
		t.Errorf("win installer=%v", k)
	}
}

func TestAssetName(t *testing.T) {
	for _, c := range []struct {
		k           Kind
		os, arch, w string
	}{
		{Standalone, "linux", "amd64", "ostiary-linux-amd64.tar.gz"},
		{Standalone, "linux", "arm64", "ostiary-linux-arm64.tar.gz"},
		{Standalone, "windows", "amd64", "ostiary-windows-amd64.zip"},
		{Standalone, "windows", "arm64", "ostiary-windows-arm64.zip"},
		{Standalone, "darwin", "arm64", "ostiary-darwin-universal.tar.gz"},
		{MacApp, "darwin", "amd64", "ostiary-darwin-universal.tar.gz"},
		{WindowsInstaller, "windows", "amd64", "Ostiary-Setup-0.3.0-x64.exe"},
		{Deb, "linux", "amd64", "ostiary_0.3.0_amd64.deb"},
		{Deb, "linux", "arm64", "ostiary_0.3.0_arm64.deb"},
	} {
		if got := AssetName(c.k, c.os, c.arch, "0.3.0"); got != c.w {
			t.Errorf("%v %s/%s = %q want %q", c.k, c.os, c.arch, got, c.w)
		}
	}
}

func tarGz(name string, body []byte) []byte {
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	tw := tar.NewWriter(gz)
	tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
	tw.Write(body)
	tw.Close()
	gz.Close()
	return b.Bytes()
}

type fake struct {
	srv      *httptest.Server
	assets   map[string][]byte
	assetHit atomic.Int32
	rel      *Release
}

// newFake serves a release with the given asset set; sums/sig signed with a test key unless badSig.
func newFake(t *testing.T, asset []byte, tamper, badSig bool) *fake {
	t.Helper()
	f := &fake{assets: map[string][]byte{}}
	name := "ostiary-linux-amd64.tar.gz"
	sum := sha256.Sum256(asset)
	sums := []byte(hex.EncodeToString(sum[:]) + "  " + name + "\n")
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	sig := []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, sums)) + "\n")
	f.assets["SHA256SUMS"] = sums
	f.assets["SHA256SUMS.sig"] = sig
	body := asset
	if tamper {
		body = append(append([]byte(nil), asset...), 'x')
	}
	f.assets[name] = body
	mux := http.NewServeMux()
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	type ja struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
	}
	var as []ja
	for n := range f.assets {
		as = append(as, ja{n, f.srv.URL + "/dl/" + n})
	}
	mux.HandleFunc("/repos/ASromancer/ostiary/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.UserAgent(), "ostiary/") {
			http.Error(w, "ua", 400)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"tag_name": "v0.3.0", "html_url": "https://x/r", "body": "notes", "assets": as})
	})
	mux.HandleFunc("/dl/", func(w http.ResponseWriter, r *http.Request) {
		n := strings.TrimPrefix(r.URL.Path, "/dl/")
		if n != "SHA256SUMS" && n != "SHA256SUMS.sig" {
			f.assetHit.Add(1)
		}
		w.Write(f.assets[n])
	})
	_ = badSig
	return f
}

func (f *fake) host() []string {
	u, _ := url.Parse(f.srv.URL)
	return []string{u.Host}
}

func TestLatest(t *testing.T) {
	f := newFake(t, []byte("x"), false, false)
	r, err := Latest(context.Background(), f.srv.URL, "0.2.0")
	if err != nil {
		t.Fatal(err)
	}
	if r.Version != "0.3.0" || r.URL != "https://x/r" || r.Notes != "notes" || r.Assets["SHA256SUMS"] == "" {
		t.Errorf("%+v", r)
	}
}

// signedApply builds a fake whose sums are signed by PublicKey-substitute: Apply verifies against
// the embedded key, so tests use applyWith with an injected key.
func TestApply(t *testing.T) {
	newBin := []byte("NEW BINARY")
	for _, tc := range []struct {
		name           string
		tamper, badSig bool
		wantErr        bool
		wantAssetHits  int32
	}{
		{"ok", false, false, false, 1},
		{"tampered", true, false, true, 1},
		{"badsig", false, true, true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(t, tarGz("ostiary", newBin), tc.tamper, tc.badSig)
			// re-sign with a known key; for badSig use a different verification key.
			pub, priv, _ := ed25519.GenerateKey(rand.Reader)
			f.assets["SHA256SUMS.sig"] = []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, f.assets["SHA256SUMS"])) + "\n")
			if tc.badSig {
				pub, _, _ = ed25519.GenerateKey(rand.Reader)
			}
			r, err := Latest(context.Background(), f.srv.URL, "0.2.0")
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			exe := filepath.Join(dir, "ostiary")
			os.WriteFile(exe, []byte("OLD"), 0o755)
			_, err = apply(context.Background(), r, Standalone, exe, "linux", "amd64", nil, f.host(), pub)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v", err)
			}
			if f.assetHit.Load() != tc.wantAssetHits {
				t.Errorf("asset hits=%d", f.assetHit.Load())
			}
			got, _ := os.ReadFile(exe)
			if tc.wantErr {
				if string(got) != "OLD" {
					t.Errorf("exe changed: %q", got)
				}
				return
			}
			if !bytes.Equal(got, newBin) {
				t.Errorf("exe=%q", got)
			}
			if st, _ := os.Stat(exe); st.Mode().Perm() != 0o755 {
				t.Errorf("mode=%v", st.Mode())
			}
			if m, _ := filepath.Glob(filepath.Join(dir, "*")); len(m) != 1 {
				t.Errorf("leftover files: %v", m)
			}
		})
	}
}

func TestApplyDebAndHostCheck(t *testing.T) {
	f := newFake(t, tarGz("ostiary", []byte("x")), false, false)
	r, _ := Latest(context.Background(), f.srv.URL, "0.2.0")
	r.Assets["ostiary_0.3.0_amd64.deb"] = "https://github.com/ASromancer/ostiary/releases/download/v0.3.0/ostiary_0.3.0_amd64.deb"
	_, err := Apply(context.Background(), r, Deb, "/usr/bin/ostiary", "linux", "amd64", nil)
	if err == nil || !strings.Contains(err.Error(), "sudo apt install ./ostiary_0.3.0_amd64.deb") {
		t.Errorf("deb err=%v", err)
	}
	// not-allowed host (test server) must be refused by the public Apply
	_, err = Apply(context.Background(), r, Standalone, filepath.Join(t.TempDir(), "ostiary"), "linux", "amd64", nil)
	if err == nil {
		t.Error("untrusted host accepted")
	}
	if f.assetHit.Load() != 0 {
		t.Error("downloaded from untrusted host")
	}
}

func TestApplyZipWindows(t *testing.T) {
	var zb bytes.Buffer
	zw := zip.NewWriter(&zb)
	for _, n := range []string{"ostiary.exe", "ostiary-app.exe"} {
		w, _ := zw.Create(n)
		fmt.Fprint(w, "new-"+n)
	}
	zw.Close()
	name := "ostiary-windows-amd64.zip"
	sum := sha256.Sum256(zb.Bytes())
	sums := []byte(hex.EncodeToString(sum[:]) + "  " + name + "\n")
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sig := []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, sums)) + "\n")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch filepath.Base(r.URL.Path) {
		case "SHA256SUMS":
			w.Write(sums)
		case "SHA256SUMS.sig":
			w.Write(sig)
		default:
			w.Write(zb.Bytes())
		}
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	rel := &Release{Version: "0.3.0", Assets: map[string]string{"SHA256SUMS": srv.URL + "/SHA256SUMS", "SHA256SUMS.sig": srv.URL + "/SHA256SUMS.sig", name: srv.URL + "/" + name}}
	dir := t.TempDir()
	exe := filepath.Join(dir, "ostiary.exe")
	os.WriteFile(exe, []byte("old"), 0o755)
	if _, err := apply(context.Background(), rel, Standalone, exe, "windows", "amd64", nil, []string{u.Host}, pub); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"ostiary.exe", "ostiary-app.exe"} {
		if b, _ := os.ReadFile(filepath.Join(dir, n)); string(b) != "new-"+n {
			t.Errorf("%s=%q", n, b)
		}
	}
}
