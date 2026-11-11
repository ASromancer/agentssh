// Package vault stores private keys and passwords encrypted with
// nacl/secretbox. The master key lives in the OS keyring or is derived from
// a passphrase with argon2id.
package vault

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/zalando/go-keyring"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/nacl/secretbox"
)

type Data struct {
	Keys       map[string][]byte `json:"keys"`      // name -> OpenSSH private key PEM
	Passwords  map[string][]byte `json:"passwords"` // name -> password (supported, not recommended)
	ConfigHash string            `json:"config_hash"`
}

// File layout: magic | salt length (1 byte) | salt | nonce (24) | secretbox.
// An empty salt means the master key is in the OS keyring.
const magic = "AGSV1"

var ErrBadKey = errors.New("vault: wrong master key or passphrase")

func NewKey() *[32]byte {
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		panic(err)
	}
	return &k
}

func NewSalt() []byte {
	s := make([]byte, 16)
	if _, err := rand.Read(s); err != nil {
		panic(err)
	}
	return s
}

func DeriveKey(pass, salt []byte) *[32]byte {
	var k [32]byte
	copy(k[:], argon2.IDKey(pass, salt, 3, 64*1024, 4, 32))
	return &k
}

// Save encrypts d and atomically writes it to path with mode 0600.
func Save(path string, key *[32]byte, salt []byte, d *Data) error {
	plain, err := json.Marshal(d)
	if err != nil {
		return err
	}
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	out := append([]byte(magic), byte(len(salt)))
	out = append(out, salt...)
	out = append(out, nonce[:]...)
	out = secretbox.Seal(out, plain, &nonce, key)
	clear(plain)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func header(b []byte) (salt, nonceAndBox []byte, err error) {
	if len(b) < len(magic)+1 || string(b[:len(magic)]) != magic {
		return nil, nil, errors.New("vault: not an ostiary vault")
	}
	n := int(b[len(magic)])
	rest := b[len(magic)+1:]
	if len(rest) < n+24 {
		return nil, nil, errors.New("vault: truncated")
	}
	return rest[:n], rest[n:], nil
}

// Salt returns the passphrase salt, or nil when the vault uses the keyring.
func Salt(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	s, _, err := header(b)
	if len(s) == 0 {
		s = nil
	}
	return s, err
}

func Open(path string, key *[32]byte) (*Data, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	_, rest, err := header(b)
	if err != nil {
		return nil, err
	}
	var nonce [24]byte
	copy(nonce[:], rest[:24])
	plain, ok := secretbox.Open(nil, rest[24:], &nonce, key)
	if !ok {
		return nil, ErrBadKey
	}
	d := &Data{}
	err = json.Unmarshal(plain, d)
	clear(plain)
	if err != nil {
		return nil, err
	}
	if d.Keys == nil {
		d.Keys = map[string][]byte{}
	}
	if d.Passwords == nil {
		d.Passwords = map[string][]byte{}
	}
	for _, m := range []map[string][]byte{d.Keys, d.Passwords} {
		for _, v := range m {
			lockMemory(v) // best effort
		}
	}
	return d, nil
}

// Wipe zeroes all secrets held in d.
func (d *Data) Wipe() {
	for _, m := range []map[string][]byte{d.Keys, d.Passwords} {
		for k, v := range m {
			clear(v)
			delete(m, k)
		}
	}
}

const keyringService, keyringUser = "ostiary", "master-key"

// keyringTimeout bounds OS keyring calls: a locked macOS Keychain or a
// D-Bus Secret Service that never answers must not hang init or the daemon.
const keyringTimeout = 10 * time.Second

func withTimeout[T any](f func() (T, error)) (T, error) {
	type res struct {
		v   T
		err error
	}
	ch := make(chan res, 1)
	go func() { v, err := f(); ch <- res{v, err} }()
	select {
	case r := <-ch:
		return r.v, r.err
	case <-time.After(keyringTimeout):
		var zero T
		return zero, errors.New("OS keyring did not answer within 10s")
	}
}

func KeyringGet() (*[32]byte, error) {
	s, err := withTimeout(func() (string, error) { return keyring.Get(keyringService, keyringUser) })
	if err != nil {
		return nil, err
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != 32 {
		return nil, fmt.Errorf("keyring: malformed master key")
	}
	var k [32]byte
	copy(k[:], b)
	return &k, nil
}

func KeyringSet(k *[32]byte) error {
	_, err := withTimeout(func() (struct{}, error) {
		return struct{}{}, keyring.Set(keyringService, keyringUser, base64.StdEncoding.EncodeToString(k[:]))
	})
	return err
}
