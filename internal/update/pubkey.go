package update

import (
	"crypto/ed25519"
	"encoding/base64"
)

// publicKeyB64 is the release-signing public key (ed25519, 32 bytes).
const publicKeyB64 = "7LMgTdAnmVq95iXKkVvcxa2BrN02LgB1pMUM7XzrVss="

var publicKey ed25519.PublicKey

// PublicKey returns a copy of the key that verifies SHA256SUMS.sig.
func PublicKey() ed25519.PublicKey { return append(ed25519.PublicKey(nil), publicKey...) }

func init() {
	b, err := base64.StdEncoding.DecodeString(publicKeyB64)
	if err != nil || len(b) != ed25519.PublicKeySize {
		panic("update: bad embedded public key")
	}
	publicKey = b
}
