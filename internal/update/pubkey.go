package update

import (
	"crypto/ed25519"
	"encoding/base64"
)

// publicKeyB64 is the release-signing public key (ed25519, 32 bytes).
const publicKeyB64 = "7LMgTdAnmVq95iXKkVvcxa2BrN02LgB1pMUM7XzrVss="

// PublicKey verifies SHA256SUMS.sig.
var PublicKey ed25519.PublicKey

func init() {
	b, err := base64.StdEncoding.DecodeString(publicKeyB64)
	if err != nil || len(b) != ed25519.PublicKeySize {
		panic("update: bad embedded public key")
	}
	PublicKey = b
}
