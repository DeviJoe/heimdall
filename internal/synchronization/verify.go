package synchronization

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
)

func VerifyState(key ed25519.PublicKey, signed SignedState) (Snapshot, error) {
	var state Snapshot
	if len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, signed.Payload, signed.Signature) {
		return state, errors.New("invalid state signature")
	}
	digest := sha256.Sum256(signed.Payload)
	if hex.EncodeToString(digest[:]) != signed.Digest {
		return state, errors.New("invalid state digest")
	}
	decoder := json.NewDecoder(bytes.NewReader(signed.Payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return state, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return state, errors.New("trailing snapshot data")
	}
	return state, nil
}
