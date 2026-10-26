package synchronization

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func TestManifestSignatureAndDigest(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(Snapshot{NodeID: "node", Schema: 1, Epoch: "epoch", Revision: 2})
	digest := sha256.Sum256(raw)
	state := SignedState{Payload: raw, Signature: ed25519.Sign(private, raw), Digest: hex.EncodeToString(digest[:])}
	if _, err = VerifyState(public, state); err != nil {
		t.Fatal(err)
	}
	corrupt := state
	corrupt.Payload = append([]byte{}, raw...)
	corrupt.Payload[0] = '['
	if _, err = VerifyState(public, corrupt); err == nil {
		t.Fatal("modified manifest accepted")
	}
	corrupt = state
	corrupt.Digest = "invalid"
	if _, err = VerifyState(public, corrupt); err == nil {
		t.Fatal("invalid digest accepted")
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err = VerifyState(other, state); err == nil {
		t.Fatal("untrusted signing key accepted")
	}
	trailing := append(append([]byte{}, raw...), []byte(" {}")...)
	digest = sha256.Sum256(trailing)
	state = SignedState{Payload: trailing, Signature: ed25519.Sign(private, trailing), Digest: hex.EncodeToString(digest[:])}
	if _, err = VerifyState(public, state); err == nil {
		t.Fatal("signed trailing JSON accepted")
	}
}
