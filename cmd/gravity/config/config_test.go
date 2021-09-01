package config

import (
	"encoding/hex"
	"github.com/btcsuite/btcutil/base58"
	"testing"
)

func TestGenerateErgoPrivKeys(t *testing.T) {
	key, err := generateErgoPrivKeys()
	if err != nil {
		t.Fatalf("returns with error: %v", err)
	}
	_, err = hex.DecodeString(key.PubKey)
	if err != nil {
		t.Fatalf("PubKey is not correct: error: %v, \n pubkey: %v", err, key.PubKey)
	}
	decoded := base58.Decode(key.Address)
	if decoded == nil {
		t.Fatalf("Address is not correct: \n Address: %v", key.Address)
	}
}
