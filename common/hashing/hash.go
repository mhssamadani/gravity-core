package hashing

import (
	"crypto/sha256"

	"github.com/Gravity-Tech/gravity-core/common/account"
	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/blake2b"
)

func WrappedKeccak256(input []byte, chain account.ChainType) []byte {
	var hash []byte
	switch chain {
	case account.Solana:
		digest := sha256.Sum256(input[:])
		hash = digest[:]
	case account.Ergo, account.Sigma:
		digest := blake2b.Sum256(input[:])
		hash = digest[:]
	default:
		hash = crypto.Keccak256(input[:])
	}
	return hash
}
