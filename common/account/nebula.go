package account

import (
	"github.com/btcsuite/btcutil/base58"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/wavesplatform/gowaves/pkg/crypto"
	"go.uber.org/zap"
)

const (
	NebulaIdLength        = 32
	EthereumAddressLength = 20
	BSCAddressLength      = 20
	WavesAddressLength    = 26
)

type NebulaId [NebulaIdLength]byte

func StringToNebulaId(address string, chainType ChainType) (NebulaId, error) {
	var nebula NebulaId

	switch chainType {
	case Ethereum, Binance, Heco, Fantom, Avax, Polygon, XDai:
		nebulaBytes, err := hexutil.Decode(address)
		if err != nil {
			return NebulaId{}, err
		}
		nebula = BytesToNebulaId(nebulaBytes)
	case Waves:
		nebulaBytes := crypto.MustBytesFromBase58(address)
		nebula = BytesToNebulaId(nebulaBytes)
	case Solana:
		nebulaBytes := base58.Decode(address)
		nebula = BytesToNebulaId(nebulaBytes)
		zap.L().Sugar().Debug("NebulaId: ", nebula)
	case Ergo, Sigma:
		nebulaBytes := base58.Decode(address)
		nebula = BytesToNebulaId(nebulaBytes)
		//nebulaBytes, err := hex.DecodeString(address)
		//if err != nil {
		//	return NebulaId{}, err
		//}
		//nebula = BytesToNebulaId(nebulaBytes)
		zap.L().Sugar().Debug("NebulaId: ", nebula)
		zap.L().Sugar().Debug("nebulaBytes: ", nebulaBytes)
		zap.L().Sugar().Debug("Nebula: ", address)
	}

	return nebula, nil
}
func BytesToNebulaId(value []byte) NebulaId {
	var idBytes []byte
	var id NebulaId
	if len(value) < NebulaIdLength {
		idBytes = append(idBytes, make([]byte, NebulaIdLength-len(value), NebulaIdLength-len(value))...)
	}
	idBytes = append(idBytes, value...)
	copy(id[:], idBytes)

	return id
}

func (id NebulaId) ToString(chainType ChainType) string {
	nebula := id.ToBytes(chainType)
	switch chainType {
	case Ethereum, Binance, Heco, Fantom, Avax, Polygon, XDai:
		return hexutil.Encode(nebula[:])
	case Waves:
		return base58.Encode(nebula[:])
	case Solana:
		return base58.Encode(nebula[:])
	case Ergo, Sigma:
		return base58.Encode(nebula[:])
		//return hex.EncodeToString(nebula[:])
	}

	return ""
}
func (id NebulaId) ToBytes(chainType ChainType) []byte {
	switch chainType {
	case Binance, Heco, Fantom, Avax, Polygon, XDai:
		return id[NebulaIdLength-BSCAddressLength:]
	case Ethereum:
		return id[NebulaIdLength-EthereumAddressLength:]
	case Waves:
		return id[NebulaIdLength-WavesAddressLength:]
	case Solana:
		return id[:]
	case Ergo, Sigma:
		return id[:]
	}

	return nil
}
