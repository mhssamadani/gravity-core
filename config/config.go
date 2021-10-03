package config

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/Gravity-Tech/gravity-core/common/account"
	"io/ioutil"
	"net/http"

	"github.com/ethereum/go-ethereum/common/hexutil"

	ergCrypto "crypto/ed25519"
	cryptorand "crypto/rand"
	ergClient "github.com/Gravity-Tech/gravity-core/common/helpers"
	ethCrypto "github.com/ethereum/go-ethereum/crypto"

	"github.com/Gravity-Tech/gravity-core/common/helpers"
	"github.com/tendermint/tendermint/crypto/ed25519"
	wavesplatform "github.com/wavesplatform/go-lib-crypto"
)

type Keys struct {
	Validator    Key
	TargetChains map[string]Key
}

type Key struct {
	Address string
	PubKey  string
	PrivKey string
}

const ergoProxyUrl = ""


func generateEthereumBasedPrivKeys() (*Key, error) {
	ethPrivKey, err := ethCrypto.GenerateKey()
	if err != nil {
		return nil, err
	}

	return &Key{
		Address: ethCrypto.PubkeyToAddress(ethPrivKey.PublicKey).String(),
		PubKey:  hexutil.Encode(ethCrypto.CompressPubkey(&ethPrivKey.PublicKey)),
		PrivKey: hexutil.Encode(ethCrypto.FromECDSA(ethPrivKey)),
	}, nil
}

func generateWavesPrivKeys(chain byte) (*Key, error) {
	wCrypto := wavesplatform.NewWavesCrypto()
	wSeed := wCrypto.RandomSeed()

	return &Key{
		Address: string(wCrypto.AddressFromSeed(wSeed, wavesplatform.WavesChainID(chain))),
		PubKey:  string(wCrypto.PublicKey(wSeed)),
		PrivKey: string(wSeed),
	}, nil
}

func generateErgoPrivKeys() (*Key, error) {
	type Response struct {
		Status  bool   `json:"success"`
		Address string `json:"address"`
		Pk      string `json:"pk"`
	}

	seed := make([]byte, 32)
	_, err := cryptorand.Read(seed)
	if err != nil {
		panic(err)
	}
	secret := ergCrypto.NewKeyFromSeed(seed)

	client, _ := ergClient.NewClient(helpers.ErgOptions{BaseUrl:ergoProxyUrl})

	values := map[string]string{"sk": hex.EncodeToString(secret)}
	jsonValue, _ := json.Marshal(values)
	url, _ := ergClient.JoinUrl(client.Options.BaseUrl, "getAddressDetail")
	req, err := http.NewRequest("POST", url.String(), bytes.NewBuffer(jsonValue))
	if err != nil {
		panic(err)
	}
	res := new(Response)
	_, err = client.Do(req, res)
	if err != nil {
		panic(err)
	}

	if !res.Status {
		err = fmt.Errorf("proxy connection problem")
		panic(err)
	}
	return &Key{
		Address: res.Address,
		PubKey:  res.Pk,
		PrivKey: hex.EncodeToString(seed),
	}, nil

}

func GeneratePrivKeys(wavesChainID byte) (*Keys, error) {
	validatorPrivKey := ed25519.GenPrivKey()

	ethPrivKeys, err := generateEthereumBasedPrivKeys()
	if err != nil {
		return nil, err
	}
	wavesPrivKeys, err := generateWavesPrivKeys(wavesChainID)
	if err != nil {
		return nil, err
	}
	ergoPrivKeys, err := generateErgoPrivKeys()
	if err != nil {
		return nil, err
	}

	return &Keys{
		Validator: Key{
			Address: hexutil.Encode(validatorPrivKey.PubKey().Bytes()[5:]),
			PubKey:  hexutil.Encode(validatorPrivKey.PubKey().Bytes()[5:]),
			PrivKey: hexutil.Encode(validatorPrivKey[:]),
		},
		TargetChains: map[string]Key{
			account.Ethereum.String(): *ethPrivKeys,
			account.Binance.String():  *ethPrivKeys,
			account.Waves.String():    *wavesPrivKeys,
			account.Avax.String():     *ethPrivKeys,
			account.Heco.String():     *ethPrivKeys,
			account.Fantom.String():   *ethPrivKeys,
			account.Ergo.String():     *ergoPrivKeys,
			account.XDai.String():     *ethPrivKeys,
		},
	}, nil
}

func ParseConfig(filename string, config interface{}) error {
	file, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(file, config); err != nil {
		return err
	}
	return nil
}
