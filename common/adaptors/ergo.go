package adaptors

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Gravity-Tech/gravity-core/abi"
	"github.com/Gravity-Tech/gravity-core/oracle/extractor"
	"github.com/gookit/validate"
	"go.uber.org/zap"

	"io/ioutil"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"

	crypto "crypto/ed25519"
	"github.com/Gravity-Tech/gravity-core/common/account"
	"github.com/Gravity-Tech/gravity-core/common/gravity"
	"github.com/Gravity-Tech/gravity-core/common/helpers"
)

const (
	ConsulsNumber  = 5
	OraclessNumber = 5
	DefaultConsul  = "038179cc7a2358f9489b629ede2304c4eebf71c9e42a246e87d31bee71a737fd8a"
	//DefaultValidOracle = "02cd0b9784f67d4ad2def93d3b485790e8f2cebfd129606601b20f9f4f90e6d021"
	DefaultOracle = "032ff0e8783d73c2d711158140be0a10123f8793ba7b42d59fd349793049e2103e"
)
var defaultPK = make([]byte, 33)

type ErgoAdaptor struct {
	secret crypto.PrivateKey

	ergoClient      *helpers.ErgClient `option:"ergClient"`
	ghClient        *gravity.Client    `option:"ghClient"`
	gravityContract string             `option:"gravityContract"`
}

type ErgoAdapterOption func(*ErgoAdaptor) error

func (adaptor *ErgoAdaptor) applyOpts(opts AdapterOptions) error {
	err := validateErgoAdapterOptions(opts)
	if err != nil {
		return err
	}
	v := reflect.TypeOf(*adaptor)
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		tag := field.Tag.Get("option")
		val, ok := opts[tag]
		if ok {
			switch tag {
			case "ghClient":
				adaptor.ghClient = val.(*gravity.Client)
			case "ergClient":
				adaptor.ergoClient = val.(*helpers.ErgClient)
			case "gravityContract":
				adaptor.gravityContract = val.(string)

			}
		}
	}
	return nil
}

func validateErgoAdapterOptions(opts AdapterOptions) error {
	v := validate.Map(opts)
	v.AddRule("ghClient", "isGhClient")
	v.AddRule("ergClient", "isErgClient")
	v.AddRule("gravityContract", "string")

	if !v.Validate() { // validate ok
		return v.Errors
	}
	return nil
}
func WithErgoGravityContract(address string) ErgoAdapterOption {
	return func(h *ErgoAdaptor) error {
		h.gravityContract = address
		return nil
	}
}
func ErgoAdapterWithGhClient(ghClient *gravity.Client) ErgoAdapterOption {
	return func(h *ErgoAdaptor) error {
		h.ghClient = ghClient
		return nil
	}
}
func NewErgoAdapterByOpts(seed []byte, nodeUrl string, ctx context.Context, opts AdapterOptions) (*ErgoAdaptor, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", nodeUrl, nil)
	if err != nil {
		return nil, err
	}
	client, err := helpers.NewClient(helpers.ErgOptions{ApiKey: "", BaseUrl: nodeUrl})
	if err != nil {
		return nil, err
	}

	_, err = client.Do(req, nil)
	if err != nil {
		return nil, err
	}
	secret := crypto.NewKeyFromSeed(seed)
	adapter := &ErgoAdaptor{
		secret:     secret,
		ergoClient: client,
	}
	err = adapter.applyOpts(opts)
	if err != nil {
		return nil, err
	}

	return adapter, nil
}
func NewErgoAdapter(seed []byte, nodeUrl string, ctx context.Context, opts ...ErgoAdapterOption) (*ErgoAdaptor, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", nodeUrl, nil)
	if err != nil {
		return nil, err
	}
	client, err := helpers.NewClient(helpers.ErgOptions{ApiKey: "", BaseUrl: nodeUrl})
	if err != nil {
		return nil, err
	}

	_, err = client.Do(req, nil)
	if err != nil {
		return nil, err
	}

	secret := crypto.NewKeyFromSeed(seed)
	er := &ErgoAdaptor{
		ergoClient: client,
		secret:     secret,
	}
	for _, opt := range opts {
		err := opt(er)
		if err != nil {
			return nil, err
		}
	}
	return er, nil
}

func (adaptor *ErgoAdaptor) WaitTx(id string, ctx context.Context) error {
	type Response struct {
		Status  bool `json:"success"`
		Confirm int  `json:"numConfirmations"`
	}
	out := make(chan error)
	const TxWaitCount = 10
	url, err := helpers.JoinUrl(adaptor.ergoClient.Options.BaseUrl, "numConfirmations")
	if err != nil {
		out <- err
	}
	go func() {
		defer close(out)
		isFounded := false
		req, err := http.NewRequestWithContext(ctx, "GET", url.String()+"/"+id, nil)
		if err != nil {
			out <- err
		}
		response := new(Response)
		_, err = adaptor.ergoClient.Do(req, response)
		if err != nil {
			out <- err
		}
		if response.Confirm > 0 {
			isFounded = true
		}
		if response.Confirm <= 0 {
			time.Sleep(time.Second * 90)
			for {
				response := new(Response)
				_, err = adaptor.ergoClient.Do(req, response)
				if err != nil {
					out <- err
					break
				}
				if response.Confirm == -1 {
					out <- errors.New(fmt.Sprintf("tx not found: %s", id))
					break
				}
				if response.Confirm == 0 {
					time.Sleep(time.Second * 60 * 2)
					continue
				} else if response.Confirm > 0 {
					isFounded = true
					break
				}
			}
		}
		if !isFounded {
			out <- errors.New(fmt.Sprintf("tx not found: %s", id))
		}
	}()
	return <-out
}
func (adaptor *ErgoAdaptor) GetHeight(ctx context.Context) (uint64, error) {
	type Response struct {
		Status bool   `json:"success"`
		Height uint64 `json:"height"`
	}
	url, err := helpers.JoinUrl(adaptor.ergoClient.Options.BaseUrl, "height")
	if err != nil {
		return 0, err
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url.String(), nil)
	if err != nil {
		return 0, err
	}
	response := new(Response)
	_, err = adaptor.ergoClient.Do(req, response)
	if err != nil {
		return 0, err
	}

	return response.Height, nil
}
func (adaptor *ErgoAdaptor) Sign(msg []byte) ([]byte, error) {
	zap.L().Sugar().Debugf("Sign: msgHex => %v", hex.EncodeToString(msg))
	zap.L().Sugar().Debugf("Sign: msgByte => %v", msg)
	zap.L().Sugar().Debugf("Sign: msg => %v", string(msg))

	type Sign struct {
		A string `json:"a"`
		Z string `json:"z"`
	}
	type Response struct {
		Status bool `json:"success"`
		Signs  Sign `json:"signs"`
	}
	values := map[string]string{"msg": hex.EncodeToString(msg), "sk": hex.EncodeToString(adaptor.secret)}
	jsonValue, _ := json.Marshal(values)
	url, err := helpers.JoinUrl(adaptor.ergoClient.Options.BaseUrl, "sign")
	if err != nil {
		return nil, err
	}

	res, err := http.Post(url.String(), "application/json", bytes.NewBuffer(jsonValue))
	if err != nil {
		return nil, err
	}
	response, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	var responseObject Response
	err = json.Unmarshal(response, &responseObject)
	if err != nil {
		return nil, err
	}

	if !responseObject.Status {
		err = fmt.Errorf("proxy connection problem")
		return nil, err
	}

	signString := responseObject.Signs.A + responseObject.Signs.Z
	// zap.L().Sugar().Debugf("sign result => %v", signString)
	signBytes := []byte(signString)
	return signBytes, nil
}
func (adaptor *ErgoAdaptor) SignHash(nebulaId account.NebulaId, intervalId uint64, pulseId uint64, hash []byte) ([]byte, error) {
	return adaptor.Sign(hash)
}
func (adaptor *ErgoAdaptor) PubKey() account.OraclesPubKey {
	type Response struct {
		Status  bool   `json:"success"`
		Address string `json:"address"`
		Pk      string `json:"pk"`
	}

	values := map[string]string{"sk": hex.EncodeToString(adaptor.secret)}
	jsonValue, _ := json.Marshal(values)
	url, _ := helpers.JoinUrl(adaptor.ergoClient.Options.BaseUrl, "getAddressDetail")

	req, _ := http.NewRequest("POST", url.String(), bytes.NewBuffer(jsonValue))

	res := new(Response)
	_, err := adaptor.ergoClient.Do(req, res)
	if err != nil {
		panic(err)
	}

	if !res.Status {
		err = fmt.Errorf("proxy connection problem")
		panic(err)
	}
	pk, _ := hex.DecodeString(res.Pk)
	oraclePubKey := account.BytesToOraclePubKey(pk[:], account.Ergo)

	zap.L().Sugar().Debugf("oraclePubKey => %v", oraclePubKey)
	return oraclePubKey
}
func (adaptor *ErgoAdaptor) ValueType(nebulaId account.NebulaId, ctx context.Context) (abi.ExtractorType, error) {
	dataType, err := helpers.GetDataType(ctx)
	if err != nil {
		return 0, err
	}
	return abi.ExtractorType(uint8(dataType)), nil
}

func (adaptor *ErgoAdaptor) AddPulse(nebulaId account.NebulaId, pulseId uint64, validators []account.OraclesPubKey, hash []byte, ctx context.Context) (string, error) {
	type AddPulseInfo struct {
		Success  bool   `json:"success"`
		Oracles []string `json:"oracles"`
		Bft     int      `json:"bft"`
	}

	type Sign struct {
		A []string `json:"a"`
		Z []string `json:"z"`
	}
	type Data struct {
		Signs Sign   `json:"signs"`
		Hash  string `json:"hashData"`
	}
	type Tx struct {
		Success bool   `json:"success"`
		TxId    string `json:"txId"`
	}
	var oracles []string
	var signsA []string
	var signsZ []string
	realSignCount := 0

	// Get oracles and bftValue
	url, err := helpers.JoinUrl(adaptor.ergoClient.Options.BaseUrl, "adaptor/getPreAddPulseInfo")
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, "GET", url.String(), nil)
	if err != nil {
		return "", err
	}
	result := new(AddPulseInfo)
	_, err = adaptor.ergoClient.Do(req, result)
	if err != nil {
		return "", err
	}
	if !result.Success {
		return "", errors.New("can't get oracles")
	} else if result.Success {
		oracles = result.Oracles
	}

	// Iterate over oracles and get signs
	for i, oracle := range oracles {
		tmpOracle := oracle
		if oracles[i] == hex.EncodeToString(defaultPK) {
			if i == 1 || i == 2{
				tmpOracle = oracles[1]
			}
		}
		pubKey, err := account.StringToOraclePubKey(tmpOracle, account.Ergo)
		if err != nil {
			signsA = append(signsA, strings.Repeat("0", 66))
			signsZ = append(signsZ, "00")
			continue
		}
		sign, err := adaptor.ghClient.Result(account.Ergo, nebulaId, int64(pulseId), pubKey)

		if err != nil {
			signsA = append(signsA, strings.Repeat("0", 66))
			signsZ = append(signsZ, "00")
			continue
		}
		signsA = append(signsA, string(sign[:66]))
		signsZ = append(signsZ, string(sign[66:]))
		realSignCount++
	}

	// Check realSignCount with bftValue before sending data
	if realSignCount < result.Bft {
		return "", nil
	}

	// Send oracleSigns to be verified by contract in proxy side and get txId
	data, err := json.Marshal(Data{Signs: Sign{A: signsA, Z: signsZ}, Hash: hex.EncodeToString(hash)})
	url, err = helpers.JoinUrl(adaptor.ergoClient.Options.BaseUrl, "adaptor/addPulse")
	if err != nil {
		return "", err
	}
	req, err = http.NewRequestWithContext(ctx, "POST", url.String(), bytes.NewBuffer(data))
	if err != nil {
		return "", err
	}
	tx := new(Tx)
	_, err = adaptor.ergoClient.Do(req, tx)
	if err != nil {
		return "", err
	}

	return tx.TxId, nil
}
func (adaptor *ErgoAdaptor) SendValueToSubs(nebulaId account.NebulaId, pulseId uint64, value *extractor.Data, ctx context.Context) error {
	type Tx struct {
		Success bool   `json:"success"`
		TxId    string `json:"txId"`
	}

	dataType, err := helpers.GetDataType(ctx)
	if err != nil {
		return err
	}

	data := make(map[string]interface{})
	data["pulseId"] = strconv.FormatUint(pulseId, 10)

	switch SubType(dataType) {
	case Int64:
		v, err := strconv.ParseInt(value.Value, 10, 64)
		if err != nil {
			return err
		}
		data["Value"] = hex.EncodeToString([]byte(strconv.FormatInt(v, 10)))
	case String:
		data["Value"] = hex.EncodeToString([]byte(value.Value))
	case Bytes:
		v, err := base64.StdEncoding.DecodeString(value.Value)
		if err != nil {
			return err
		}
		data["value"] = hex.EncodeToString(v)
	}

	jsonData, err := json.Marshal(data)
	zap.L().Sugar().Debugf("sendValueToSubs Data: %v", bytes.NewBuffer(jsonData))
	url, err := helpers.JoinUrl(adaptor.ergoClient.Options.BaseUrl, "adaptor/sendValueToSubs")
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", url.String(), bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	tx := new(Tx)
	_, err = adaptor.ergoClient.Do(req, tx)
	if err != nil {
		return err
	}
	return nil
}

func (adaptor *ErgoAdaptor) SetOraclesToNebula(nebulaId account.NebulaId, oracles []*account.OraclesPubKey, signs map[account.OraclesPubKey][]byte, round int64, ctx context.Context) (string, error) {
	type Tx struct {
		Success bool   `json:"success"`
		TxId    string `json:"txId"`
	}
	type Consuls struct {
		Success bool     `json:"success"`
		Consuls []string `json:"consuls"`
	}
	type Sign struct {
		A []string `json:"a"`
		Z []string `json:"z"`
	}
	type Data struct {
		NewOracles []string `json:"newOracles"`
		Signs      Sign     `json:"signs"`
		RoundId    int64    `json:"roundId"`
	}

	lastRound, err := adaptor.LastRound(ctx)
	if err != nil {
		return "", err
	}
	if uint64(round) <= lastRound {
		return "", errors.New("this is not a new round")
	}

	var consuls []string
	url, err := helpers.JoinUrl(adaptor.ergoClient.Options.BaseUrl, "adaptor/getConsuls")
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, "GET", url.String(), nil)
	result := new(Consuls)
	_, err = adaptor.ergoClient.Do(req, result)
	if err != nil {
		return "", err
	}
	if !result.Success {
		return "", errors.New("can't get consuls")
	} else {
		consuls = result.Consuls
	}

	// zap.L().Sugar().Debugf("consuls => %v", consuls)
	var signsA = make([]string, len(consuls), len(consuls))
	var signsZ = make([]string, len(consuls), len(consuls))

	for k, sign := range signs {
		pubKey := k.ToString(account.Ergo)
		// zap.L().Sugar().Debugf("pk => %v\n sign => %v", pubKey, string(sign))
		index := -1
		for i, v := range consuls {
			if v == pubKey {
				index = i
				break
			}
		}
		if index == -1 {
			continue
		}
		signsA[index] = string(sign[:66])
		signsZ[index] = string(sign[66:])
	}

	// just in debug mode and if one consuls existed
	for i := 1; i < len(oracles); i++ {
		if signsA[i] == "" {
			if i <= 2 {
				signsA[i] = signsA[i-1]
				signsZ[i] = signsZ[i-1]
			} else {
				signsA[i] = strings.Repeat("0", 66)
				signsZ[i] = "00"
			}
		}
	}

	var newOracles = make([]string, len(oracles), len(oracles))

	zap.L().Sugar().Debugf("oracles: %v", oracles)
	for i, v := range oracles {
		if v == nil {
			if i == 1 {
				newOracles[i] = hex.EncodeToString(oracles[i-1].ToBytes(account.Ergo))
				newOracles[i+1] = hex.EncodeToString(oracles[i-1].ToBytes(account.Ergo))
			} else if i == 2 && oracles[i-1] != nil {
				newOracles[i] = hex.EncodeToString(oracles[i-1].ToBytes(account.Ergo))
			} else if i > 2 {
				newOracles[i] = hex.EncodeToString(defaultPK)
			}
			continue
		}
		newOracles[i] = hex.EncodeToString(oracles[i].ToBytes(account.Ergo))
	}

	url, err = helpers.JoinUrl(adaptor.ergoClient.Options.BaseUrl, "adaptor/updateOracles")
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(Data{NewOracles: newOracles, Signs: Sign{A: signsA, Z: signsZ}, RoundId: round})
	zap.L().Sugar().Debugf("updateOracles: data => %v", bytes.NewBuffer(data))
	req, err = http.NewRequest("POST", url.String(), bytes.NewBuffer(data))
	tx := new(Tx)
	_, err = adaptor.ergoClient.Do(req, tx)
	if err != nil {
		return "", err
	}
	if !tx.Success {
		return "", err
	}

	return tx.TxId, nil
}
func (adaptor *ErgoAdaptor) SendConsulsToGravityContract(newConsulsAddresses []*account.OraclesPubKey, signs map[account.OraclesPubKey][]byte, round int64, ctx context.Context) (string, error) {
	type Tx struct {
		Success bool   `json:"success"`
		TxId    string `json:"txId"`
	}
	type Consuls struct {
		Success bool     `json:"success"`
		Consuls []string `json:"consuls"`
	}
	type Sign struct {
		A []string `json:"a"`
		Z []string `json:"z"`
	}
	type Data struct {
		NewConsuls []string `json:"newConsuls"`
		Signs      Sign     `json:"signs"`
		RoundId    int64    `json:"roundId"`
	}

	lastRound, err := adaptor.LastRound(ctx)
	if err != nil {
		return "", err
	}
	if uint64(round) <= lastRound {
		return "", errors.New("this is not a new round")
	}

	var consuls []string
	url, err := helpers.JoinUrl(adaptor.ergoClient.Options.BaseUrl, "adaptor/getConsuls")
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, "GET", url.String(), nil)
	result := new(Consuls)
	_, err = adaptor.ergoClient.Do(req, result)
	if err != nil {
		return "", err
	}
	if !result.Success {
		return "", errors.New("can't get consuls")
	} else {
		consuls = result.Consuls
	}

	var signsA = make([]string, len(consuls), len(consuls))
	var signsZ = make([]string, len(consuls), len(consuls))
	// zap.L().Sugar().Debugf("Consuls => %v", consuls)
	for k, sign := range signs {
		pubKey := k.ToString(account.Ergo)
		// zap.L().Sugar().Debugf("pk => %v\n sign => %v", pubKey, string(sign))

		index := -1
		for i, v := range consuls {
			if v == pubKey {
				index = i
				break
			}
		}

		if index == -1 {
			continue
		}
		signsA[index] = string(sign[:66])
		signsZ[index] = string(sign[66:])
	}

	// just in debug mode and if one consuls existed
	for i := 1; i < len(consuls); i++ {
		if signsA[i] == "" {
			if i == 1 {
				signsA[i] = signsA[i-1]
				signsA[i+1] = signsA[i-1]
				signsZ[i] = signsZ[i-1]
				signsZ[i+1] = signsZ[i-1]
			} else if i == 2 {
				signsA[i] = signsA[i-1]
				signsZ[i] = signsZ[i-1]
			} else {
				signsA[i] = strings.Repeat("0", 66)
				signsZ[i] = "00"
			}
		}
	}

	var newConsulsString = make([]string, ConsulsNumber, ConsulsNumber)
	// just in debug mode and if one consuls existed
	for i := 0; i < len(newConsulsAddresses); i++ {
		if newConsulsAddresses[i] == nil {
			if i == 1 {
				newConsulsString[i] = hex.EncodeToString(newConsulsAddresses[0].ToBytes(account.Ergo))
				newConsulsString[i+1] = hex.EncodeToString(newConsulsAddresses[0].ToBytes(account.Ergo))
			} else if i == 2 && newConsulsAddresses[i-1] != nil {
				newConsulsString[i] = newConsulsString[i-1]
			} else if i > 2 {
				newConsulsString[i] = DefaultConsul
			}
		} else {
			newConsulsString[i] = hex.EncodeToString(newConsulsAddresses[i].ToBytes(account.Ergo))
		}
	}

	emptyCount := ConsulsNumber - len(newConsulsString)
	for i := 0; i < emptyCount; i++ {
		newConsulsString = append(newConsulsString, DefaultConsul)
	}

	url, err = helpers.JoinUrl(adaptor.ergoClient.Options.BaseUrl, "adaptor/updateConsuls")
	if err != nil {
		return "", err
	}

	data, err := json.Marshal(&Data{NewConsuls: newConsulsString, Signs: Sign{A: signsA, Z: signsZ}, RoundId: round})
	zap.L().Sugar().Debugf("updateConsuls: data => %v", bytes.NewBuffer(data))
	req, err = http.NewRequest("POST", url.String(), bytes.NewBuffer(data))
	tx := new(Tx)
	_, err = adaptor.ergoClient.Do(req, tx)
	if err != nil {
		return "", err
	}
	if !tx.Success {
		return "", err
	}

	return tx.TxId, nil
}
func (adaptor *ErgoAdaptor) SignConsuls(consulsAddresses []*account.OraclesPubKey, roundId int64, sender account.OraclesPubKey) ([]byte, error) {
	//var msg []byte
	DefaultConsulByte, _ := hex.DecodeString(DefaultConsul)

	var msg = make([]byte, 0, len(consulsAddresses))
	// just in debug mode and if one consuls existed
	firstConsul := consulsAddresses[0].ToBytes(account.Ergo)
	for i := 0; i < len(consulsAddresses); i++ {
		if consulsAddresses[i] == nil {
			if i == 1 {
				msg = append(msg, firstConsul...)
				msg = append(msg, firstConsul...)
			} else if i == 2 && consulsAddresses[i-1] != nil {
				msg = append(msg, consulsAddresses[i-1].ToBytes(account.Ergo)...)
			} else if i > 2 {
				msg = append(msg, DefaultConsulByte...)
			}
		} else {
			msg = append(msg, consulsAddresses[i].ToBytes(account.Ergo)...)
		}
	}

	//if consulsAddresses[1] == nil {
	//	for i := 0; i < 3; i++ {
	//		msg = append(msg, consulsAddresses[0].ToBytes(account.Ergo)...)
	//	}
	//	for i := 0; i < 2; i++ {
	//		msg = append(msg, DefaultConsulByte...)
	//	}
	//} else {
	//	// in real this must be exist
	//	for _, v := range consulsAddresses {
	//		if v == nil {
	//			msg = append(msg, DefaultConsulByte...)
	//			continue
	//		}
	//		msg = append(msg, v.ToBytes(account.Ergo)...)
	//	}
	//}

	//for _, v := range consulsAddresses {
	//	if v == nil {
	//		msg = append(msg, strings.Repeat("0", 66))
	//		continue
	//	}
	//	msg = append(msg, hex.EncodeToString(v.ToBytes(account.Ergo)))
	//}

	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(roundId))
	msg = append(msg, b...)
	//msg = append(msg, fmt.Sprintf("%d", myRound))

	//msgHex, _ := hex.DecodeString(strings.Join(msg, ""))
	sign, err := adaptor.Sign(msg)
	if err != nil {
		return nil, err
	}
	// zap.L().Sugar().Debugf("SignConsuls erg => %v", string(sign))

	return sign, err
}
func (adaptor *ErgoAdaptor) SignOracles(nebulaId account.NebulaId, oracles []*account.OraclesPubKey, round int64, sender account.OraclesPubKey) ([]byte, error) {
	var msg []byte

	for i, v := range oracles {
		if v == nil {
			if i == 1 {
				msg = append(msg, oracles[i-1].ToBytes(account.Ergo)...)
				msg = append(msg, oracles[i-1].ToBytes(account.Ergo)...)
			} else if i == 2 && oracles[i-1] != nil {
				msg = append(msg, oracles[i-1].ToBytes(account.Ergo)...)
			} else if i > 2 {
				msg = append(msg, defaultPK...)
			}
			continue
		}
		msg = append(msg, v.ToBytes(account.Ergo)...)
	}

	sign, err := adaptor.Sign(msg)
	if err != nil {
		return nil, err
	}

	return sign, err
}

func (adaptor *ErgoAdaptor) LastPulseId(nebulaId account.NebulaId, ctx context.Context) (uint64, error) {
	type Result struct {
		Success bool   `json:"success"`
		PulseId int64 `json:"lastPulseId"`
	}
	url, err := helpers.JoinUrl(adaptor.ergoClient.Options.BaseUrl, "adaptor/getLastPulseId")
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, "GET", url.String(), nil)
	if err != nil {
		return 0, err
	}
	result := new(Result)
	_, err = adaptor.ergoClient.Do(req, result)
	if err != nil {
		return 0, err
	}
	if !result.Success {
		return 0, errors.New("can't get lastPulseId")
	}
	return uint64(result.PulseId), nil
}
func (adaptor *ErgoAdaptor) LastRound(ctx context.Context) (uint64, error) {
	type Result struct {
		Success   bool  `json:"success"`
		LastRound int64 `json:"lastRound"`
	}
	// zap.L().Sugar().Debugf("\t\tLastRound\t\t")

	url, err := helpers.JoinUrl(adaptor.ergoClient.Options.BaseUrl, "adaptor/lastRound")
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, "GET", url.String(), nil)
	if err != nil {
		return 0, err
	}
	result := new(Result)
	_, err = adaptor.ergoClient.Do(req, result)
	if err != nil {
		return 0, err
	}
	// zap.L().Sugar().Debugf("LastRound: %v\n", result)
	if !result.Success {
		return 0, errors.New("can't get lastRound")
	}
	return uint64(result.LastRound), nil
}
func (adaptor *ErgoAdaptor) RoundExist(roundId int64, ctx context.Context) (bool, error) {
	lastRound, err := adaptor.LastRound(ctx)
	if err != nil {
		return false, err
	}
	if uint64(roundId) > lastRound {
		return false, nil
	}
	return true, nil

}
