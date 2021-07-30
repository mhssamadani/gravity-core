package adaptors

import (
	"bytes"
	"context"
	"encoding/base64"
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
	Consuls = 5
)

type SigmaAdaptor struct {
	secret crypto.PrivateKey

	sigmaClient     *helpers.ErgClient `option:"sigmaClient"`
	ghClient        *gravity.Client    `option:"ghClient"`
	gravityContract string             `option:"gravityContract"`
}

type SigmaAdapterOption func(*SigmaAdaptor) error

func (adaptor *SigmaAdaptor) applyOpts(opts AdapterOptions) error {
	err := validateSigmaAdapterOptions(opts)
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
				adaptor.sigmaClient = val.(*helpers.ErgClient)
			case "gravityContract":
				adaptor.gravityContract = val.(string)

			}
		}
	}
	return nil
}

func validateSigmaAdapterOptions(opts AdapterOptions) error {
	v := validate.Map(opts)
	v.AddRule("ghClient", "isGhClient")
	v.AddRule("ergClient", "isErgClient")
	v.AddRule("gravityContract", "string")

	if !v.Validate() { // validate ok
		return v.Errors
	}
	return nil
}

func WithSigmaGravityContract(address string) SigmaAdapterOption {
	return func(h *SigmaAdaptor) error {
		h.gravityContract = address
		return nil
	}
}

func SigmaAdapterWithGhClient(ghClient *gravity.Client) SigmaAdapterOption {
	return func(h *SigmaAdaptor) error {
		h.ghClient = ghClient
		return nil
	}
}

func NewSigmaAdapterByOpts(seed []byte, nodeUrl string, ctx context.Context, opts AdapterOptions) (*SigmaAdaptor, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", nodeUrl, nil)
	if err != nil {
		return nil, err
	}
	client, err := helpers.NewClient(helpers.ErgOptions{ApiKey: "", BaseUrl: nodeUrl})
	if err != nil {
		return nil, err
	}

	_, err = client.Do(ctx, req, nil)
	if err != nil {
		return nil, err
	}
	secret := crypto.NewKeyFromSeed(seed)
	adapter := &SigmaAdaptor{
		secret:      secret,
		sigmaClient: client,
	}
	err = adapter.applyOpts(opts)
	if err != nil {
		return nil, err
	}

	return adapter, nil
}

func NewSigmaAdapter(seed []byte, nodeUrl string, ctx context.Context, opts ...SigmaAdapterOption) (*SigmaAdaptor, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", nodeUrl, nil)
	if err != nil {
		return nil, err
	}
	client, err := helpers.NewClient(helpers.ErgOptions{ApiKey: "", BaseUrl: nodeUrl})
	if err != nil {
		return nil, err
	}

	_, err = client.Do(ctx, req, nil)
	if err != nil {
		return nil, err
	}

	secret := crypto.NewKeyFromSeed(seed)
	er := &SigmaAdaptor{
		sigmaClient: client,
		secret:      secret,
	}
	for _, opt := range opts {
		err := opt(er)
		if err != nil {
			return nil, err
		}
	}
	return er, nil
}

func (adaptor *SigmaAdaptor) WaitTx(id string, ctx context.Context) error {
	type Response struct {
		Status  bool `json:"success"`
		Confirm int  `json:"numConfirmations"`
	}
	out := make(chan error)
	const TxWaitCount = 10
	url, err := helpers.JoinUrl(adaptor.sigmaClient.Options.BaseUrl, "numConfirmations")
	if err != nil {
		out <- err
	}
	go func() {
		defer close(out)
		for i := 0; i <= TxWaitCount; i++ {
			req, err := http.NewRequest("GET", url.String()+"/:"+id, nil)
			if err != nil {
				out <- err
				break
			}
			response := new(Response)
			_, err = adaptor.sigmaClient.Do(ctx, req, response)
			if err != nil {
				out <- err
				break
			}

			if response.Confirm == -1 {
				_, err = adaptor.sigmaClient.Do(ctx, req, response)
				if err != nil {
					out <- err
					break
				}

				if response.Confirm == -1 {
					out <- errors.New("tx not found")
					break
				} else {
					break
				}
			}

			if TxWaitCount == i {
				out <- errors.New("tx not found")
				break
			}
			time.Sleep(time.Second)
		}
	}()
	return <-out
}

func (adaptor *SigmaAdaptor) GetHeight(ctx context.Context) (uint64, error) {
	type Response struct {
		Status bool   `json:"success"`
		Height uint64 `json:"height"`
	}
	url, err := helpers.JoinUrl(adaptor.sigmaClient.Options.BaseUrl, "height")
	if err != nil {
		return 0, err
	}

	req, err := http.NewRequest("GET", url.String(), nil)
	if err != nil {
		return 0, err
	}
	response := new(Response)
	_, err = adaptor.sigmaClient.Do(ctx, req, response)
	if err != nil {
		return 0, err
	}

	return response.Height, nil
}

func (adaptor *SigmaAdaptor) Sign(msg []byte) ([]byte, error) {
	type Sign struct {
		A string
		Z string
	}
	type Response struct {
		Status bool `json:"success"`
		Signed Sign `json:"signed"`
	}
	values := map[string]string{"msg": hex.EncodeToString(msg), "sk": hex.EncodeToString(adaptor.secret)}
	jsonValue, _ := json.Marshal(values)
	url, err := helpers.JoinUrl(adaptor.sigmaClient.Options.BaseUrl, "sign")
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
	return []byte(responseObject.Signed.A + responseObject.Signed.Z), nil
}

func (adaptor *SigmaAdaptor) SignHash(nebulaId account.NebulaId, intervalId uint64, pulseId uint64, hash []byte) ([]byte, error) {
	return adaptor.Sign(hash)
}

func (adaptor *SigmaAdaptor) PubKey() account.OraclesPubKey {
	type Response struct {
		Status  bool   `json:"success"`
		Address string `json:"address"`
		Pk      string `json:"pk"`
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	values := map[string]string{"sk": hex.EncodeToString(adaptor.secret)}
	jsonValue, _ := json.Marshal(values)
	url, _ := helpers.JoinUrl(adaptor.sigmaClient.Options.BaseUrl, "getAddressDetail")
	zap.L().Debug("getAddressDetail: make request")
	req, err := http.NewRequestWithContext(ctx, "POST", url.String(), bytes.NewBuffer(jsonValue))
	if err != nil {
		zap.L().Error(err.Error())
		panic(err)
	}
	zap.L().Debug("getAddressDetail: Do request")
	res := new(Response)
	_, err = adaptor.sigmaClient.Do(ctx, req, res)
	if err != nil {
		zap.L().Error(err.Error())
		panic(err)
	}

	if !res.Status {
		zap.L().Error("proxy connection problem")
		panic(err)
	}
	pk, _ := hex.DecodeString(res.Pk)
	oraclePubKey := account.BytesToOraclePubKey(pk[:], account.Ergo)
	return oraclePubKey
}

func (adaptor *SigmaAdaptor) ValueType(nebulaId account.NebulaId, ctx context.Context) (abi.ExtractorType, error) {
	dataType, err := helpers.GetDataType(ctx)
	if err != nil {
		return 0, err
	}
	return abi.ExtractorType(dataType), nil
}

func (adaptor *SigmaAdaptor) AddPulse(nebulaId account.NebulaId, pulseId uint64, validators []account.OraclesPubKey, hash []byte, ctx context.Context) (string, error) {
	type Oracle struct {
		State   bool     `json:"state"`
		Oracles []string `json:"oracles"`
		Bft     int      `json:"bft"`
	}
	type Result struct {
		Success  bool   `json:"success"`
		Response Oracle `json:"response"`
	}
	type Sign struct {
		a []string
		z []string
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
	url, err := helpers.JoinUrl(adaptor.sigmaClient.Options.BaseUrl, "adaptor/getPreAddPulseInfo")
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, "GET", url.String(), nil)
	if err != nil {
		return "", err
	}
	result := new(Result)
	_, err = adaptor.sigmaClient.Do(ctx, req, result)
	if err != nil {
		return "", err
	}
	if !result.Success {
		return "", errors.New("can't get oracles")
	} else if result.Success && !result.Response.State {
		return "", errors.New("wrong pulseID")
	} else {
		oracles = result.Response.Oracles
	}

	// Iterate over oracles and get signs
	for _, oracle := range oracles {
		pubKey, err := account.StringToOraclePubKey(oracle, account.Ergo)
		if err != nil {
			signsA = append(signsA, hex.EncodeToString([]byte{0}))
			signsZ = append(signsZ, hex.EncodeToString([]byte{0}))
			continue
		}
		sign, err := adaptor.ghClient.Result(account.Ergo, nebulaId, int64(pulseId), pubKey)

		if err != nil {
			signsA = append(signsA, hex.EncodeToString([]byte{0}))
			signsZ = append(signsZ, hex.EncodeToString([]byte{0}))
			continue
		}
		signsA = append(signsA, string(sign[:66]))
		signsZ = append(signsZ, string(sign[66:]))
		realSignCount++
	}

	// Check realSignCount with bftValue before sending data
	if realSignCount == 0 {
		return "", nil
	}
	if realSignCount < result.Response.Bft {
		return "", nil
	}

	// Send oracleSigns to be verified by contract in proxy side and get txId
	data, err := json.Marshal(Data{Signs: Sign{a: signsA, z: signsZ}, Hash: hex.EncodeToString(hash)})
	url, err = helpers.JoinUrl(adaptor.sigmaClient.Options.BaseUrl, "adaptor/addPulse")
	if err != nil {
		return "", err
	}
	req, err = http.NewRequestWithContext(ctx, "POST", url.String(), bytes.NewBuffer(data))
	if err != nil {
		return "", err
	}
	tx := new(Tx)
	_, err = adaptor.sigmaClient.Do(ctx, req, tx)
	if err != nil {
		return "", err
	}

	return tx.TxId, nil
}

func (adaptor *SigmaAdaptor) SendValueToSubs(nebulaId account.NebulaId, pulseId uint64, value *extractor.Data, ctx context.Context) error {
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
	url, err := helpers.JoinUrl(adaptor.sigmaClient.Options.BaseUrl, "adaptor/sendValueToSubs")
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", url.String(), bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	tx := new(Tx)
	_, err = adaptor.sigmaClient.Do(ctx, req, tx)
	if err != nil {
		return err
	}
	return nil
}

func (adaptor *SigmaAdaptor) SetOraclesToNebula(nebulaId account.NebulaId, oracles []*account.OraclesPubKey, signs map[account.OraclesPubKey][]byte, round int64, ctx context.Context) (string, error) {
	var signsA [5]string
	var signsZ [5]string
	type Tx struct {
		Success bool   `json:"success"`
		TxId    string `json:"txId"`
	}
	type Consuls struct {
		Success bool     `json:"success"`
		consuls []string `json:"consuls"`
	}
	type Sign struct {
		a [5]string
		z [5]string
	}
	type Data struct {
		newOracles []string `json:"newOracles"`
		Signs      Sign     `json:"signs"`
	}

	lastRound, err := adaptor.LastRound(ctx)
	if err != nil {
		return "", err
	}
	if uint64(round) <= lastRound {
		return "", errors.New("this is not a new round")
	}

	var consuls []string
	url, err := helpers.JoinUrl(adaptor.sigmaClient.Options.BaseUrl, "adaptor/getConsuls")
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, "GET", url.String(), nil)
	result := new(Consuls)
	_, err = adaptor.sigmaClient.Do(ctx, req, result)
	if err != nil {
		return "", err
	}
	if !result.Success {
		return "", errors.New("can't get consuls")
	} else {
		consuls = result.consuls
	}

	for k, sign := range signs {
		pubKey := k.ToString(account.Ergo)
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

	for i, v := range signsA {
		if v != "" {
			continue
		}

		signsA[i] = hex.EncodeToString([]byte{0})
		signsZ[i] = hex.EncodeToString([]byte{0})
	}

	var newOracles []string

	for _, v := range oracles {
		if v == nil {
			newOracles = append(newOracles, hex.EncodeToString([]byte{0}))
			continue
		}
		newOracles = append(newOracles, hex.EncodeToString(v.ToBytes(account.Ergo)))
	}

	url, err = helpers.JoinUrl(adaptor.sigmaClient.Options.BaseUrl, "adaptor/updateOracles")
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(Data{newOracles: newOracles, Signs: Sign{a: signsA, z: signsZ}})
	req, err = http.NewRequestWithContext(ctx, "POST", url.String(), bytes.NewBuffer(data))
	tx := new(Tx)
	_, err = adaptor.sigmaClient.Do(ctx, req, tx)
	if err != nil {
		return "", err
	}

	return tx.TxId, nil
}

func (adaptor *SigmaAdaptor) SendConsulsToGravityContract(newConsulsAddresses []*account.OraclesPubKey, signs map[account.OraclesPubKey][]byte, round int64, ctx context.Context) (string, error) {
	var signsA [5]string
	var signsZ [5]string
	type Tx struct {
		Success bool   `json:"success"`
		TxId    string `json:"txId"`
	}
	type Consuls struct {
		Success bool     `json:"success"`
		consuls []string `json:"consuls"`
	}
	type Sign struct {
		a [5]string
		z [5]string
	}
	type Data struct {
		newConsuls []string `json:"newConsuls"`
		Signs      Sign     `json:"signs"`
	}

	lastRound, err := adaptor.LastRound(ctx)
	if err != nil {
		return "", err
	}
	if uint64(round) <= lastRound {
		return "", errors.New("this is not a new round")
	}

	var consuls []string
	url, err := helpers.JoinUrl(adaptor.sigmaClient.Options.BaseUrl, "adaptor/getConsuls")
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, "GET", url.String(), nil)
	result := new(Consuls)
	_, err = adaptor.sigmaClient.Do(ctx, req, result)
	if err != nil {
		return "", err
	}
	if !result.Success {
		return "", errors.New("can't get consuls")
	} else {
		consuls = result.consuls
	}

	for k, sign := range signs {
		pubKey := k.ToString(account.Ergo)
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

	for i, v := range signsA {
		if v != "" {
			continue
		}

		signsA[i] = hex.EncodeToString([]byte{0})
		signsZ[i] = hex.EncodeToString([]byte{0})
	}

	var newConsulsString []string

	for _, v := range newConsulsAddresses {
		if v == nil {
			newConsulsString = append(newConsulsString, hex.EncodeToString([]byte{0}))
			continue
		}
		newConsulsString = append(newConsulsString, hex.EncodeToString(v.ToBytes(account.Ergo)))
	}

	emptyCount := ConsulsNumber - len(newConsulsString)
	for i := 0; i < emptyCount; i++ {
		newConsulsString = append(newConsulsString, hex.EncodeToString([]byte{0}))
	}

	url, err = helpers.JoinUrl(adaptor.sigmaClient.Options.BaseUrl, "adaptor/updateConsuls")
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(Data{newConsuls: newConsulsString, Signs: Sign{a: signsA, z: signsZ}})
	req, err = http.NewRequestWithContext(ctx, "POST", url.String(), bytes.NewBuffer(data))
	tx := new(Tx)
	_, err = adaptor.sigmaClient.Do(ctx, req, tx)
	if err != nil {
		return "", err
	}

	return tx.TxId, nil
}

func (adaptor *SigmaAdaptor) SignConsuls(consulsAddresses []*account.OraclesPubKey, roundId int64, sender account.OraclesPubKey) ([]byte, error) {
	var msg []string
	for _, v := range consulsAddresses {
		if v == nil {
			msg = append(msg, hex.EncodeToString([]byte{0}))
			continue
		}
		msg = append(msg, hex.EncodeToString(v.ToBytes(account.Ergo)))
	}
	msg = append(msg, fmt.Sprintf("%d", roundId))

	sign, err := adaptor.Sign([]byte(strings.Join(msg, ",")))
	if err != nil {
		return nil, err
	}

	return sign, err
}

func (adaptor *SigmaAdaptor) SignOracles(nebulaId account.NebulaId, oracles []*account.OraclesPubKey, round int64, sender account.OraclesPubKey) ([]byte, error) {
	var stringOracles []string
	for _, v := range oracles {
		if v == nil {
			stringOracles = append(stringOracles, hex.EncodeToString([]byte{1}))
			continue
		}
		stringOracles = append(stringOracles, hex.EncodeToString(v.ToBytes(account.Ergo)))
	}

	sign, err := adaptor.Sign([]byte(strings.Join(stringOracles, ",")))
	if err != nil {
		return nil, err
	}

	return sign, err
}

func (adaptor *SigmaAdaptor) LastPulseId(nebulaId account.NebulaId, ctx context.Context) (uint64, error) {
	type Result struct {
		Success bool   `json:"success"`
		PulseId string `json:"pulse_id"`
	}
	url, err := helpers.JoinUrl(adaptor.sigmaClient.Options.BaseUrl, "adaptor/getLastPulseId")
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, "GET", url.String(), nil)
	if err != nil {
		return 0, err
	}
	result := new(Result)
	_, err = adaptor.sigmaClient.Do(ctx, req, result)
	if err != nil {
		return 0, err
	}
	if !result.Success {
		return 0, errors.New("can't get lastPulseId")
	}
	pulseId, _ := strconv.ParseUint(result.PulseId, 10, 64)
	return pulseId, nil
}

func (adaptor *SigmaAdaptor) LastRound(ctx context.Context) (uint64, error) {
	type Result struct {
		Success   bool  `json:"success"`
		LastRound int64 `json:"lastRound"`
	}
	zap.L().Sugar().Debugf("\t\tLastRound\t\t")
	url, err := helpers.JoinUrl(adaptor.sigmaClient.Options.BaseUrl, "adaptor/lastRound")
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, "GET", url.String(), nil)
	if err != nil {
		return 0, err
	}
	result := new(Result)
	_, err = adaptor.sigmaClient.Do(ctx, req, result)
	if err != nil {
		return 0, err
	}
	zap.L().Sugar().Debugf("LastRound: %v\n", result)
	if !result.Success {
		return 0, errors.New("can't get lastRound")
	}
	return uint64(result.LastRound), nil
}

func (adaptor *SigmaAdaptor) RoundExist(roundId int64, ctx context.Context) (bool, error) {
	lastRound, err := adaptor.LastRound(ctx)
	if err != nil {
		return false, err
	}
	if uint64(roundId) > lastRound {
		return false, nil
	}
	return true, nil

}
