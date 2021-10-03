package adaptors

import (
	"context"
	"github.com/Gravity-Tech/gravity-core/common/account"
	"github.com/Gravity-Tech/gravity-core/common/gravity"
	"reflect"
	"time"

	crypto "crypto/ed25519"
	"crypto/rand"
	"github.com/Gravity-Tech/gravity-core/common/helpers"
	"testing"
)

const proxyUrl = ""

func TestErgoAdaptor_applyOpts(t *testing.T) {
	f := NewFactory()
	if f != nil {
	}

	ghClient := gravity.Client{}
	ergClient := helpers.ErgClient{}
	wanted := ErgoAdaptor{
		ergoClient:      &ergClient,
		ghClient:        &ghClient,
		gravityContract: "contract",
	}
	validOpts := AdapterOptions{
		"ergClient":       &ergClient,
		"ghClient":        &ghClient,
		"gravityContract": "contract",
	}

	type args struct {
		opts AdapterOptions
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
		want    ErgoAdaptor
	}{
		{name: "Test valid options", args: args{opts: validOpts}, wantErr: false, want: wanted},
		{name: "Test invalid ghClient", args: args{opts: AdapterOptions{
			"ghClient":        6,
			"ergClient":       &ergClient,
			"gravityContract": "contract",
		}}, wantErr: true},
		{name: "Test invaid ergoClient", args: args{opts: AdapterOptions{
			"ghClient":        &ghClient,
			"ergClient":       5,
			"gravityContract": "contract"}}, wantErr: true},
		{name: "Test invaid gravityContract", args: args{opts: AdapterOptions{
			"ghClient":        &ghClient,
			"ergClient":       &ergClient,
			"gravityContract": 56,
		}}, wantErr: true},

		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ea := &ErgoAdaptor{}
			if err := ea.applyOpts(tt.args.opts); (err != nil) != tt.wantErr {
				t.Errorf("ErgoAdaptor.applyOpts() error = %v, wantErr %v", err, tt.wantErr)
			} else if !tt.wantErr {
				if ea.ghClient != tt.want.ghClient {
					t.Errorf("ghClientValidator() = %v, want %v", *ea, tt.want)
				}
			}
		})
	}
}

func TestErgoAdaptor_GetHeight(t *testing.T) {
	ctx1, cancel1 := context.WithTimeout(context.Background(), 100*time.Millisecond)
	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel1()
	defer cancel2()

	tests := []struct {
		name    string
		ctx     context.Context
		wantErr bool
	}{
		{name: "Test valid options", ctx: ctx2, wantErr: false},
		{name: "Test valid options", ctx: ctx1, wantErr: true},

		// TODO: Add test cases.
	}
	seed := make([]byte, 32)
	rand.Read(seed)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, _ := helpers.NewClient(helpers.ErgOptions{ApiKey: "", BaseUrl: proxyUrl})
			secret := crypto.NewKeyFromSeed(seed)
			er := &ErgoAdaptor{
				ergoClient: client,
				secret:     secret,
			}
			if height, err := er.GetHeight(tt.ctx); (err != nil) != tt.wantErr {
				t.Errorf("ErgoAdaptor.GetHeight error = %v, wantErr %v", err, tt.wantErr)
			} else {
				t.Logf("ErgoAdaptor.GetHeight height = %v", height)
			}

		})
	}
}

func TestErgoAdaptor_Sign(t *testing.T) {
	tests := []struct {
		name string
		msg  []byte
	}{
		{name: "Test valid options", msg: []byte("salam")},
		// TODO: Add test cases.
	}
	seed := make([]byte, 32)
	rand.Read(seed)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, _ := helpers.NewClient(helpers.ErgOptions{ApiKey: "", BaseUrl: proxyUrl})
			secret := crypto.NewKeyFromSeed(seed)
			er := &ErgoAdaptor{
				ergoClient: client,
				secret:     secret,
			}
			if signs, err := er.Sign(tt.msg); err != nil {
				t.Errorf("ErgoAdaptor.sign error = %v", err)
			} else {
				t.Logf("ErgoAdaptor.sign sign = %v", signs)
			}
		})
	}
}

func TestErgoAdaptor_WaitTx(t *testing.T) {
	type Response struct {
		Status  bool `json:"success"`
		Confirm int  `json:"numConfirmations"`
	}
	wanted := Response{
		Status: true,
	}

	tests := []struct {
		name    string
		id      string
		wantErr bool
		want    Response
	}{
		{name: "Test invalid options", id: "ksah289hf2nhf", wantErr: true, want: wanted},
		// TODO: Add test cases.
	}
	seed := make([]byte, 32)
	rand.Read(seed)
	ctx, _ := context.WithTimeout(context.Background(), 500*time.Millisecond)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, _ := helpers.NewClient(helpers.ErgOptions{ApiKey: "", BaseUrl: proxyUrl})
			secret := crypto.NewKeyFromSeed(seed)
			er := &ErgoAdaptor{
				ergoClient: client,
				secret:     secret,
			}
			if err := er.WaitTx(tt.id, ctx); (err != nil) != tt.wantErr {
				t.Errorf("ErgoAdaptor.WaitTx error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestErgo_PubKey(t *testing.T) {
	type Response struct {
		Status  bool   `json:"success"`
		Address string `json:"address"`
		Pk      string `json:"pk"`
	}
	tests := []struct {
		name    string
	}{
		{name: "Test invalid options"},
		// TODO: Add test cases.
	}
	seed := make([]byte, 32)
	rand.Read(seed)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, _ := helpers.NewClient(helpers.ErgOptions{ApiKey: "", BaseUrl: proxyUrl})
			secret := crypto.NewKeyFromSeed(seed)
			er := &ErgoAdaptor{
				ergoClient: client,
				secret:     secret,
			}
			if pk := er.PubKey(); reflect.DeepEqual(pk.ToBytes(account.Ergo), []byte{}) {
				t.Errorf("ErgoAdaptor.Pubkey has some problem in making oracle pk")
			}
		})
	}
}

func TestErgoAdaptor_LastPulseId(t *testing.T) {
	ctx1, cancel1 := context.WithTimeout(context.Background(), 100*time.Millisecond)
	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel1()
	defer cancel2()

	tests := []struct {
		name    string
		ctx     context.Context
		nebulaId [32]byte
		wantErr bool
	}{
		{name: "Test valid options", nebulaId: [32]byte{}, ctx: ctx2, wantErr: false},
		{name: "Test valid options", nebulaId: [32]byte{}, ctx: ctx1, wantErr: true},

		// TODO: Add test cases.
	}
	seed := make([]byte, 32)
	rand.Read(seed)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, _ := helpers.NewClient(helpers.ErgOptions{ApiKey: "", BaseUrl: proxyUrl})
			secret := crypto.NewKeyFromSeed(seed)
			er := &ErgoAdaptor{
				ergoClient: client,
				secret:     secret,
			}
			if pulseId, err := er.LastPulseId(tt.nebulaId, tt.ctx); (err != nil) != tt.wantErr {
				t.Errorf("ErgoAdaptor.LastPulseId error = %v, wantErr %v", err, tt.wantErr)
			} else {
				t.Logf("ErgoAdaptor.LastPulseId pulseId = %v", pulseId)
			}

		})
	}
}

func TestErgoAdaptor_LastRound(t *testing.T) {
	ctx1, cancel1 := context.WithTimeout(context.Background(), 100*time.Millisecond)
	ctx2, cancel2 := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel1()
	defer cancel2()

	tests := []struct {
		name    string
		ctx     context.Context
		wantErr bool
	}{
		{name: "Test valid options", ctx: ctx2, wantErr: false},
		{name: "Test valid options", ctx: ctx1, wantErr: true},

		// TODO: Add test cases.
	}
	seed := make([]byte, 32)
	rand.Read(seed)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, _ := helpers.NewClient(helpers.ErgOptions{ApiKey: "", BaseUrl: proxyUrl})
			secret := crypto.NewKeyFromSeed(seed)
			er := &ErgoAdaptor{
				ergoClient: client,
				secret:     secret,
			}
			if round, err := er.LastRound(tt.ctx); (err != nil) != tt.wantErr {
				t.Errorf("ErgoAdaptor.LastRound error = %v, wantErr %v", err, tt.wantErr)
			} else {
				t.Logf("ErgoAdaptor.LastRound round = %v", round)
			}

		})
	}
}