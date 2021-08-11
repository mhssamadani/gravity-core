package helpers

import (
	"context"
	"encoding/json"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"time"
)

type ErgDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type ErgOptions struct {
	BaseUrl string
	Doer    ErgDoer
	ApiKey  string
}

var DefaultOptions = ErgOptions{
	BaseUrl: "http://176.9.65.58:9016/",
	Doer:    &http.Client{Timeout: 3 * time.Second},
}

type ErgClient struct {
	Options ErgOptions
}

type Response struct {
	*http.Response
}

type RequestError struct {
	Err  error
	Body string
}

func (a *RequestError) Error() string {
	if a.Body != "" {
		return errors.Wrap(a.Err, a.Body).Error()
	}
	return a.Err.Error()
}

type ParseError struct {
	Err error
}

func (a ParseError) Error() string {
	return a.Err.Error()
}

// Creates new client instance
// If no options provided will use default
func NewClient(options ...ErgOptions) (*ErgClient, error) {
	if len(options) > 1 {
		return nil, errors.New("too many options provided. Expects no or just one item")
	}

	opts := DefaultOptions

	if len(options) == 1 {
		option := options[0]

		if option.BaseUrl != "" {
			opts.BaseUrl = option.BaseUrl
		}

		if option.Doer != nil {
			opts.Doer = option.Doer
		}

		if option.ApiKey != "" {
			opts.ApiKey = option.ApiKey
		}
	}

	c := &ErgClient{
		Options: opts,
	}

	return c, nil
}

func GetDataType(ctx context.Context) (int, error) {
	type Result struct {
		Success  bool `json:"success"`
		DataType int  `json:"dataType"`
	}
	client, err := NewClient()
	if err != nil {
		return 0, err
	}
	url, err := JoinUrl(client.Options.BaseUrl, "adaptor/getDataType")
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, "GET", url.String(), nil)
	result := new(Result)
	_, err = client.Do(req, result)
	if err != nil {
		return 0, err
	}
	if !result.Success {
		return 0, errors.New("can't get lastRound")
	}
	return result.DataType, nil
}

func (a ErgClient) GetOptions() ErgOptions {
	return a.Options
}

//func withContext(ctx context.Context, req *http.Request) *http.Request {
//	return req.WithContext(ctx)
//}

func newResponse(response *http.Response) *Response {
	return &Response{
		Response: response,
	}
}

func (a *ErgClient) Do(req *http.Request, v interface{}) (*Response, error) {
	return doHttp(a.Options, req, v)
}

func doHttp(options ErgOptions, req *http.Request, v interface{}) (*Response, error) {
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "application/json")
	}
	req.Header.Set("Content-Type", "application/json")

	req.Close = true
	resp, err := options.Doer.Do(req)
	if err != nil {
		return nil, &RequestError{Err: err}
	}
	defer resp.Body.Close()

	response := newResponse(resp)
	body, _ := ioutil.ReadAll(response.Body)
	zap.L().Sugar().Debugf("response: %v\n", string(body))

	if response.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(response.Body)
		return response, &RequestError{
			Err:  errors.Errorf("Invalid status code: expect 200 got %d", response.StatusCode),
			Body: string(body),
		}
	}

	//select {
	//case <-ctx.Done():
	//	zap.L().Sugar().Debugf("ctx ended")
	//	return response, ctx.Err()
	//default:
	//}

	if v != nil {
		if err = json.Unmarshal(body, v); err != nil {
			zap.L().Sugar().Debugf("json parse error")
			return response, &ParseError{Err: err}
		}
	}
	return response, err
}

func JoinUrl(baseRaw string, pathRaw string) (*url.URL, error) {
	baseUrl, err := url.Parse(baseRaw)
	if err != nil {
		return nil, err
	}

	pathUrl, err := url.Parse(pathRaw)
	if err != nil {
		return nil, err
	}

	baseUrl.Path = path.Join(baseUrl.Path, pathUrl.Path)

	query := baseUrl.Query()
	for k := range pathUrl.Query() {
		query.Set(k, pathUrl.Query().Get(k))
	}
	baseUrl.RawQuery = query.Encode()

	return baseUrl, nil
}
