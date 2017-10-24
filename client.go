package goinone

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

var (
	baseURL = &url.URL{
		Scheme: "https",
		Host:   "api.coinone.co.kr",
	}
)

// AuthPayload 인증 헤더에 필요한 페이로드 필수 값
type AuthPayload struct {
	AccessToken string `json:"access_token"`
	Nonce       int64  `json:"nonce"`
}

// APIResponse api의 응답의 공통된 값들
type APIResponse struct {
	Result  string `json:"result"`
	ErrCode string `json:"errCode"`
}

// Balance accountv2 api balance
type Balance struct {
	Avail float64 `json:"avail"`
	Value float64 `json:"balance"`
}

// Client http api client 구조체
type Client struct {
	accountV2           *url.URL
	personalToken       string
	personalTokenSecret []byte
	*http.Client
}

// NewClient coinone api 클라이언트 생성자
func NewClient(pToken, pTokenSecret string) *Client {
	acV2 := *baseURL
	acV2.Path = "v2/account"

	return &Client{
		accountV2:           &acV2,
		personalToken:       pToken,
		personalTokenSecret: []byte(strings.ToUpper(pTokenSecret)),
		Client:              &http.Client{Timeout: time.Second * 10},
	}
}

func (c *Client) authPayload() AuthPayload {
	return AuthPayload{
		AccessToken: c.personalToken,
		Nonce:       time.Now().Unix(),
	}
}

func (c *Client) personalAuthHeader(payloadJSON []byte) (http.Header, error) {
	payloadBase64 := make([]byte, base64.StdEncoding.EncodedLen(len(payloadJSON)))
	base64.StdEncoding.Encode(payloadBase64, payloadJSON)
	hmac512 := hmac.New(sha512.New, c.personalTokenSecret)
	_, err := hmac512.Write(payloadBase64)
	if err != nil {
		return nil, err
	}
	signature := hex.EncodeToString(hmac512.Sum(nil))

	return http.Header{
		"content-type":        []string{"application/json"},
		"X-COINONE-PAYLOAD":   []string{string(payloadBase64)},
		"X-COINONE-SIGNATURE": []string{signature},
	}, nil
}

// Balance 사용자의 잔고 조회
func (c *Client) Balance() (map[string]Balance, error) {
	reqURL := *c.accountV2
	reqURL.Path = path.Join(reqURL.Path, "balance/")

	payload := c.authPayload()
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	authHeader, err := c.personalAuthHeader(payloadJSON)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", reqURL.String(), nil)
	req.Header = authHeader

	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	data, _ := ioutil.ReadAll(resp.Body)
	log.Print(string(data))

	balances := map[string]Balance{}
	unmarshal := json.NewDecoder(resp.Body)
	if err := unmarshal.Decode(balances); err != nil {
		return nil, err
	}
	return balances, nil
}
