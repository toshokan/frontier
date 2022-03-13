package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/toshokan/frontier/internal/config"
	"github.com/toshokan/frontier/internal/security"
	"net/http"
	"net/url"
)

const (
	stateLabel = "state"
)

type State struct {
	OriginalUrl  string `json:"original_url"`
	PkceVerifier string `json:"pkce_verifier"`
}

type AuthHandle struct {
	config *config.Config
}

type PkceChallenge struct {
	Verifier  string
	Method    string
	Challenge string
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	Scope       string `json:"scope"`
}

type UserInfo struct {
	Subject string `json:"sub"`
}

func NewAuthHandle(cfg *config.Config) *AuthHandle {
	return &AuthHandle{cfg}
}

func NewPkceChallenge() (*PkceChallenge, error) {
	b := make([]byte, 66)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	verifier := base64.URLEncoding.EncodeToString(b)
	sha := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sha[:])

	return &PkceChallenge{
		verifier,
		"S256",
		challenge}, nil
}

func (h *AuthHandle) GetAuthorizationRequestUrl(originalUrl string, callbackPath string) (*url.URL, error) {
	challenge, err := NewPkceChallenge()
	if err != nil {
		return nil, err
	}

	state := State{originalUrl, challenge.Verifier}
	stateValue, err := security.EncryptAsJson(h.config, &state, stateLabel)
	if err != nil {
		return nil, err
	}

	query := url.Values{
		"response_type":         {"code"},
		"client_id":             {h.config.ClientId},
		"scope":                 {h.config.Scopes},
		"redirect_uri":          {h.config.BaseUrl + callbackPath},
		"code_challenge":        {challenge.Challenge},
		"code_challenge_method": {challenge.Method},
		"state":                 {stateValue}}

	requestUrl, err := url.Parse(h.config.AuthEndpoint)
	if err != nil {
		return nil, err
	}

	requestUrl.RawQuery = query.Encode()

	return requestUrl, nil
}

func (h *AuthHandle) GetToken(code string, state string, callbackPath string) (*TokenResponse, *State, error) {
	var stateValue State
	err := security.DecryptAsJson(h.config, state, &stateValue, stateLabel)
	if err != nil {
		return nil, nil, err
	}

	formData := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {h.config.BaseUrl + callbackPath},
		"client_id":     {h.config.ClientId},
		"client_secret": {h.config.ClientSecret},
		"code_verifier": {stateValue.PkceVerifier}}

	resp, err := http.PostForm(h.config.TokenEndpoint, formData)
	if err != nil {
		return nil, nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, nil, errors.New(fmt.Sprintf("Got error while requesting a token. Status Code = %d", resp.StatusCode))
	}

	defer resp.Body.Close()
	var tokenResponse TokenResponse
	if err = json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return nil, nil, err
	}

	return &tokenResponse, &stateValue, nil
}

func (h *AuthHandle) GetUserInfo(token string) (*UserInfo, error) {
	client := http.Client{}
	req, err := http.NewRequest(http.MethodGet, h.config.UserInfoEndpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New(fmt.Sprintf("Got error while getting UserInfo. StatusCode = %d", resp.StatusCode))
	}

	defer resp.Body.Close()
	var userInfo UserInfo
	if err = json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, err
	}

	return &userInfo, nil
}
