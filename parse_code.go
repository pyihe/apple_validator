package apple_validate

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

func (p *Parser) CheckIdentityCode(code string) (*TokenResponse, error) {
	if p.clientID == "" {
		return nil, ErrInvalidClientID
	}
	if p.clientSecret == "" {
		return nil, ErrInvalidClientSecret
	}
	//验证IdentityCode时需要填写redirect_uri参数，且redirect_uri参数必须是https协议
	if uri := strings.ToLower(p.redirectUri); strings.HasPrefix(uri, "https://") {
		return nil, ErrInvalidRedirectURI
	}

	param := fmt.Sprintf("client_id=%s&client_secret=%s&code=%s&grant_type=authorization_code&redirect_uri=%s", p.clientID, p.clientSecret, code, p.redirectUri)
	rder := strings.NewReader(param)
	response, err := http.Post("https://appleid.apple.com/auth/token", "application/x-www-form-urlencoded", rder)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("checking identityCode from apple server fail: %d", response.StatusCode)
	}

	data, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	var tkResult *TokenResponse
	if err = json.Unmarshal(data, &tkResult); err != nil {
		return nil, err
	}
	return tkResult, nil
}

func (p *Parser) CheckRefreshToken(refreshToken string) (*TokenResponse, error) {
	if p.clientID == "" {
		return nil, ErrInvalidClientID
	}
	if p.clientSecret == "" {
		return nil, ErrInvalidClientSecret
	}
	param := fmt.Sprintf("client_id=%s&client_secret=%s&grant_type=refresh_token&refresh_token=%s", p.clientID, p.clientSecret, refreshToken)
	rder := strings.NewReader(param)
	response, err := http.Post("https://appleid.apple.com/auth/token", "application/x-www-form-urlencoded", rder)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("checking refreshToken from apple server fail: %d", response.StatusCode)
	}

	data, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	var tkResult *TokenResponse
	if err = json.Unmarshal(data, &tkResult); err != nil {
		return nil, err
	}
	return tkResult, nil
}
