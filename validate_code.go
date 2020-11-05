package apple_validator

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

func (v *Validator) CheckIdentityCode(code string) (*TokenResponse, error) {
	if code == "" {
		return nil, ErrInvalidIdentityCode
	}
	if v.clientID == "" {
		return nil, ErrInvalidClientID
	}
	if v.clientSecret == "" {
		return nil, ErrInvalidClientSecret
	}
	//验证IdentityCode时需要填写redirect_uri参数，且redirect_uri参数必须是https协议
	if uri := strings.ToLower(v.redirectUri); strings.HasPrefix(uri, "https://") {
		return nil, ErrInvalidRedirectURI
	}

	param := fmt.Sprintf("client_id=%s&client_secret=%s&code=%s&grant_type=authorization_code&redirect_uri=%s", v.clientID, v.clientSecret, code, v.redirectUri)
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

func (v *Validator) CheckRefreshToken(refreshToken string) (*TokenResponse, error) {
	if refreshToken == "" {
		return nil, ErrInvalidRefreshToken
	}
	if v.clientID == "" {
		return nil, ErrInvalidClientID
	}
	if v.clientSecret == "" {
		return nil, ErrInvalidClientSecret
	}
	param := fmt.Sprintf("client_id=%s&client_secret=%s&grant_type=refresh_token&refresh_token=%s", v.clientID, v.clientSecret, refreshToken)
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
