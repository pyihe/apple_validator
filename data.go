package apple_validate

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

var (
	ErrInvalidHashType     = errors.New("invalid hash type")
	ErrInvalidTokenFormat  = errors.New("invalid token")
	ErrFetchKeysFail       = errors.New("invalid rsa public key")
	ErrInvalidClientID     = errors.New("invalid client_id")
	ErrInvalidClientSecret = errors.New("invalid client_secret")
	ErrInvalidRedirectURI  = errors.New("invalid redirect_uri")
	ErrTokenExpired        = errors.New("token expired")
	ErrInvalidIssValue     = errors.New("invalid iss value")
)

type JWTToken interface {
	Kid() string
	Alg() string
	Iss() string
	Aud() string
	Exp() int64
	Iat() int64
	Sub() string
	CHash() string
	AuthTime() int64
	Email() string
	EmailVerified() bool
	NonceSupported() bool
	IsPrivateEmail() bool
	IsValid() (bool, error)
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int64  `json:"expires_in"`
	IdToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"` //固定值: bearer
}

type appleKey struct {
	Kid string `json:"kid"` //公钥ID
	Alg string `json:"alg"` //签名算法
	Kty string `json:"kty"` //加密算法
	E   string `json:"e"`   //RSA公钥指数值
	N   string `json:"n"`   //RSA公钥模数值
	Use string `json:"use"` //
}

type appleHeader struct {
	Kid string `json:"kid"` //apple公钥的密钥ID
	Alg string `json:"alg"` //签名token的算法
}

type appleToken struct {
	header    *appleHeader //header
	headerStr string
	claims    *appleClaim //claims
	claimsStr string
	sign      string //签名
}

func (t *appleToken) Kid() string {
	if t == nil || t.claims == nil {
		return ""
	}
	return t.header.Kid
}

func (t *appleToken) Alg() string {
	if t == nil || t.claims == nil {
		return ""
	}
	return t.header.Alg
}

func (t *appleToken) Iss() string {
	if t == nil || t.claims == nil {
		return ""
	}
	return t.claims.Iss
}

func (t *appleToken) Aud() string {
	if t == nil || t.claims == nil {
		return ""
	}
	return t.claims.Aud
}

func (t *appleToken) Exp() int64 {
	if t == nil || t.claims == nil {
		return 0
	}
	return t.claims.Exp
}

func (t *appleToken) Iat() int64 {
	if t == nil || t.claims == nil {
		return 0
	}
	return t.claims.Iat
}

func (t *appleToken) Sub() string {
	if t == nil || t.claims == nil {
		return ""
	}
	return t.claims.Sub
}

func (t *appleToken) CHash() string {
	if t == nil || t.claims == nil {
		return ""
	}
	return t.claims.CHash
}

func (t *appleToken) AuthTime() int64 {
	if t == nil || t.claims == nil {
		return 0
	}
	return t.claims.AuthTime
}

func (t *appleToken) Email() string {
	if t == nil || t.claims == nil {
		return ""
	}
	return t.claims.Email
}

func (t *appleToken) EmailVerified() bool {
	if t == nil || t.claims == nil {
		return false
	}
	return t.claims.EmailVerified
}

func (t *appleToken) NonceSupported() bool {
	if t == nil || t.claims == nil {
		return false
	}
	return t.claims.NonceSupported
}

func (t *appleToken) IsPrivateEmail() bool {
	if t == nil || t.claims == nil {
		return false
	}
	return t.claims.IsPrivateEmail
}

func (t *appleToken) IsValid() (bool, error) {
	if t == nil || t.claims == nil {
		return false, ErrInvalidTokenFormat
	}
	if t.claims.Iss != "https://appleid.apple.com" {
		return false, ErrInvalidIssValue
	}
	var now = time.Now().Unix()
	if t.claims.Exp < now {
		return false, ErrTokenExpired
	}
	if t.claims.Iat > now {
		return false, ErrTokenExpired
	}
	return true, nil
}

func (t *appleToken) String() string {
	var hStr, cStr string
	if t.header != nil {
		hStr = fmt.Sprintf("%+v", *t.header)
	}
	if t.claims != nil {
		cStr = fmt.Sprintf("%+v", *t.claims)
	}
	return fmt.Sprintf("Header: [%s], Claims: [%s], Sign: [%s]\n", hStr, cStr, t.sign)
}

type appleClaim struct {
	Iss            string `json:"iss"`       //签发者，固定值: https://appleid.apple.com
	Aud            string `json:"aud"`       //App ID
	Exp            int64  `json:"exp"`       //token过期时间
	Iat            int64  `json:"iat"`       //token生成时间
	Sub            string `json:"sub"`       //用户唯一标识
	CHash          string `json:"c_hash"`    //
	AuthTime       int64  `json:"auth_time"` //验证时间
	Email          string `json:"email"`     //邮件
	EmailVerified  bool   `json:"email_verified"`
	NonceSupported bool   `json:"nonce_supported"`
	IsPrivateEmail bool   `json:"is_private_email"`
}

func (c *appleClaim) UnmarshalJSON(data []byte) error {

	src := bytes2String(data)
	src = strings.TrimLeft(src, "{")
	src = strings.TrimRight(src, "}")
	kvs := strings.Split(src, ",")
	var err error
	var kv []string
	var key, value string
	for _, kvStr := range kvs {
		kv = strings.Split(kvStr, "\":")
		key = strings.ReplaceAll(kv[0], "\"", "")
		value = strings.ReplaceAll(kv[1], "\"", "")
		switch key {
		case "iss":
			c.Iss = value
		case "aud":
			c.Aud = value
		case "sub":
			c.Sub = value
		case "c_hash":
			c.CHash = value
		case "email":
			c.Email = value
		case "auth_time":
			c.AuthTime, err = strconv.ParseInt(value, 10, 64)
		case "exp":
			c.Exp, err = strconv.ParseInt(value, 10, 64)
		case "iat":
			c.Iat, err = strconv.ParseInt(value, 10, 64)
		case "email_verified":
			c.EmailVerified, err = strconv.ParseBool(value)
		case "nonce_supported":
			c.NonceSupported, err = strconv.ParseBool(value)
		case "is_private_email":
			c.IsPrivateEmail, err = strconv.ParseBool(value)
		default:
			err = fmt.Errorf("unmarshal claims fail, invalid key: %s", key)
		}
		if err != nil {
			return err
		}
	}
	return nil
}
