package apple_validate

import (
	"crypto"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"hash"
	"io/ioutil"
	"math/big"
	"net/http"
	"strings"
)

func (p *Parser) CheckIdentityToken(token string) (JWTToken, error) {
	appleToken, err := parseToken(token)
	if err != nil {
		return nil, err
	}
	key, err := fetchKeysFromApple(appleToken.header.Kid)
	if err != nil {
		return nil, err
	}
	if key == nil {
		return nil, ErrFetchKeysFail
	}

	pubKey, err := generatePubKey(key.N, key.E)
	if err != nil {
		return nil, err
	}

	//利用获取到的公钥解密token中的签名数据
	sig, err := decodeSegment(appleToken.sign)
	if err != nil {
		return nil, err
	}

	//苹果使用的是SHA256
	var h hash.Hash
	switch appleToken.header.Alg {
	case "RS256":
		h = crypto.SHA256.New()
	case "RS384":
		h = crypto.SHA384.New()
	case "RS512":
		h = crypto.SHA512.New()
	}
	if h == nil {
		return nil, ErrInvalidHashType
	}

	h.Write([]byte(appleToken.headerStr + "." + appleToken.claimsStr))

	return appleToken, rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, h.Sum(nil), sig)
}

func parseToken(token string) (*appleToken, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidTokenFormat
	}
	//header
	var apToken = &appleToken{
		headerStr: parts[0],
		claimsStr: parts[1],
		sign:      parts[2],
	}
	var headerBytes []byte
	var err error
	if headerBytes, err = decodeSegment(parts[0]); err != nil {
		return nil, err
	}
	if err = json.Unmarshal(headerBytes, &apToken.header); err != nil {
		return nil, err
	}

	//claims
	var claimBytes []byte
	if claimBytes, err = decodeSegment(parts[1]); err != nil {
		return nil, err
	}
	if err = json.Unmarshal(claimBytes, &apToken.claims); err != nil {
		return nil, err
	}
	return apToken, nil
}

func fetchKeysFromApple(kid string) (*appleKey, error) {
	rsp, err := http.Get("https://appleid.apple.com/auth/keys")
	if err != nil {
		return nil, err
	}
	defer rsp.Body.Close()

	if rsp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching keys from apple server fail: %d", rsp.StatusCode)
	}

	data, err := ioutil.ReadAll(rsp.Body)
	if err != nil {
		return nil, err
	}

	type Keys struct {
		Keys []*appleKey `json:"keys"`
	}

	var ks *Keys
	var result *appleKey
	if err = json.Unmarshal(data, &ks); err != nil {
		return nil, err
	}
	for _, k := range ks.Keys {
		if k == nil {
			continue
		}
		if k.Kid == kid {
			result = k
			break
		}
	}
	return result, nil
}

func generatePubKey(nStr, eStr string) (*rsa.PublicKey, error) {
	nBytes, err := decodeBase64String(nStr)
	if err != nil {
		return nil, err
	}
	eBytes, err := decodeBase64String(eStr)
	if err != nil {
		return nil, err
	}

	n := &big.Int{}
	n.SetBytes(nBytes)
	e := &big.Int{}
	e.SetBytes(eBytes)

	var pub = rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}
	return &pub, nil
}
