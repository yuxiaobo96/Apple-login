package main

import (
	"crypto"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	log "github.com/cihub/seelog"
	"hash"
	"io/ioutil"
	"math/big"
	"net/http"
	"strings"
	"time"
)

func CheckIdentityToken(token string) (*AppleToken, error) {
	if token == "" {
		return nil, ErrInvalidIdentityToken
	}
	appleToken, err := parseToken(token)
	if err != nil {
		return nil, err
	}
	// 通过Apple的url获得的对应公钥
	publicKey, err := fetchKeysFromApple(appleToken.header.Kid)
	if err != nil {
		return nil, err
	}
	if publicKey == nil {
		return nil, ErrFetchKeysFail
	}
	log.Info("公钥key:", publicKey)
	pubKey, err := generatePubKey(publicKey.N, publicKey.E)
	if err != nil {
		return nil, err
	}
	log.Info("生成公钥:", pubKey)
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

	h.Write([]byte(appleToken.headerStr + "." + appleToken.payloadStr))
	log.Info("appleToken:", appleToken)
	// 验证签名，若为nil，验证成功
	log.Info("verify signature:", rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, h.Sum(nil), sig))
	return appleToken, rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, h.Sum(nil), sig)
}
// 解析Token
func parseToken(token string) (*AppleToken, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidTokenFormat
	}
	//将token分为三部分
	var apToken = &AppleToken{
		headerStr: parts[0],
		payloadStr: parts[1],
		sign:      parts[2],
	}
	log.Infof("Header:%s Payload:%s sign:%s", apToken.headerStr, apToken.payloadStr, apToken.sign)
	var headerBytes []byte
	var err error
	// 将Header转化为字节
	if headerBytes, err = decodeSegment(parts[0]); err != nil {
		return nil, err
	}
	log.Info("headerBytes:", headerBytes)
	// 将字节解码为结构体
	if err = json.Unmarshal(headerBytes, &apToken.header); err != nil {
		return nil, err
	}
	log.Info("apToken.header:", apToken.header)
	//payload
	var payloadBytes []byte
	// 将payLoad转化为字节
	if payloadBytes, err = decodeSegment(parts[1]); err != nil {
		return nil, err
	}
	log.Info("payloadBytes:", payloadBytes)
	// 将字节转化为结构体
	if err = json.Unmarshal(payloadBytes, &apToken.payload); err != nil {
		log.Info("解码错误:", err)
		return nil, err
	}
	// 判断token是否过期
	current := time.Now().Unix()
	if current > apToken.payload.Exp || current < apToken.payload.Iat{
		return nil, ErrTokenAlreadyExpired
	}
	// 判断clientId, iss是否为APP对应的开发者账户信息
	if apToken.payload.Aud != clientId || apToken.payload.Iss != iss{
		return nil, ErrDeveloperAccountInfo
	}

	log.Info("生成时间:%d 过期时间:%d", apToken.payload.Iat, apToken.payload.Exp)
	log.Info("apToken.payload:", apToken.payload)
	return apToken, nil
}

func fetchKeysFromApple(kid string) (*AppleKey, error) {
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

	var ks *Keys
	var result *AppleKey
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
