package main

import "errors"

var (
	clientId = "com.Radacat.RadacatComTracker"  // APP对应的开发者账户Id
	iss = "https://appleid.apple.com"           // 签发者，固定值
)

var (
	ErrInvalidHashType      = errors.New("invalid hash type")
	ErrInvalidTokenFormat   = errors.New("invalid token format")
	ErrFetchKeysFail        = errors.New("invalid rsa public key")
	ErrInvalidIdentityToken = errors.New("token 为空")
	ErrTokenAlreadyExpired  = errors.New("token already expired")
	ErrDeveloperAccountInfo = errors.New("wrong developer account information")
)

type Keys struct {
	Keys []*AppleKey `json:"keys"`
}

type AppleKey struct {
	Kid string `json:"kid"` //公钥ID
	Alg string `json:"alg"` //签名算法
	Kty string `json:"kty"` //加密算法
	E   string `json:"e"`   //RSA公钥指数值
	N   string `json:"n"`   //RSA公钥模数值
	Use string `json:"use"` //
}

type AppleHeader struct {
	Kid string `json:"kid"` //apple公钥的密钥ID
	Alg string `json:"alg"` //签名token的算法
}

type ApplePayload struct {
	Iss            string `json:"iss"`              //签发者，固定值: https://appleid.apple.com
	Aud            string `json:"aud"`              //App ID
	Exp            int64  `json:"exp"`              //token过期时间
	Iat            int64  `json:"iat"`              //token生成时间
	Sub            string `json:"sub"`              //用户唯一标识
//	Nonce          string `json:"nonce"`            //客户端设置的随机值
	CHash          string `json:"c_hash"`           //
	Email          string `json:"email"`            //邮件
	EmailVerified  string `json:"email_verified"`   // 服务是否已验证电子邮件，始终为true
	AuthTime       int64  `json:"auth_time"`        //验证时间
	NonceSupported bool   `json:"nonce_supported"`  // 是否支持客户设置随机数
//	IsPrivateEmail string `json:"is_private_email"` // 电子邮件是否为代理地址
//	RealUserStatus int    `json:"real_user_status"` // 判断用户是否为真实的人（三种状态，0:unsupported;1:unknown;2:likelyReal）
}

type AppleToken struct {
	header    *AppleHeader //header
	headerStr string
	payload    *ApplePayload //payload
	payloadStr string
	sign      string //签名
}
