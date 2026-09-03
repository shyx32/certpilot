// Package acme 封装 ACME 客户端与签发流程。
package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/registration"
)

// User 实现 lego 的 registration.User。
type User struct {
	Email        string
	Registration *registration.Resource
	Key          crypto.PrivateKey
}

func (u *User) GetEmail() string                        { return u.Email }
func (u *User) GetRegistration() *registration.Resource { return u.Registration }
func (u *User) GetPrivateKey() crypto.PrivateKey        { return u.Key }

// GenerateAccountKey 生成一把新的 ACME 账号私钥并返回 PEM。
//
// 账号私钥注册后无法再取回，丢失等于该 CA 账号作废，
// 因此它和证书私钥一样进凭据箱加密保存。
func GenerateAccountKey() ([]byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}

// ParseAccountKey 从 PEM 还原账号私钥。
func ParseAccountKey(pemBytes []byte) (crypto.PrivateKey, error) {
	blk, _ := pem.Decode(pemBytes)
	if blk == nil {
		return nil, errors.New("acme: 账号私钥不是合法 PEM")
	}
	switch blk.Type {
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(blk.Bytes)
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(blk.Bytes)
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(blk.Bytes)
	default:
		return nil, fmt.Errorf("acme: 不支持的私钥类型 %q", blk.Type)
	}
}

// KeyType 把配置里的字符串映射为 lego 的密钥类型。
//
// 默认 EC256：更短更快，且当代客户端普遍支持。对兼容性敏感的域名
// 可以显式选 RSA2048。
func KeyType(s string) certcrypto.KeyType {
	switch s {
	case "RSA2048":
		return certcrypto.RSA2048
	case "RSA4096":
		return certcrypto.RSA4096
	case "EC384":
		return certcrypto.EC384
	default:
		return certcrypto.EC256
	}
}
