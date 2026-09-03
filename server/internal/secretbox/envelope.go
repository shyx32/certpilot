// Package secretbox 实现凭据与私钥的信封加密。
//
// 每条记录用一把独立的数据密钥（DEK）加密，DEK 本身再由主密钥（KEK）加密后
// 与密文一同存放。主密钥永不入库——拿到数据库全量备份也解不开任何一条记录。
package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
)

const (
	keyLen   = 32 // AES-256
	nonceLen = 12 // GCM 标准 nonce
)

var (
	ErrBadMasterKey = errors.New("secretbox: 主密钥必须是 32 字节（base64 编码）")
	ErrMalformed    = errors.New("secretbox: 密文格式不合法")
)

// Box 持有主密钥，进程内唯一。
type Box struct {
	kek cipher.AEAD
}

// New 从 base64 编码的 32 字节主密钥构造 Box。
func New(masterKeyB64 string) (*Box, error) {
	raw, err := base64.StdEncoding.DecodeString(masterKeyB64)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadMasterKey, err)
	}
	if len(raw) != keyLen {
		return nil, ErrBadMasterKey
	}
	aead, err := newAEAD(raw)
	if err != nil {
		return nil, err
	}
	return &Box{kek: aead}, nil
}

// GenerateMasterKey 生成一把新的主密钥，供首次部署时写入配置。
func GenerateMasterKey() (string, error) {
	k := make([]byte, keyLen)
	if _, err := rand.Read(k); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(k), nil
}

// Sealed 是可以安全落库的密文信封。
type Sealed struct {
	// WrappedDEK 是被主密钥加密后的数据密钥。
	WrappedDEK []byte `json:"dek"`
	// Ciphertext 是被数据密钥加密后的明文。
	Ciphertext []byte `json:"ct"`
}

// Seal 用一把新生成的 DEK 加密 plaintext，并用主密钥包裹该 DEK。
//
// aad 是附加认证数据，不会被加密但会参与完整性校验。传入记录标识
// （例如 "credential:42"）可以防止密文被整体搬到另一条记录上复用。
func (b *Box) Seal(plaintext, aad []byte) (*Sealed, error) {
	dek := make([]byte, keyLen)
	if _, err := rand.Read(dek); err != nil {
		return nil, err
	}
	defer zero(dek)

	dekAEAD, err := newAEAD(dek)
	if err != nil {
		return nil, err
	}
	ct, err := sealWith(dekAEAD, plaintext, aad)
	if err != nil {
		return nil, err
	}
	wrapped, err := sealWith(b.kek, dek, aad)
	if err != nil {
		return nil, err
	}
	return &Sealed{WrappedDEK: wrapped, Ciphertext: ct}, nil
}

// Open 还原明文。aad 必须与 Seal 时完全一致。
func (b *Box) Open(s *Sealed, aad []byte) ([]byte, error) {
	if s == nil || len(s.WrappedDEK) == 0 || len(s.Ciphertext) == 0 {
		return nil, ErrMalformed
	}
	dek, err := openWith(b.kek, s.WrappedDEK, aad)
	if err != nil {
		return nil, fmt.Errorf("解开数据密钥失败: %w", err)
	}
	defer zero(dek)

	dekAEAD, err := newAEAD(dek)
	if err != nil {
		return nil, err
	}
	return openWith(dekAEAD, s.Ciphertext, aad)
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// sealWith 输出 nonce ‖ ciphertext。
func sealWith(a cipher.AEAD, plaintext, aad []byte) ([]byte, error) {
	nonce := make([]byte, a.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return a.Seal(nonce, nonce, plaintext, aad), nil
}

func openWith(a cipher.AEAD, blob, aad []byte) ([]byte, error) {
	n := a.NonceSize()
	if len(blob) < n {
		return nil, ErrMalformed
	}
	return a.Open(nil, blob[:n], blob[n:], aad)
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
