package deploy

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
)

// ErrNoCert 表示 PEM 中没有任何证书块。
var ErrNoCert = errors.New("deploy: PEM 中没有证书")

func parseChain(pemBytes []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := pemBytes
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, ErrNoCert
	}
	return out, nil
}

// Fingerprint 返回证书的 SHA-256 指纹（小写十六进制，无分隔符）。
// 巡检与部署校验都以它作为「线上跑的是哪一版」的判据。
func Fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}
