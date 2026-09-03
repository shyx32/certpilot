package deploy

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"net"
	"strconv"
	"time"
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

// ProbeFingerprint 与目标握手并取出叶证书指纹。
//
// 各 provider 的 Verify 都需要它，放在这里避免每家重复实现。
// 刻意不做信任校验：这里只关心「线上发的是哪一张」，
// 链是否可信由巡检单独判断。
func ProbeFingerprint(ctx context.Context, host string, port int) (string, error) {
	dialer := &tls.Dialer{Config: &tls.Config{
		ServerName:         host,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
	}}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return "", err
	}
	defer conn.Close()

	state := conn.(*tls.Conn).ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return "", errors.New("对端没有返回证书")
	}
	return Fingerprint(state.PeerCertificates[0]), nil
}
