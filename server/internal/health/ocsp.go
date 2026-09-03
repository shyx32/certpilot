package health

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"io"
	"net/http"

	"golang.org/x/crypto/ocsp"
)

// checkOCSP 向 CA 查询证书是否已被吊销。
//
// 用于捕捉 CA 侧的批量吊销事故——那种情况下证书还在有效期内，
// 却已经不被信任，只有主动查询才能发现。
func checkOCSP(ctx context.Context, leaf, issuer *x509.Certificate) (bool, error) {
	if len(leaf.OCSPServer) == 0 {
		return false, errors.New("证书未提供 OCSP 地址")
	}
	req, err := ocsp.CreateRequest(leaf, issuer, &ocsp.RequestOptions{Hash: crypto.SHA1})
	if err != nil {
		return false, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		leaf.OCSPServer[0], bytes.NewReader(req))
	if err != nil {
		return false, err
	}
	httpReq.Header.Set("Content-Type", "application/ocsp-request")

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	// 限制读取量：OCSP 响应很小，异常大的响应不值得信任。
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return false, err
	}
	parsed, err := ocsp.ParseResponseForCert(body, leaf, issuer)
	if err != nil {
		return false, err
	}
	return parsed.Status == ocsp.Revoked, nil
}
