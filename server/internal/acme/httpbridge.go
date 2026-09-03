package acme

// HTTPChallenge 是 HTTP-01 验证的应答端。
//
// 由 httpapi.ChallengeStore 实现：CA 来取 /.well-known/acme-challenge/<token>
// 时由本服务直接应答。配合业务服务器上一次性配置的重定向
//
//	location ^~ /.well-known/acme-challenge/ { return 301 http://acme.example.com$request_uri; }
//
// 续期路径上就不再需要登录目标机器投放文件——ACME 规范允许验证过程中
// 跟随 HTTP 重定向，这正是集中验证成立的依据。
type HTTPChallenge interface {
	Present(token, keyAuth string)
	CleanUp(token string)
}

// httpBridge 把 HTTPChallenge 适配成 lego 的 challenge.Provider。
type httpBridge struct {
	store    HTTPChallenge
	onRecord func(domain, token string)
}

func (b *httpBridge) Present(domain, token, keyAuth string) error {
	b.store.Present(token, keyAuth)
	if b.onRecord != nil {
		b.onRecord(domain, token)
	}
	return nil
}

func (b *httpBridge) CleanUp(_, token, _ string) error {
	// 无论验证成功与否都要清理，避免无用 token 长期驻留内存。
	b.store.CleanUp(token)
	return nil
}
