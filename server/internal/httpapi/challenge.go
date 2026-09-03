package httpapi

import (
	"net/http"
	"sync"
)

// ChallengeStore 应答 HTTP-01 验证。
//
// 配合集中验证模式使用：业务服务器上一次性配置
//
//	location ^~ /.well-known/acme-challenge/ { return 301 http://acme.example.com$request_uri; }
//
// 之后所有域名的验证都由这里应答，续期路径上不再需要 SSH 登录目标机器。
// ACME 规范允许验证过程中跟随重定向，这正是该模式成立的依据。
type ChallengeStore struct {
	mu     sync.RWMutex
	tokens map[string]string
}

func NewChallengeStore() *ChallengeStore {
	return &ChallengeStore{tokens: make(map[string]string)}
}

// Present 登记一个待应答的 token。
func (s *ChallengeStore) Present(token, keyAuth string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[token] = keyAuth
}

// CleanUp 注销 token。验证成功与否都要调用，避免无用条目长期驻留。
func (s *ChallengeStore) CleanUp(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tokens, token)
}

// Count 返回当前待应答的 token 数，供健康检查与调试。
func (s *ChallengeStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.tokens)
}

func (s *ChallengeStore) serve(w http.ResponseWriter, r *http.Request) {
	token := chiURLParam(r, "token")
	s.mu.RLock()
	keyAuth, ok := s.tokens[token]
	s.mu.RUnlock()

	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(keyAuth))
}
