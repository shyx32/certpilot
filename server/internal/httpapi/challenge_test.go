package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

func serveToken(t *testing.T, s *ChallengeStore, token string) *httptest.ResponseRecorder {
	t.Helper()
	r := chi.NewRouter()
	r.Get("/.well-known/acme-challenge/{token}", s.serve)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/acme-challenge/"+token, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestChallengeServesRegisteredToken(t *testing.T) {
	s := NewChallengeStore()
	s.Present("tok123", "tok123.keyauthorization")

	w := serveToken(t, s, "tok123")
	if w.Code != http.StatusOK {
		t.Fatalf("状态码 %d，期望 200", w.Code)
	}
	if got := w.Body.String(); got != "tok123.keyauthorization" {
		t.Fatalf("响应体 %q 与登记的 keyAuth 不符", got)
	}
	// CA 是明文 HTTP 来取，内容类型必须是纯文本。
	if ct := w.Header().Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Errorf("Content-Type = %q", ct)
	}
}

func TestChallengeUnknownTokenIs404(t *testing.T) {
	s := NewChallengeStore()
	if w := serveToken(t, s, "nope"); w.Code != http.StatusNotFound {
		t.Fatalf("未登记的 token 应返回 404，实得 %d", w.Code)
	}
}

// 验证结束后必须清理，否则内存里会堆积无用条目。
func TestChallengeCleanUp(t *testing.T) {
	s := NewChallengeStore()
	s.Present("tok", "auth")
	if s.Count() != 1 {
		t.Fatalf("登记后应有 1 个 token，实得 %d", s.Count())
	}
	s.CleanUp("tok")
	if s.Count() != 0 {
		t.Fatalf("清理后应为 0，实得 %d", s.Count())
	}
	if w := serveToken(t, s, "tok"); w.Code != http.StatusNotFound {
		t.Errorf("清理后仍能取到，状态码 %d", w.Code)
	}
}

// 并发登记与应答不能出现数据竞争（配合 -race 运行）。
func TestChallengeConcurrent(t *testing.T) {
	s := NewChallengeStore()
	done := make(chan struct{})
	go func() {
		for i := 0; i < 200; i++ {
			s.Present("tok", "auth")
			s.CleanUp("tok")
		}
		close(done)
	}()
	for i := 0; i < 200; i++ {
		serveToken(t, s, "tok")
	}
	<-done
}
