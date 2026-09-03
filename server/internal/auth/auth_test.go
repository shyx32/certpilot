package auth

import (
	"testing"
	"time"
)

func TestPasswordHashing(t *testing.T) {
	h, err := HashPassword("a-sufficiently-long-password")
	if err != nil {
		t.Fatal(err)
	}
	if h == "a-sufficiently-long-password" {
		t.Fatal("密码没有被哈希")
	}
	if !VerifyPassword(h, "a-sufficiently-long-password") {
		t.Error("正确密码校验失败")
	}
	if VerifyPassword(h, "wrong-password-here") {
		t.Error("错误密码通过了校验")
	}
}

// 这个后台被攻破意味着全站私钥泄露，不能接受弱口令。
func TestRejectsShortPassword(t *testing.T) {
	if _, err := HashPassword("short"); err != ErrWeakPassword {
		t.Fatalf("短密码应被拒绝，实得 %v", err)
	}
}

func TestSessionLifecycle(t *testing.T) {
	s := NewSessions(time.Hour)
	tok, err := s.Create(1, "admin", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if len(tok) < 32 {
		t.Errorf("会话 token 太短，可能被猜到: %d 字符", len(tok))
	}
	sess, ok := s.Lookup(tok)
	if !ok || sess.Username != "admin" {
		t.Fatal("无法取回刚创建的会话")
	}
	s.Destroy(tok)
	if _, ok := s.Lookup(tok); ok {
		t.Error("销毁后仍能取回会话")
	}
}

func TestExpiredSessionRejected(t *testing.T) {
	s := NewSessions(time.Millisecond)
	tok, _ := s.Create(1, "admin", "admin")
	time.Sleep(10 * time.Millisecond)
	if _, ok := s.Lookup(tok); ok {
		t.Fatal("过期会话仍然有效")
	}
	if s.Count() != 0 {
		t.Error("过期会话没有被顺手清理")
	}
}

func TestLookupEmptyToken(t *testing.T) {
	s := NewSessions(time.Hour)
	if _, ok := s.Lookup(""); ok {
		t.Fatal("空 token 不应通过")
	}
}

// 两次创建必须得到不同 token。
func TestTokensAreUnique(t *testing.T) {
	s := NewSessions(time.Hour)
	a, _ := s.Create(1, "admin", "admin")
	b, _ := s.Create(1, "admin", "admin")
	if a == b {
		t.Fatal("两次登录生成了相同的 token")
	}
}
