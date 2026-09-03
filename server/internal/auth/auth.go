// Package auth 提供登录与会话。
//
// 这个系统集中持有全站证书私钥与多个云账号密钥，本身就是最高价值的攻击目标，
// 因此接口默认全部需要认证，没有「内网所以不设防」的例外。
package auth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

var (
	ErrBadCredentials = errors.New("用户名或密码不正确")
	ErrWeakPassword   = errors.New("密码至少需要 12 个字符")
)

// MinPasswordLen 是最短密码长度。
//
// 这个后台一旦被攻破，攻击者拿到的是全站私钥，
// 因此不接受 6 位弱口令。
const MinPasswordLen = 12

// HashPassword 用 bcrypt 生成密码哈希。
func HashPassword(pw string) (string, error) {
	if len([]rune(pw)) < MinPasswordLen {
		return "", ErrWeakPassword
	}
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	return string(h), err
}

// VerifyPassword 校验密码。
func VerifyPassword(hash, pw string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
}

// Session 是一次登录。
type Session struct {
	UserID    int64
	Username  string
	Role      string
	ExpiresAt time.Time
}

// Sessions 是进程内的会话表。
//
// 重启后所有人需要重新登录——对一个每天只被人访问几次的运维后台来说，
// 这个代价远小于引入外部会话存储的复杂度。
type Sessions struct {
	mu   sync.RWMutex
	byID map[string]*Session
	ttl  time.Duration
}

func NewSessions(ttl time.Duration) *Sessions {
	if ttl <= 0 {
		ttl = 12 * time.Hour
	}
	return &Sessions{byID: make(map[string]*Session), ttl: ttl}
}

// Create 生成一个新会话，返回不可猜测的 token。
func (s *Sessions) Create(userID int64, username, role string) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.byID[token] = &Session{
		UserID: userID, Username: username, Role: role,
		ExpiresAt: time.Now().Add(s.ttl),
	}
	return token, nil
}

// Lookup 取回会话，过期的当作不存在并顺手清理。
func (s *Sessions) Lookup(token string) (*Session, bool) {
	if token == "" {
		return nil, false
	}
	s.mu.RLock()
	sess, ok := s.byID[token]
	s.mu.RUnlock()
	if !ok {
		return nil, false
	}
	if time.Now().After(sess.ExpiresAt) {
		s.Destroy(token)
		return nil, false
	}
	return sess, true
}

func (s *Sessions) Destroy(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.byID, token)
}

// Count 返回当前活跃会话数。
func (s *Sessions) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byID)
}

// Cleanup 定期清除过期会话，避免内存里堆积无用条目。
func (s *Sessions) Cleanup() {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.byID {
		if now.After(v.ExpiresAt) {
			delete(s.byID, k)
		}
	}
}

// GeneratePassword 生成初始管理员密码。
func GeneratePassword() (string, error) {
	raw := make([]byte, 18)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
