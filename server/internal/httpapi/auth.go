package httpapi

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/certpilot/server/internal/auth"
)

const sessionCookie = "cp_session"

type ctxKey int

const sessionKey ctxKey = 0

// sessionFrom 取出当前请求的会话，供 handler 记录审计日志。
func sessionFrom(r *http.Request) *auth.Session {
	s, _ := r.Context().Value(sessionKey).(*auth.Session)
	return s
}

func actorOf(r *http.Request) string {
	if s := sessionFrom(r); s != nil {
		return s.Username
	}
	return "anonymous"
}

// requireAuth 保护所有需要登录的接口。
func (a *API) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil {
			fail(w, http.StatusUnauthorized, "请先登录")
			return
		}
		sess, ok := a.sessions.Lookup(c.Value)
		if !ok {
			fail(w, http.StatusUnauthorized, "登录已过期，请重新登录")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), sessionKey, sess)))
	})
}

// requireAdmin 保护会放大权限的操作：管理凭据、创建 RAM 子账号等。
func (a *API) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s := sessionFrom(r); s == nil || s.Role != "admin" {
			fail(w, http.StatusForbidden, "该操作需要管理员权限")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *API) login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decode(w, r, &req) {
		return
	}

	u, err := a.store.UserByName(r.Context(), req.Username)
	// 用户不存在与密码错误返回同一条消息，避免暴露哪些用户名有效。
	if err != nil || u.Disabled || !auth.VerifyPassword(u.PasswordHash, req.Password) {
		slog.Warn("登录失败", "username", req.Username, "ip", r.RemoteAddr)
		fail(w, http.StatusUnauthorized, "用户名或密码不正确")
		return
	}

	token, err := a.sessions.Create(u.ID, u.Username, u.Role)
	if err != nil {
		failErr(w, err, "创建会话失败")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true, // 阻止脚本读取，降低 XSS 的影响面
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
		MaxAge:   int(12 * time.Hour / time.Second),
	})
	a.store.Audit(r.Context(), u.Username, "login", "", nil)
	writeJSON(w, http.StatusOK, map[string]any{
		"username": u.Username, "role": u.Role,
	})
}

func (a *API) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		a.sessions.Destroy(c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", HttpOnly: true, MaxAge: -1,
	})
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) me(w http.ResponseWriter, r *http.Request) {
	s := sessionFrom(r)
	if s == nil {
		fail(w, http.StatusUnauthorized, "请先登录")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"username": s.Username, "role": s.Role})
}

// changePassword 让首次登录的管理员尽快替换掉初始密码。
func (a *API) changePassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if !decode(w, r, &req) {
		return
	}
	s := sessionFrom(r)
	u, err := a.store.UserByName(r.Context(), s.Username)
	if err != nil {
		failErr(w, err, "读取用户失败")
		return
	}
	if !auth.VerifyPassword(u.PasswordHash, req.OldPassword) {
		fail(w, http.StatusForbidden, "当前密码不正确")
		return
	}
	hash, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := a.store.SetPassword(r.Context(), u.ID, hash); err != nil {
		failErr(w, err, "更新密码失败")
		return
	}
	a.store.Audit(r.Context(), u.Username, "change_password", "", nil)
	w.WriteHeader(http.StatusNoContent)
}
