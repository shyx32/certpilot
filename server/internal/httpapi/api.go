package httpapi

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/certpilot/server/internal/auth"
	"github.com/certpilot/server/internal/store"
	"github.com/go-chi/chi/v5"
)

// API 持有各 handler 的共享依赖。
type API struct {
	store    *store.Store
	sessions *auth.Sessions
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	if v != nil {
		if err := json.NewEncoder(w).Encode(v); err != nil {
			slog.Error("写出响应失败", "err", err)
		}
	}
}

// fail 输出统一的错误结构。错误信息面向使用者，说明发生了什么、怎么办，
// 而不是把内部异常原样抛出去。
func fail(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// failErr 把 store 的错误映射成合适的状态码。
func failErr(w http.ResponseWriter, err error, fallback string) {
	if errors.Is(err, store.ErrNotFound) {
		fail(w, http.StatusNotFound, "记录不存在")
		return
	}
	slog.Error(fallback, "err", err)
	fail(w, http.StatusInternalServerError, fallback)
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	// 限制请求体大小，避免一个畸形请求吃光内存。
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		fail(w, http.StatusBadRequest, "请求内容无法解析: "+err.Error())
		return false
	}
	return true
}

// pathID 读取路径中的数字 ID。
func pathID(w http.ResponseWriter, r *http.Request, name string) (int64, bool) {
	raw := chi.URLParam(r, name)
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 {
		fail(w, http.StatusBadRequest, "路径参数 "+name+" 不是合法 ID")
		return 0, false
	}
	return id, true
}

func queryInt(r *http.Request, name string, def int) int {
	v := r.URL.Query().Get(name)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	return n
}

// chiURLParam 便于在非 handler 结构体上取路径参数。
func chiURLParam(r *http.Request, name string) string {
	return chi.URLParam(r, name)
}

// parseID 解析查询参数里的数字 ID。
func parseID(v string) (int64, bool) {
	id, err := strconv.ParseInt(v, 10, 64)
	if err != nil || id <= 0 {
		return 0, false
	}
	return id, true
}
