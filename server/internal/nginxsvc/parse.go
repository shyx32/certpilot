package nginxsvc

import (
	"bufio"
	"strings"
)

// ServerBlock 是从 nginx 配置里提取出的一个 server 块的关键信息。
type ServerBlock struct {
	// Names 是 server_name 指令列出的域名（已去掉 _ 与通配前缀之外的噪音）。
	Names []string
	// CertPath / KeyPath 是该块使用的证书路径（容器内视角）。
	CertPath string
	KeyPath  string
	// TLS 表示该块监听了 TLS 端口。
	TLS bool
}

// ParseServers 从 `nginx -T` 的输出里提取所有 server 块。
//
// 这不是完整的 nginx 配置解析器，也不需要是：目的只是回答
// 「这台机器上哪些域名用了哪些证书文件」。因此只跟踪花括号深度，
// 识别 server_name / ssl_certificate / ssl_certificate_key / listen 四条指令，
// 其余一律忽略。遇到看不懂的配置最坏结果是少发现几个 server 块，
// 而不是给出错误答案。
func ParseServers(dump string) []ServerBlock {
	var (
		out      []ServerBlock
		cur      *ServerBlock
		depth    int
		curDepth int
		// http 块级别的证书指令会被 server 块继承，作为兜底。
		httpCert, httpKey string
	)

	sc := bufio.NewScanner(strings.NewReader(dump))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	for sc.Scan() {
		line := stripComment(sc.Text())
		if line == "" {
			continue
		}

		// 指令可能与花括号同行，逐段处理。
		for _, tok := range splitTokens(line) {
			switch {
			case tok == "{":
				depth++
			case tok == "}":
				if cur != nil && depth == curDepth {
					finish(&out, cur, httpCert, httpKey)
					cur = nil
				}
				if depth > 0 {
					depth--
				}
			case strings.HasPrefix(tok, "server") && isBlockStart(tok):
				// server 块开始；深度在下一个 "{" 里 +1
				cur = &ServerBlock{}
				curDepth = depth + 1
			default:
				applyDirective(tok, cur, &httpCert, &httpKey)
			}
		}
	}
	if cur != nil {
		finish(&out, cur, httpCert, httpKey)
	}
	return out
}

func finish(out *[]ServerBlock, b *ServerBlock, httpCert, httpKey string) {
	if b.CertPath == "" {
		b.CertPath = httpCert
	}
	if b.KeyPath == "" {
		b.KeyPath = httpKey
	}
	// 没有证书的 server 块（纯 80 端口跳转）对我们没有价值。
	if b.CertPath == "" || len(b.Names) == 0 {
		return
	}
	*out = append(*out, *b)
}

func applyDirective(tok string, cur *ServerBlock, httpCert, httpKey *string) {
	fields := strings.Fields(strings.TrimSuffix(tok, ";"))
	if len(fields) < 2 {
		return
	}
	switch fields[0] {
	case "server_name":
		if cur == nil {
			return
		}
		for _, n := range fields[1:] {
			// "_" 是 nginx 的通配默认站点，不是真实域名。
			if n == "_" || n == "" {
				continue
			}
			cur.Names = append(cur.Names, strings.TrimSuffix(n, "."))
		}
	case "ssl_certificate":
		if cur != nil {
			cur.CertPath = unquote(fields[1])
		} else {
			*httpCert = unquote(fields[1])
		}
	case "ssl_certificate_key":
		if cur != nil {
			cur.KeyPath = unquote(fields[1])
		} else {
			*httpKey = unquote(fields[1])
		}
	case "listen":
		if cur == nil {
			return
		}
		for _, f := range fields[1:] {
			if f == "ssl" || strings.HasSuffix(f, ":443") || f == "443" {
				cur.TLS = true
			}
		}
	}
}

// isBlockStart 判断这是不是 "server" 块的起始，而不是 "server_name" 之类的指令。
func isBlockStart(tok string) bool {
	f := strings.Fields(tok)
	return len(f) == 1 && f[0] == "server"
}

// splitTokens 把一行拆成指令与花括号。
func splitTokens(line string) []string {
	var out []string
	var buf strings.Builder
	flush := func() {
		if t := strings.TrimSpace(buf.String()); t != "" {
			out = append(out, t)
		}
		buf.Reset()
	}
	for _, r := range line {
		switch r {
		case '{', '}':
			flush()
			out = append(out, string(r))
		case ';':
			buf.WriteRune(r)
			flush()
		default:
			buf.WriteRune(r)
		}
	}
	flush()
	return out
}

func stripComment(s string) string {
	if i := strings.IndexByte(s, '#'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

func unquote(s string) string {
	return strings.Trim(s, `"'`)
}

// CertUsage 汇总一份配置里「哪些证书文件服务了哪些域名」。
type CertUsage struct {
	CertPath string
	KeyPath  string
	Domains  []string
}

// GroupByCert 把 server 块按证书文件归并，用于接入时的批量导入。
//
// 多个 server 块共用一张证书是常态（主站与其重定向站点），
// 归并后用户看到的是「这 1 张证书覆盖这 5 个域名」，而不是 5 行重复项。
func GroupByCert(blocks []ServerBlock) []CertUsage {
	order := []string{}
	byCert := map[string]*CertUsage{}
	for _, b := range blocks {
		u, ok := byCert[b.CertPath]
		if !ok {
			u = &CertUsage{CertPath: b.CertPath, KeyPath: b.KeyPath}
			byCert[b.CertPath] = u
			order = append(order, b.CertPath)
		}
		if u.KeyPath == "" {
			u.KeyPath = b.KeyPath
		}
		for _, n := range b.Names {
			if !contains(u.Domains, n) {
				u.Domains = append(u.Domains, n)
			}
		}
	}
	out := make([]CertUsage, 0, len(order))
	for _, k := range order {
		out = append(out, *byCert[k])
	}
	return out
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
