// Package sshx 提供 SSH 连接、命令执行与文件传输。
package sshx

import (
	"errors"
	"strings"
)

// ErrEmptyArgv 表示命令为空。
var ErrEmptyArgv = errors.New("sshx: 命令不能为空")

// Quote 把一个参数包成 shell 安全的形式。
//
// SSH 的 exec 请求本质上是把一整个字符串交给远端登录 shell 执行，
// 没有 execve 那样的「参数即数据」保证。因此要真正做到用户填的内容
// 只是参数而不会变成代码，必须在这一层做严格转义。
//
// 用单引号包裹是最保险的做法：单引号内 shell 不做任何展开，
// 唯一需要处理的是内容里的单引号本身——用 '\” 的方式闭合再拼接。
func Quote(s string) string {
	if s == "" {
		return "''"
	}
	// 只含安全字符时不加引号，命令行更可读，行为完全一致。
	if isPlain(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func isPlain(s string) bool {
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-', r == '_', r == '.', r == '/', r == ':', r == '=', r == '@', r == ',', r == '+':
		default:
			return false
		}
	}
	return true
}

// BuildCommand 把 argv 拼成一条可安全交给远端 shell 的命令行。
//
// 调用方永远传数组，不传拼好的字符串——这是「用户填的是参数，不是代码」
// 这一约束在实现上的落点。
func BuildCommand(argv []string) (string, error) {
	if len(argv) == 0 {
		return "", ErrEmptyArgv
	}
	parts := make([]string, len(argv))
	for i, a := range argv {
		parts[i] = Quote(a)
	}
	return strings.Join(parts, " "), nil
}

// WithSudo 在 argv 前加上非交互 sudo。
//
// -n 让 sudo 在需要密码时直接失败，而不是挂起等待输入——
// 一个永远等不到输入的 SSH 会话会一直占着连接。
func WithSudo(argv []string) []string {
	return append([]string{"sudo", "-n"}, argv...)
}

// ExpandArgv 把 argv 里的占位符替换成实际值。
//
// 占位符限定在白名单内，且替换后的值只作为参数出现，
// 因此即使值里含有 shell 元字符也不会被解释。
func ExpandArgv(argv []string, vars map[string]string) []string {
	out := make([]string, len(argv))
	for i, a := range argv {
		for k, v := range vars {
			a = strings.ReplaceAll(a, "{"+k+"}", v)
		}
		out[i] = a
	}
	return out
}
