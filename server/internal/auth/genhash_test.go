package auth

import (
	"fmt"
	"os"
	"testing"
)

// TestGenerateHashForOps 是一个运维辅助：给定 CP_HASH_PASSWORD 时
// 打印对应的 bcrypt 哈希，便于手工建用户或重置密码。
//
// 平时跳过，不影响正常测试。
func TestGenerateHashForOps(t *testing.T) {
	pw := os.Getenv("CP_HASH_PASSWORD")
	if pw == "" {
		t.Skip("未设置 CP_HASH_PASSWORD，跳过")
	}
	h, err := HashPassword(pw)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(h)
}
