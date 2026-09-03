package domain

import "testing"

func TestStageAdvancesToVerified(t *testing.T) {
	s := StagePending
	steps := 0
	for {
		next, ok := s.Next()
		if !ok {
			break
		}
		s = next
		if steps++; steps > 20 {
			t.Fatal("状态机没有收敛，可能存在环")
		}
	}
	if s != StageVerified {
		t.Fatalf("终点应是 %q，实际是 %q", StageVerified, s)
	}
}

// 部署完成不是终点——签发成功不等于线上生效。
func TestIssuedIsNotTerminal(t *testing.T) {
	if StageIssued.Terminal() {
		t.Fatal("issued 不应是终态，必须走到 verified")
	}
	if !StageVerified.Terminal() || !StageFailed.Terminal() {
		t.Fatal("verified 与 failed 应是终态")
	}
}

func TestStageValid(t *testing.T) {
	if !StageFailed.Valid() || !StageChallenge.Valid() {
		t.Fatal("已知状态被判为无效")
	}
	if Stage("bogus").Valid() {
		t.Fatal("未知状态被判为有效")
	}
}
