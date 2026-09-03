package dnsx

import (
	"errors"
	"testing"
)

var zones = []Zone{
	{Name: "example.com", CredentialID: 1},
	{Name: "b.example.com", CredentialID: 2},
	{Name: "other.com", CredentialID: 3},
}

func TestResolveZone(t *testing.T) {
	cases := []struct {
		name       string
		domain     string
		wantZone   string
		wantCred   int64
		wantRecord string
	}{
		{"顶级域", "example.com", "example.com", 1, "_acme-challenge"},
		{"一级子域", "www.example.com", "example.com", 1, "_acme-challenge.www"},
		{"更精确的 zone 优先", "a.b.example.com", "b.example.com", 2, "_acme-challenge.a"},
		{"精确 zone 自身", "b.example.com", "b.example.com", 2, "_acme-challenge"},
		{"通配符落到 zone 顶点", "*.example.com", "example.com", 1, "_acme-challenge"},
		{"子域通配符", "*.a.example.com", "example.com", 1, "_acme-challenge.a"},
		{"大写与尾点", "WWW.Example.Com.", "example.com", 1, "_acme-challenge.www"},
		{"深层子域", "x.y.z.example.com", "example.com", 1, "_acme-challenge.x.y.z"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m, err := ResolveZone(c.domain, zones)
			if err != nil {
				t.Fatal(err)
			}
			if m.Zone.Name != c.wantZone {
				t.Errorf("zone = %q, 期望 %q", m.Zone.Name, c.wantZone)
			}
			if m.Zone.CredentialID != c.wantCred {
				t.Errorf("凭据 = %d, 期望 %d", m.Zone.CredentialID, c.wantCred)
			}
			if m.RecordName != c.wantRecord {
				t.Errorf("主机记录 = %q, 期望 %q", m.RecordName, c.wantRecord)
			}
			if want := c.wantRecord + "." + c.wantZone; m.FQDN != want {
				t.Errorf("FQDN = %q, 期望 %q", m.FQDN, want)
			}
		})
	}
}

func TestResolveZoneNoMatch(t *testing.T) {
	if _, err := ResolveZone("nope.net", zones); !errors.Is(err, ErrNoZone) {
		t.Fatalf("期望 ErrNoZone, 得到 %v", err)
	}
}

// 后缀相同但不是子域的情况不能误判：notexample.com 不属于 example.com。
func TestResolveZoneRejectsSuffixLookalike(t *testing.T) {
	if _, err := ResolveZone("notexample.com", zones); !errors.Is(err, ErrNoZone) {
		t.Fatalf("notexample.com 不应命中 example.com, 得到 %v", err)
	}
}

func TestResolveZoneAmbiguous(t *testing.T) {
	dup := []Zone{{Name: "example.com", CredentialID: 1}, {Name: "example.com", CredentialID: 9}}
	if _, err := ResolveZone("www.example.com", dup); !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("期望 ErrAmbiguous, 得到 %v", err)
	}
}

func TestResolveZoneBadInput(t *testing.T) {
	for _, d := range []string{"", "localhost", "..", "a..b.com", "*", "*.*.com"} {
		if _, err := ResolveZone(d, zones); err == nil {
			t.Errorf("域名 %q 应当被拒绝", d)
		}
	}
}

// 一张 SAN 证书里 example.com 与 *.example.com 共用同一条 TXT，必须去重，
// 否则会对同一记录发起两次写入与两次清理。
func TestResolveAllDeduplicates(t *testing.T) {
	got, err := ResolveAll([]string{"example.com", "*.example.com"}, zones)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("期望去重成 1 条, 得到 %d 条", len(got))
	}
}

func TestResolveAllSpansCredentials(t *testing.T) {
	got, err := ResolveAll([]string{"www.example.com", "a.b.example.com", "other.com"}, zones)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("期望 3 条, 得到 %d", len(got))
	}
	creds := map[int64]bool{}
	for _, m := range got {
		creds[m.Zone.CredentialID] = true
	}
	if len(creds) != 3 {
		t.Fatalf("三个域名应分属 3 个凭据, 实得 %d", len(creds))
	}
}

// 失败时必须指出是哪个域名，界面才能高亮那一行。
func TestResolveAllReportsOffendingDomain(t *testing.T) {
	_, err := ResolveAll([]string{"www.example.com", "nope.net"}, zones)
	var de *DomainError
	if !errors.As(err, &de) || de.Domain != "nope.net" {
		t.Fatalf("期望指明 nope.net, 得到 %v", err)
	}
}
