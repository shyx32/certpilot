package aliyun

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func TestBuildPolicyDNSOnly(t *testing.T) {
	doc, err := BuildPolicy([]Capability{CapDNS}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Statement) != 1 {
		t.Fatalf("只勾 DNS 应只有一条语句，实得 %d", len(doc.Statement))
	}
	// zone 自动扫描依赖 DescribeDomains，漏了它自动识别就用不了。
	if !slices.Contains(doc.Statement[0].Action, "alidns:DescribeDomains") {
		t.Error("DNS 档必须包含 DescribeDomains")
	}
	for _, a := range doc.Statement[0].Action {
		if !strings.HasPrefix(a, "alidns:") {
			t.Errorf("只勾 DNS 却出现了越权 Action: %s", a)
		}
	}
}

// 同一个 Action 被多项能力要求时不能重复出现。
func TestBuildPolicyDeduplicates(t *testing.T) {
	doc, err := BuildPolicy([]Capability{CapCDN, CapSLB}, nil)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	for _, s := range doc.Statement {
		for _, a := range s.Action {
			seen[a]++
		}
	}
	if seen["cas:UploadUserCertificate"] != 1 {
		t.Errorf("cas:UploadUserCertificate 出现 %d 次，应当去重", seen["cas:UploadUserCertificate"])
	}
}

// 收窄 DNS 资源范围只影响 DNS 语句，其余仍为 *。
func TestBuildPolicyNarrowsDNSResource(t *testing.T) {
	res := []string{"acs:alidns:*:*:domain/acme-dv.example.com"}
	doc, err := BuildPolicy([]Capability{CapDNS, CapCDN}, res)
	if err != nil {
		t.Fatal(err)
	}
	var dnsStmt, otherStmt *Statement
	for i := range doc.Statement {
		if strings.HasPrefix(doc.Statement[i].Action[0], "alidns:") {
			dnsStmt = &doc.Statement[i]
		} else {
			otherStmt = &doc.Statement[i]
		}
	}
	if dnsStmt == nil || !slices.Equal(dnsStmt.Resource, res) {
		t.Errorf("DNS 资源未收窄: %+v", dnsStmt)
	}
	if otherStmt == nil || otherStmt.Resource[0] != "*" {
		t.Errorf("非 DNS 语句不应被 DNS 的资源限制影响: %+v", otherStmt)
	}
}

func TestBuildPolicyRejectsEmptyAndUnknown(t *testing.T) {
	if _, err := BuildPolicy(nil, nil); err == nil {
		t.Error("未勾选任何能力时应报错")
	}
	if _, err := BuildPolicy([]Capability{"bogus"}, nil); err == nil {
		t.Error("未知能力应报错")
	}
}

func TestPolicyJSONIsValid(t *testing.T) {
	doc, _ := BuildPolicy([]Capability{CapDNS, CapCDN}, nil)
	s, err := doc.JSON()
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal([]byte(s), &back); err != nil {
		t.Fatalf("生成的策略不是合法 JSON: %v", err)
	}
	if back["Version"] != "1" {
		t.Errorf("Version 应为 \"1\"，实得 %v", back["Version"])
	}
}
