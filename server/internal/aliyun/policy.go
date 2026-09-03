package aliyun

import (
	"encoding/json"
	"fmt"
	"sort"
)

// Capability 是用户在向导里勾选的一项能力。策略按勾选内容拼装，
// 而不是发一套万能策略。
type Capability string

const (
	CapDNS Capability = "dns" // DNS-01 验证
	CapCDN Capability = "cdn" // CDN 部署（含 CAS 证书托管）
	CapSLB Capability = "slb" // 负载均衡证书绑定
	CapOSS Capability = "oss" // OSS 自定义域名证书
)

// capabilityActions 是每项能力所需的最小 Action 集合。
//
// DescribeDomains 出现在 DNS 档里不是多余的：域名 zone 自动扫描依赖它，
// 没有它就无法做「录入凭据即识别可管理域名」。
var capabilityActions = map[Capability][]string{
	CapDNS: {
		"alidns:AddDomainRecord",
		"alidns:DeleteDomainRecord",
		"alidns:DescribeDomainRecords",
		"alidns:DescribeSubDomainRecords",
		"alidns:DescribeDomains",
	},
	CapCDN: {
		"cas:UploadUserCertificate",
		"cas:DescribeUserCertificateList",
		"cas:DeleteUserCertificate",
		"cdn:SetCdnDomainSSLCertificate",
		"cdn:DescribeDomainCertificateInfo",
		"cdn:DescribeUserDomains",
	},
	CapSLB: {
		"cas:UploadUserCertificate",
		"slb:UploadServerCertificate",
		"slb:SetLoadBalancerHTTPSListenerAttribute",
		"slb:DescribeLoadBalancers",
	},
	CapOSS: {
		"oss:PutBucketCname",
		"oss:ListBuckets",
	},
}

// KnownCapabilities 按固定顺序返回全部能力，供界面渲染。
func KnownCapabilities() []Capability {
	return []Capability{CapDNS, CapCDN, CapSLB, CapOSS}
}

// Statement 是一条 RAM 策略语句。
type Statement struct {
	Effect   string   `json:"Effect"`
	Action   []string `json:"Action"`
	Resource []string `json:"Resource"`
}

// PolicyDocument 是 RAM 自定义策略文档。
type PolicyDocument struct {
	Version   string      `json:"Version"`
	Statement []Statement `json:"Statement"`
}

// BuildPolicy 按勾选的能力生成最小权限策略。
//
// dnsResources 可以把 DNS 权限收窄到具体域名——配合 CNAME 委派，
// 甚至可以只授权那一个没有业务流量的验证专用域。为空时退回 "*"。
func BuildPolicy(caps []Capability, dnsResources []string) (*PolicyDocument, error) {
	if len(caps) == 0 {
		return nil, fmt.Errorf("aliyun: 至少要勾选一项能力")
	}

	// 同一个 Action 可能被多项能力要求（如 cas:UploadUserCertificate），去重。
	dnsSet := map[string]bool{}
	otherSet := map[string]bool{}
	for _, c := range caps {
		actions, ok := capabilityActions[c]
		if !ok {
			return nil, fmt.Errorf("aliyun: 未知能力 %q", c)
		}
		for _, a := range actions {
			if c == CapDNS {
				dnsSet[a] = true
			} else {
				otherSet[a] = true
			}
		}
	}

	doc := &PolicyDocument{Version: "1"}
	if len(dnsSet) > 0 {
		res := dnsResources
		if len(res) == 0 {
			res = []string{"*"}
		}
		doc.Statement = append(doc.Statement, Statement{
			Effect: "Allow", Action: sortedKeys(dnsSet), Resource: res,
		})
	}
	if len(otherSet) > 0 {
		doc.Statement = append(doc.Statement, Statement{
			Effect: "Allow", Action: sortedKeys(otherSet), Resource: []string{"*"},
		})
	}
	return doc, nil
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// JSON 返回策略文档的 JSON 文本。
//
// 创建之前要把它完整展示给用户——一个索要管理凭据的功能，
// 透明度就是它的信任基础。
func (d *PolicyDocument) JSON() (string, error) {
	b, err := json.MarshalIndent(d, "", "  ")
	return string(b), err
}
