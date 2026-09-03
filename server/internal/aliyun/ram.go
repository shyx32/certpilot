package aliyun

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"

	ram "github.com/aliyun/alibaba-cloud-sdk-go/services/ram"
)

// ProvisionRequest 描述一次子账号自动创建。
//
// AdminAccessKeyID/Secret 是用户临时提供的管理凭据。它们只存在于本次请求的
// 内存中：不入库、不落盘、不进日志，函数返回即失去引用。
type ProvisionRequest struct {
	AdminAccessKeyID     string
	AdminAccessKeySecret string
	Capabilities         []Capability
	// DNSResources 可选，把 DNS 权限收窄到指定域名。
	DNSResources []string
	// NamePrefix 默认为 certpilot。
	NamePrefix string
}

// ProvisionResult 是创建出来的子账号。只有它会被保存。
type ProvisionResult struct {
	UserName        string
	PolicyName      string
	AccessKeyID     string
	AccessKeySecret string
	PolicyJSON      string
}

// Provision 依次创建 RAM 用户、自定义策略、绑定策略、生成 AccessKey。
//
// 任意一步失败都会反向清理已创建的资源，让用户的阿里云账号回到干净状态；
// 清理本身若再失败，错误信息里会列出需要手工删除的资源名，不留哑谜。
func Provision(ctx context.Context, req *ProvisionRequest) (*ProvisionResult, error) {
	doc, err := BuildPolicy(req.Capabilities, req.DNSResources)
	if err != nil {
		return nil, err
	}
	policyJSON, err := doc.JSON()
	if err != nil {
		return nil, err
	}

	client, err := ram.NewClientWithAccessKey("cn-hangzhou", req.AdminAccessKeyID, req.AdminAccessKeySecret)
	if err != nil {
		return nil, fmt.Errorf("管理凭据无效：%s", Explain(err))
	}

	prefix := req.NamePrefix
	if prefix == "" {
		prefix = "certpilot"
	}
	suffix, err := randomSuffix()
	if err != nil {
		return nil, err
	}
	userName := fmt.Sprintf("%s-%s", prefix, suffix)
	policyName := fmt.Sprintf("%sPolicy-%s", strings.ToUpper(prefix[:1])+prefix[1:], suffix)

	// rollback 按创建的逆序清理。
	var cleanup []func()
	rollback := func() {
		for i := len(cleanup) - 1; i >= 0; i-- {
			cleanup[i]()
		}
	}

	// 1. 创建用户
	cu := ram.CreateCreateUserRequest()
	cu.UserName = userName
	cu.DisplayName = userName
	if err := Prepare(ctx, cu); err != nil {
		return nil, err
	}
	if _, err := client.CreateUser(cu); err != nil {
		return nil, fmt.Errorf("创建 RAM 用户失败：%s", Explain(err))
	}
	cleanup = append(cleanup, func() {
		r := ram.CreateDeleteUserRequest()
		r.UserName = userName
		if _, err := client.DeleteUser(r); err != nil {
			slog.Error("回滚：删除 RAM 用户失败，需手工清理", "user", userName, "err", err)
		}
	})

	// 2. 创建策略
	cp := ram.CreateCreatePolicyRequest()
	cp.PolicyName = policyName
	cp.PolicyDocument = policyJSON
	cp.Description = "Created by CertPilot for certificate automation"
	if err := Prepare(ctx, cp); err != nil {
		rollback()
		return nil, err
	}
	if _, err := client.CreatePolicy(cp); err != nil {
		rollback()
		return nil, fmt.Errorf("创建自定义策略失败：%s", Explain(err))
	}
	cleanup = append(cleanup, func() {
		r := ram.CreateDeletePolicyRequest()
		r.PolicyName = policyName
		if _, err := client.DeletePolicy(r); err != nil {
			slog.Error("回滚：删除策略失败，需手工清理", "policy", policyName, "err", err)
		}
	})

	// 3. 绑定策略
	ap := ram.CreateAttachPolicyToUserRequest()
	ap.PolicyType = "Custom"
	ap.PolicyName = policyName
	ap.UserName = userName
	if err := Prepare(ctx, ap); err != nil {
		rollback()
		return nil, err
	}
	if _, err := client.AttachPolicyToUser(ap); err != nil {
		rollback()
		return nil, fmt.Errorf("绑定策略到用户失败：%s", Explain(err))
	}
	cleanup = append(cleanup, func() {
		r := ram.CreateDetachPolicyFromUserRequest()
		r.PolicyType = "Custom"
		r.PolicyName = policyName
		r.UserName = userName
		if _, err := client.DetachPolicyFromUser(r); err != nil {
			slog.Error("回滚：解绑策略失败，需手工清理", "policy", policyName, "err", err)
		}
	})

	// 4. 创建 AccessKey
	//
	// Secret 只在这一次响应里出现，此后再也读不到。调用方必须立即加密入库，
	// 入库失败要调用 RevokeAccessKey 撤销，否则会留下一把谁也不知道密码的僵尸 AK。
	ck := ram.CreateCreateAccessKeyRequest()
	ck.UserName = userName
	if err := Prepare(ctx, ck); err != nil {
		rollback()
		return nil, err
	}
	akResp, err := client.CreateAccessKey(ck)
	if err != nil {
		rollback()
		return nil, fmt.Errorf("创建 AccessKey 失败：%s", Explain(err))
	}

	return &ProvisionResult{
		UserName:        userName,
		PolicyName:      policyName,
		AccessKeyID:     akResp.AccessKey.AccessKeyId,
		AccessKeySecret: akResp.AccessKey.AccessKeySecret,
		PolicyJSON:      policyJSON,
	}, nil
}

// RevokeAccessKey 撤销一把已创建但未能安全保存的 AccessKey。
func RevokeAccessKey(ctx context.Context, adminID, adminSecret, userName, accessKeyID string) error {
	client, err := ram.NewClientWithAccessKey("cn-hangzhou", adminID, adminSecret)
	if err != nil {
		return err
	}
	r := ram.CreateDeleteAccessKeyRequest()
	r.UserName = userName
	r.UserAccessKeyId = accessKeyID
	if err := Prepare(ctx, r); err != nil {
		return err
	}
	_, err = client.DeleteAccessKey(r)
	return err
}

func randomSuffix() (string, error) {
	b := make([]byte, 3)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// RotateRequest 是一次 AccessKey 轮换。
type RotateRequest struct {
	AdminAccessKeyID     string
	AdminAccessKeySecret string
	// UserName 是要轮换的 RAM 用户。
	UserName string
	// OldAccessKeyID 是当前正在用的那把，验证通过后删除它。
	OldAccessKeyID string
}

// RotateResult 是新生成的凭据。
type RotateResult struct {
	AccessKeyID     string
	AccessKeySecret string
}

// RotateAccessKey 零停机地更换一把 AccessKey。
//
// RAM 用户最多持有 2 把 AK，正好够走「建新 → 验证 → 换用 → 删旧」这条路：
// 任何一步失败都停在安全状态，旧 AK 始终可用，直到新的被确认能工作。
//
// 删除旧 AK 由调用方在新凭据入库成功后调用 RevokeAccessKey 完成——
// 顺序很重要：先入库再删旧，反过来会在入库失败时让两把 AK 都不可用。
func RotateAccessKey(ctx context.Context, req *RotateRequest) (*RotateResult, error) {
	client, err := ram.NewClientWithAccessKey("cn-hangzhou",
		req.AdminAccessKeyID, req.AdminAccessKeySecret)
	if err != nil {
		return nil, fmt.Errorf("管理凭据无效：%s", Explain(err))
	}

	ck := ram.CreateCreateAccessKeyRequest()
	ck.UserName = req.UserName
	if err := Prepare(ctx, ck); err != nil {
		return nil, err
	}
	resp, err := client.CreateAccessKey(ck)
	if err != nil {
		return nil, fmt.Errorf("创建新 AccessKey 失败：%s", Explain(err))
	}
	return &RotateResult{
		AccessKeyID:     resp.AccessKey.AccessKeyId,
		AccessKeySecret: resp.AccessKey.AccessKeySecret,
	}, nil
}

// UpdatePolicy 更新子账号的权限策略。
//
// 用户后来想加 SLB 部署时走这条路：子账号 AK 不变，无需重新分发。
// 一个策略最多 5 个版本，因此先清掉非默认的旧版本再建新版。
func UpdatePolicy(ctx context.Context, adminID, adminSecret, policyName string,
	caps []Capability, dnsResources []string) (string, error) {

	doc, err := BuildPolicy(caps, dnsResources)
	if err != nil {
		return "", err
	}
	policyJSON, err := doc.JSON()
	if err != nil {
		return "", err
	}

	client, err := ram.NewClientWithAccessKey("cn-hangzhou", adminID, adminSecret)
	if err != nil {
		return "", fmt.Errorf("管理凭据无效：%s", Explain(err))
	}

	// 先腾出版本空间：策略最多 5 个版本，满了会直接失败。
	lv := ram.CreateListPolicyVersionsRequest()
	lv.PolicyName = policyName
	lv.PolicyType = "Custom"
	if err := Prepare(ctx, lv); err == nil {
		if versions, err := client.ListPolicyVersions(lv); err == nil {
			for _, v := range versions.PolicyVersions.PolicyVersion {
				if v.IsDefaultVersion {
					continue
				}
				dv := ram.CreateDeletePolicyVersionRequest()
				dv.PolicyName = policyName
				dv.VersionId = v.VersionId
				if err := Prepare(ctx, dv); err == nil {
					_, _ = client.DeletePolicyVersion(dv)
				}
			}
		}
	}

	cv := ram.CreateCreatePolicyVersionRequest()
	cv.PolicyName = policyName
	cv.PolicyDocument = policyJSON
	cv.SetAsDefault = "true"
	if err := Prepare(ctx, cv); err != nil {
		return "", err
	}
	if _, err := client.CreatePolicyVersion(cv); err != nil {
		return "", fmt.Errorf("更新策略失败：%s", Explain(err))
	}
	return policyJSON, nil
}
