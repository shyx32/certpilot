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
