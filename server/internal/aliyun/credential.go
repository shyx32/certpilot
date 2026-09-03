// Package aliyun 封装阿里云凭据与各服务客户端的构造。
package aliyun

import (
	"encoding/json"
	"errors"
)

// DefaultRegion 是 CAS 证书服务的默认地域。
const DefaultRegion = "cn-hangzhou"

var ErrIncomplete = errors.New("aliyun: AccessKey ID 与 Secret 都不能为空")

// Credential 是一个阿里云 AccessKey。
type Credential struct {
	AccessKeyID     string `json:"access_key_id"`
	AccessKeySecret string `json:"access_key_secret"`
	// Region 影响 CAS 等区域性服务；DNS 与 RAM 是全局服务。
	Region string `json:"region,omitempty"`
}

// ParseCredential 从凭据箱中的明文 JSON 解析。
func ParseCredential(secret []byte) (*Credential, error) {
	var c Credential
	if err := json.Unmarshal(secret, &c); err != nil {
		return nil, err
	}
	if c.AccessKeyID == "" || c.AccessKeySecret == "" {
		return nil, ErrIncomplete
	}
	if c.Region == "" {
		c.Region = DefaultRegion
	}
	return &c, nil
}

// MarshalCredential 构造凭据 JSON，供写入凭据箱。
func MarshalCredential(id, secret, region string) ([]byte, error) {
	if id == "" || secret == "" {
		return nil, ErrIncomplete
	}
	if region == "" {
		region = DefaultRegion
	}
	return json.Marshal(Credential{AccessKeyID: id, AccessKeySecret: secret, Region: region})
}
