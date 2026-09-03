// Package nginxsvc 处理目标服务器上的 nginx 服务：探测形态、定位证书路径、下发与重载。
package nginxsvc

import (
	"errors"
	"path"
	"strings"
)

// Mount 是 docker inspect .Mounts 里的一条挂载。
type Mount struct {
	Type        string `json:"Type"`        // bind | volume
	Source      string `json:"Source"`      // 宿主机路径
	Destination string `json:"Destination"` // 容器内路径
	RW          bool   `json:"RW"`
	Name        string `json:"Name"` // named volume 的名字
}

// ErrNotMounted 表示容器内路径不在任何挂载下。
//
// 这意味着证书要么被打进了镜像，要么落在容器可写层——
// 两种情况下写进去都会在下次容器重建时消失，因此必须拒绝部署，
// 而不是制造一个几个月后才爆的雷。
var ErrNotMounted = errors.New("nginxsvc: 该路径不在任何挂载卷下")

// Resolved 是一次容器内路径到宿主机路径的翻译结果。
type Resolved struct {
	// HostPath 是宿主机上的真实路径。named volume 时指向 Docker 内部目录。
	HostPath string
	// Mount 是命中的那条挂载。
	Mount Mount
}

// ResolveHostPath 把容器内路径翻译成宿主机路径。
//
// 采用最长前缀匹配：同时挂了 /etc/nginx 与 /etc/nginx/certs 时，
// /etc/nginx/certs/a.pem 应归属更精确的那一条。
func ResolveHostPath(containerPath string, mounts []Mount) (*Resolved, error) {
	cp := path.Clean(containerPath)
	if !strings.HasPrefix(cp, "/") {
		return nil, ErrNotMounted
	}

	var best *Mount
	bestLen := -1
	for i := range mounts {
		dest := path.Clean(mounts[i].Destination)
		if !covers(dest, cp) {
			continue
		}
		if len(dest) > bestLen {
			bestLen = len(dest)
			best = &mounts[i]
		}
	}
	if best == nil {
		return nil, ErrNotMounted
	}

	dest := path.Clean(best.Destination)
	rel := strings.TrimPrefix(cp, dest)
	rel = strings.TrimPrefix(rel, "/")

	host := path.Clean(best.Source)
	if rel != "" {
		host = path.Join(host, rel)
	}
	return &Resolved{HostPath: host, Mount: *best}, nil
}

// covers 判断挂载点是否覆盖该路径。
//
// 注意不能只用 HasPrefix：/etc/nginx-extra 不属于 /etc/nginx。
func covers(dest, target string) bool {
	if dest == "/" {
		return true
	}
	return target == dest || strings.HasPrefix(target, dest+"/")
}

// WriteStrategy 决定证书文件用什么方式落到目标上。
type WriteStrategy string

const (
	// WriteHost 直接写宿主机路径。最简单，备份与回滚都在文件系统上，
	// 出问题人工也能介入。
	WriteHost WriteStrategy = "host"
	// WriteHostSudo 同上，但需要 sudo。
	WriteHostSudo WriteStrategy = "host_sudo"
	// WriteHelper 起一个一次性容器，用 --volumes-from 继承 nginx 的挂载后写入。
	//
	// 这条路径绕开了「宿主机路径是什么」的问题：不需要知道 Source，
	// 也不需要 sudo 去读 Docker 的内部目录。
	WriteHelper WriteStrategy = "helper"
)

// StrategyInput 是判定写入策略所需的探测结果。
type StrategyInput struct {
	// InContainer 表示 nginx 跑在容器里。
	InContainer bool
	// Mount 是证书目录命中的那条挂载（仅容器场景有意义）。
	Mount *Mount
	// HostWritable 表示当前 SSH 用户能直接写宿主机上那个目录。
	HostWritable bool
	// SudoAvailable 表示可以免密 sudo。
	SudoAvailable bool
}

// ChooseStrategy 按探测结果选定写入方式。
//
// named volume 的默认策略是辅助容器而非直写：/var/lib/docker/volumes
// 属主是 root、权限 700，在 docker 组里意味着能指挥 daemon，
// 并不意味着能用自己的身份读写那个目录。
func ChooseStrategy(in StrategyInput) (WriteStrategy, string) {
	if !in.InContainer {
		if in.HostWritable {
			return WriteHost, "直接写宿主机路径"
		}
		if in.SudoAvailable {
			return WriteHostSudo, "证书目录需要提权，使用 sudo 写入"
		}
		return WriteHostSudo, "证书目录当前用户不可写，且未能验证免密 sudo，写入步骤可能失败"
	}

	// 容器场景
	if in.Mount == nil {
		return WriteHelper, "证书路径未命中任何挂载，需先为容器添加挂载"
	}
	switch {
	case in.Mount.Type == "volume":
		return WriteHelper, "named volume 由 Docker 管理，经辅助容器写入"
	case in.Mount.Type == "bind" && in.HostWritable:
		return WriteHost, "bind mount 且宿主机路径可写，直接写入"
	case in.Mount.Type == "bind" && in.SudoAvailable:
		return WriteHostSudo, "bind mount 但需提权，使用 sudo 写入"
	default:
		return WriteHelper, "宿主机路径不可直接写入，经辅助容器写入"
	}
}
