package nginxsvc

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Kind 是 nginx 的运行形态。它决定证书写到哪、用什么命令重载。
type Kind string

const (
	// KindSystemd 宿主机上由 systemd 管理。
	KindSystemd Kind = "nginx_systemd"
	// KindBare 宿主机上直接运行，没有 systemd 单元。
	KindBare Kind = "nginx_bare"
	// KindDocker 跑在容器里。
	KindDocker Kind = "nginx_docker"
)

func (k Kind) Label() string {
	switch k {
	case KindSystemd:
		return "宿主机 · systemd"
	case KindBare:
		return "宿主机 · 直接管理"
	case KindDocker:
		return "Docker 容器"
	default:
		return string(k)
	}
}

// Service 是一台主机上的一个 nginx 实例。
type Service struct {
	Kind Kind `json:"kind"`

	// ---- 容器场景 ----
	ContainerID    string  `json:"container_id,omitempty"`
	ContainerName  string  `json:"container_name,omitempty"`
	ComposeProject string  `json:"compose_project,omitempty"`
	ComposeService string  `json:"compose_service,omitempty"`
	Image          string  `json:"image,omitempty"`
	ContainerUser  string  `json:"container_user,omitempty"`
	Mounts         []Mount `json:"mounts,omitempty"`

	// ---- 通用 ----
	TestArgv       []string      `json:"test_argv"`
	ReloadArgv     []string      `json:"reload_argv"`
	WriteStrategy  WriteStrategy `json:"write_strategy"`
	StrategyReason string        `json:"strategy_reason"`
	// ReloadNeedsSudo 与写入权限是两件独立的事：
	// SSH 用户常常能写证书目录，却没有权限向 root 启动的
	// nginx master 进程发信号。
	ReloadNeedsSudo bool `json:"reload_needs_sudo"`
	// Certs 是从配置里发现的证书用法，供接入时批量导入。
	Certs []CertUsage `json:"certs,omitempty"`
	// Notes 是需要让用户知道的提示。
	Notes []string `json:"notes,omitempty"`
}

// Locator 返回稳定的容器定位方式。
//
// 容器名会变——compose 重建后可能从 proj_nginx_1 变成 proj-nginx-1，
// 容器 ID 更是每次都换。稳定的标识是 compose 项目名 + 服务名。
func (s *Service) Locator() []string {
	if s.ComposeProject != "" && s.ComposeService != "" {
		return []string{
			"docker", "ps", "-q",
			"--filter", "label=com.docker.compose.project=" + s.ComposeProject,
			"--filter", "label=com.docker.compose.service=" + s.ComposeService,
		}
	}
	if s.ContainerName != "" {
		return []string{"docker", "ps", "-q", "--filter", "name=^" + s.ContainerName + "$"}
	}
	return nil
}

// DisplayName 是界面上展示的名字。
func (s *Service) DisplayName() string {
	switch s.Kind {
	case KindDocker:
		if s.ComposeService != "" {
			return fmt.Sprintf("%s / %s", s.ComposeProject, s.ComposeService)
		}
		return s.ContainerName
	default:
		return s.Kind.Label()
	}
}

// ---------- 探测输出解析 ----------

// Container 是 docker ps 输出的一行。
type Container struct {
	ID             string
	Name           string
	Image          string
	ComposeProject string
	ComposeService string
}

// psFormat 是探测时使用的 docker ps 格式串。
const psFormat = `{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Label "com.docker.compose.project"}}\t{{.Label "com.docker.compose.service"}}`

// ParseDockerPS 解析 docker ps 的制表符输出。
func ParseDockerPS(out string) []Container {
	var list []Container
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 3 || f[0] == "" {
			continue
		}
		c := Container{ID: f[0], Name: f[1], Image: f[2]}
		if len(f) > 3 {
			c.ComposeProject = f[3]
		}
		if len(f) > 4 {
			c.ComposeService = f[4]
		}
		list = append(list, c)
	}
	return list
}

// LooksLikeNginx 判断一个容器是否在跑 nginx。
//
// 镜像名匹配是启发式的：自建镜像可能叫别的名字，
// 所以探测时还会用「谁占着 443」和「容器内有没有 nginx 命令」交叉验证。
func LooksLikeNginx(c Container) bool {
	s := strings.ToLower(c.Image + " " + c.Name + " " + c.ComposeService)
	for _, kw := range []string{"nginx", "openresty", "tengine"} {
		if strings.Contains(s, kw) {
			return true
		}
	}
	return false
}

// inspectPayload 是 docker inspect 里我们关心的字段。
type inspectPayload struct {
	Mounts []Mount `json:"Mounts"`
	Config struct {
		User  string `json:"User"`
		Image string `json:"Image"`
	} `json:"Config"`
}

// ParseInspect 从 docker inspect 的 JSON 数组里取出挂载与运行用户。
func ParseInspect(out string) ([]Mount, string, error) {
	out = strings.TrimSpace(out)
	if out == "" {
		return nil, "", fmt.Errorf("nginxsvc: docker inspect 没有输出")
	}
	var arr []inspectPayload
	if err := json.Unmarshal([]byte(out), &arr); err != nil {
		// 有些版本用 --format '{{json .}}' 时输出单个对象。
		var one inspectPayload
		if err2 := json.Unmarshal([]byte(out), &one); err2 != nil {
			return nil, "", fmt.Errorf("nginxsvc: 解析 docker inspect 失败: %w", err)
		}
		return one.Mounts, one.Config.User, nil
	}
	if len(arr) == 0 {
		return nil, "", fmt.Errorf("nginxsvc: 容器不存在")
	}
	return arr[0].Mounts, arr[0].Config.User, nil
}

// ---------- 命令模板 ----------

// BuildCommands 按形态生成成对的预检与重载命令。
//
// 一律用 reload 而不是 restart：restart 会断掉所有连接，
// reload 是平滑的。docker kill -s HUP 虽然也能触发重载，
// 但它跳过了配置校验，不作为默认。
func BuildCommands(kind Kind, container string) (test, reload []string) {
	switch kind {
	case KindSystemd:
		return []string{"nginx", "-t"}, []string{"systemctl", "reload", "nginx"}
	case KindBare:
		return []string{"nginx", "-t"}, []string{"nginx", "-s", "reload"}
	case KindDocker:
		c := container
		if c == "" {
			c = "{container}"
		}
		return []string{"docker", "exec", c, "nginx", "-t"},
			[]string{"docker", "exec", c, "nginx", "-s", "reload"}
	}
	return nil, nil
}

// NeedsChown 报告写入后是否需要把属主改成容器的运行用户。
//
// 辅助容器以 root 写入。多数 nginx 镜像主进程也是 root（worker 降权后仍能读），
// 但 nginx-unprivileged 这类非 root 镜像会读不到新证书，reload 后握手失败。
func NeedsChown(containerUser string) (string, bool) {
	u := strings.TrimSpace(containerUser)
	if u == "" || u == "root" || u == "0" || strings.HasPrefix(u, "0:") {
		return "", false
	}
	return u, true
}
