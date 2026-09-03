package nginxsvc

import (
	"context"
	"fmt"
	"path"
	"strings"

	"github.com/certpilot/server/internal/sshx"
)

// Runner 是探测所需的最小执行能力，便于测试时替换。
type Runner interface {
	Run(ctx context.Context, argv []string) (*sshx.Result, error)
}

// Detection 是一次主机探测的完整结果。
type Detection struct {
	Services        []Service `json:"services"`
	DockerAvailable bool      `json:"docker_available"`
	SudoAvailable   bool      `json:"sudo_available"`
	// Port443 记录谁占着 443，是判断 TLS 由谁提供最可靠的一条线索。
	Port443 string   `json:"port_443,omitempty"`
	Notes   []string `json:"notes,omitempty"`
}

// Detect 探测目标主机上的 nginx 形态。
//
// 全部使用只读命令。识别不出来不是错误——返回空服务列表，
// 由用户手工选择档案或自定义命令。
func Detect(ctx context.Context, r Runner) (*Detection, error) {
	d := &Detection{}

	// sudo 可用性要在探测阶段就问清楚，免得部署时才发现要输密码。
	if res, err := r.Run(ctx, []string{"sudo", "-n", "true"}); err == nil && res.ExitCode == 0 {
		d.SudoAvailable = true
	}

	// 谁占着 443：占用者是 docker-proxy 基本就能断定 TLS 由容器提供。
	if res, err := r.Run(ctx, []string{"sh", "-c", "ss -lntp 'sport = :443' 2>/dev/null || true"}); err == nil {
		d.Port443 = strings.TrimSpace(res.Stdout)
	}

	if res, err := r.Run(ctx, []string{"docker", "version", "--format", "{{.Server.Version}}"}); err == nil && res.ExitCode == 0 {
		d.DockerAvailable = true
	}

	if d.DockerAvailable {
		svcs, notes := detectContainers(ctx, r, d.SudoAvailable)
		d.Services = append(d.Services, svcs...)
		d.Notes = append(d.Notes, notes...)
	}

	if svc := detectHost(ctx, r, d.SudoAvailable); svc != nil {
		d.Services = append(d.Services, *svc)
	}

	if len(d.Services) == 0 {
		d.Notes = append(d.Notes,
			"未能自动识别出 nginx。可以手工添加自定义命令，或确认当前用户有权限执行 nginx 与 docker。")
	}
	if strings.Contains(d.Port443, "docker-proxy") {
		d.Notes = append(d.Notes, "443 端口由 docker-proxy 占用，TLS 应由容器提供。")
	}
	return d, nil
}

// detectHost 探测宿主机上直接运行的 nginx。
func detectHost(ctx context.Context, r Runner, sudoAvailable bool) *Service {
	res, err := r.Run(ctx, []string{"command", "-v", "nginx"})
	if err != nil || res.ExitCode != 0 || strings.TrimSpace(res.Stdout) == "" {
		return nil
	}

	kind := KindBare
	if u, err := r.Run(ctx, []string{"systemctl", "list-unit-files", "nginx.service"}); err == nil &&
		u.ExitCode == 0 && strings.Contains(u.Stdout, "nginx.service") {
		kind = KindSystemd
	}

	test, reload := BuildCommands(kind, "")
	svc := Service{Kind: kind, TestArgv: test, ReloadArgv: reload}

	// 先定权限再读配置：nginx -T 往往和 reload 一样需要提权，
	// 用错身份跑会得到空结果，进而让后面的判断全部走偏。
	svc.ReloadNeedsSudo = nginxNeedsSudo(ctx, r)
	svc.Certs = discoverCerts(ctx, r, nil, svc.ReloadNeedsSudo)

	if svc.ReloadNeedsSudo {
		if canSudoNginx(ctx, r) {
			svc.Notes = append(svc.Notes,
				"nginx 主进程以 root 运行，预检与重载将通过 sudo 执行。")
		} else {
			svc.Notes = append(svc.Notes,
				"nginx 主进程以 root 运行，但当前用户无法免密 sudo 执行 nginx，重载步骤会失败。"+
					"请在 sudoers 中放行 nginx 命令。")
		}
	}
	if len(svc.Certs) == 0 {
		svc.Notes = append(svc.Notes,
			"没能从 nginx 配置里读出证书路径，部署时需要手工指定证书存放位置。")
	}

	// 写入权限与重载权限是两件独立的事：证书目录常常属于运维用户，
	// 而 nginx 主进程是 root。分开探测才不会互相带偏。
	svc.WriteStrategy, svc.StrategyReason = ChooseStrategy(StrategyInput{
		HostWritable:  certDirWritable(ctx, r, svc.Certs, nil),
		SudoAvailable: sudoAvailable,
	})
	return &svc
}

// canSudoNginx 检查能否免密 sudo 执行 nginx。
//
// 单独探测是因为运维给出的 sudo 权限往往是受限的——
// sudoers 里只放行 nginx 是常见做法，此时 `sudo -n true` 会失败，
// 但 `sudo -n nginx -t` 可以成功。
func canSudoNginx(ctx context.Context, r Runner) bool {
	res, err := r.Run(ctx, []string{"sudo", "-n", "nginx", "-t"})
	return err == nil && res.ExitCode == 0
}

// nginxNeedsSudo 判断执行 nginx 命令是否需要提权。
//
// nginx -s reload 的实质是向 master 进程发 HUP 信号，nginx -T 也要读取
// 只有 root 能读的配置与私钥。master 通常由 root 启动，而 SSH 登录的
// 多半是普通运维用户——能写证书目录不代表能做这两件事。
// 这类权限必须与写入权限分开探测，否则会在部署的最后一步才失败。
func nginxNeedsSudo(ctx context.Context, r Runner) bool {
	cur, err := r.Run(ctx, []string{"id", "-u"})
	if err != nil || strings.TrimSpace(cur.Stdout) == "0" {
		return false // 自己就是 root
	}
	// 最老的 nginx 进程即 master。
	pid, err := r.Run(ctx, []string{"sh", "-c", "pgrep -o nginx 2>/dev/null || echo ''"})
	if err != nil || strings.TrimSpace(pid.Stdout) == "" {
		return false // nginx 没在跑，无从判断，交给实际执行时报错
	}
	owner, err := r.Run(ctx, []string{"sh", "-c",
		"stat -c %u /proc/" + strings.TrimSpace(pid.Stdout) + " 2>/dev/null || echo ''"})
	if err != nil {
		return false
	}
	o := strings.TrimSpace(owner.Stdout)
	return o == "0" && strings.TrimSpace(cur.Stdout) != "0"
}

// detectContainers 探测容器里的 nginx。
func detectContainers(ctx context.Context, r Runner, sudo bool) ([]Service, []string) {
	var svcs []Service
	var notes []string

	res, err := r.Run(ctx, []string{"docker", "ps", "--format", psFormat})
	if err != nil || res.ExitCode != 0 {
		return nil, []string{"无法列出 Docker 容器，请确认当前用户在 docker 组中或可免密 sudo。"}
	}

	for _, c := range ParseDockerPS(res.Stdout) {
		if !LooksLikeNginx(c) {
			continue
		}
		// 交叉验证：镜像名只是启发式，真正确认要看容器里有没有 nginx。
		if probe, err := r.Run(ctx, []string{"docker", "exec", c.ID, "nginx", "-v"}); err != nil || probe.ExitCode != 0 {
			continue
		}

		svc := Service{
			Kind:           KindDocker,
			ContainerID:    c.ID,
			ContainerName:  c.Name,
			ComposeProject: c.ComposeProject,
			ComposeService: c.ComposeService,
			Image:          c.Image,
		}

		if ins, err := r.Run(ctx, []string{"docker", "inspect", c.ID}); err == nil && ins.ExitCode == 0 {
			if mounts, user, err := ParseInspect(ins.Stdout); err == nil {
				svc.Mounts = mounts
				svc.ContainerUser = user
			}
		}

		svc.TestArgv, svc.ReloadArgv = BuildCommands(KindDocker, c.ID)
		// 容器场景的重载走 docker exec，权限由 docker 组决定，
		// 与宿主机的进程属主无关。
		svc.ReloadNeedsSudo = false
		svc.Certs = discoverCerts(ctx, r, &svc, false)

		// 用第一张证书的路径来判定写入策略——同一个 nginx 的证书
		// 通常都在同一个挂载下。
		var mount *Mount
		if len(svc.Certs) > 0 {
			if resolved, err := ResolveHostPath(svc.Certs[0].CertPath, svc.Mounts); err == nil {
				mount = &resolved.Mount
			} else {
				svc.Notes = append(svc.Notes,
					fmt.Sprintf("证书路径 %s 不在任何挂载卷下，写进去会在容器重建时丢失，请先为容器添加挂载。",
						svc.Certs[0].CertPath))
			}
		}
		svc.WriteStrategy, svc.StrategyReason = ChooseStrategy(StrategyInput{
			InContainer:   true,
			Mount:         mount,
			HostWritable:  certDirWritable(ctx, r, svc.Certs, &svc),
			SudoAvailable: sudo,
		})
		if u, need := NeedsChown(svc.ContainerUser); need {
			svc.Notes = append(svc.Notes,
				fmt.Sprintf("容器以非 root 用户 %s 运行，写入后会自动 chown，否则 nginx 读不到新证书。", u))
		}
		svcs = append(svcs, svc)
	}
	return svcs, notes
}

// discoverCerts 用 nginx -T 找出配置里实际引用的证书。
//
// 这一条命令能直接回答「这台机器上哪些域名用了哪些证书文件」，
// 接入时据此批量导入，不必手工录入几十个域名。
func discoverCerts(ctx context.Context, r Runner, svc *Service, sudo bool) []CertUsage {
	argv := []string{"nginx", "-T"}
	switch {
	case svc != nil && svc.ContainerID != "":
		argv = append([]string{"docker", "exec", svc.ContainerID}, argv...)
	case sudo:
		argv = sshx.WithSudo(argv)
	}
	res, err := r.Run(ctx, argv)
	if err != nil || res.Stdout == "" {
		return nil
	}
	return GroupByCert(ParseServers(res.Stdout))
}

// certDirWritable 测试证书目录在宿主机侧是否可直接写入。
func certDirWritable(ctx context.Context, r Runner, certs []CertUsage, svc *Service) bool {
	dir := hostCertDir(certs, svc)
	if dir == "" {
		return false
	}
	res, err := r.Run(ctx, []string{"test", "-w", dir})
	return err == nil && res.ExitCode == 0
}

// hostCertDir 返回证书所在目录的宿主机路径。
func hostCertDir(certs []CertUsage, svc *Service) string {
	if len(certs) == 0 {
		return ""
	}
	p := certs[0].CertPath
	if svc != nil && len(svc.Mounts) > 0 {
		resolved, err := ResolveHostPath(p, svc.Mounts)
		if err != nil {
			return ""
		}
		p = resolved.HostPath
	}
	return path.Dir(p)
}

// HostPathOf 把服务内的路径翻译成宿主机路径；宿主机形态直接返回原路径。
func (s *Service) HostPathOf(containerPath string) (string, error) {
	if s.Kind != KindDocker {
		return containerPath, nil
	}
	resolved, err := ResolveHostPath(containerPath, s.Mounts)
	if err != nil {
		return "", err
	}
	return resolved.HostPath, nil
}
