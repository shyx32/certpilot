package nginxsvc

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/certpilot/server/internal/sshx"
)

// Executor 是部署所需的执行能力。
type Executor interface {
	Runner
	RunScript(ctx context.Context, script string, args []string, sudo bool) (*sshx.Result, error)
	PipeIn(ctx context.Context, argv []string, content io.Reader) (*sshx.Result, error)
}

// commitScript 备份旧文件并原子替换，失败时不留半新半旧的状态。
const commitScript = `
set -eu
cert="$1"; key="$2"; ts="$3"; owner="${4:-}"
[ -f "$cert" ] && cp -p "$cert" "$cert.bak.$ts" || true
[ -f "$key" ] && cp -p "$key" "$key.bak.$ts" || true
mv "$cert.new" "$cert"
mv "$key.new" "$key"
chmod 644 "$cert"
chmod 600 "$key"
if [ -n "$owner" ]; then
  chown "$owner" "$cert" "$key" 2>/dev/null || true
fi
`

// rollbackScript 用备份还原。
const rollbackScript = `
set -eu
cert="$1"; key="$2"; ts="$3"
[ -f "$cert.bak.$ts" ] && mv "$cert.bak.$ts" "$cert" || true
[ -f "$key.bak.$ts" ] && mv "$key.bak.$ts" "$key" || true
`

// cleanupScript 删除临时文件与过期备份，避免目录里越堆越多。
const cleanupScript = `
set -eu
cert="$1"; key="$2"; keep="$3"
rm -f "$cert.new" "$key.new"
for f in "$cert".bak.* "$key".bak.*; do
  [ -e "$f" ] || continue
  echo "$f"
done | sort -r | tail -n +"$keep" | xargs -r rm -f
`

// Material 是要下发的一份证书。
type Material struct {
	// CertPath / KeyPath 是服务视角的路径（容器场景即容器内路径）。
	CertPath     string
	KeyPath      string
	FullChainPEM []byte
	KeyPEM       []byte
}

// DeployResult 记录一次下发的过程，供界面展示。
type DeployResult struct {
	Strategy   WriteStrategy `json:"strategy"`
	TestOutput string        `json:"test_output"`
	Steps      []string      `json:"steps"`
	RolledBack bool          `json:"rolled_back"`
}

// Deploy 把证书写到目标并重载 nginx。
//
// 顺序是刻意的：**先替换，再预检，最后重载**。
//
// 直觉上似乎该先预检再替换，但 nginx -t 读的是配置里写死的那个路径——
// 新证书还躺在 .new 里时，预检验的仍是旧文件，等于没验。
// 而替换磁盘文件对正在运行的 nginx 是安全的：它用的是内存里已加载的证书，
// 只有 reload 才会重新读盘。因此把替换提前，预检才真正验到新证书；
// 任何一步失败都回滚，服务全程不受影响。
func Deploy(ctx context.Context, ex Executor, svc *Service, m *Material, timestamp string) (*DeployResult, error) {
	res := &DeployResult{Strategy: svc.WriteStrategy}
	step := func(f string, a ...any) { res.Steps = append(res.Steps, fmt.Sprintf(f, a...)) }

	certTarget, keyTarget, err := targetPaths(svc, m)
	if err != nil {
		return res, err
	}
	sudo := svc.WriteStrategy == WriteHostSudo

	// nginx 命令的权限与写文件的权限是两件事：证书目录常属于运维用户，
	// 而 master 进程是 root。
	testArgv, reloadArgv := svc.TestArgv, svc.ReloadArgv
	if svc.ReloadNeedsSudo {
		testArgv = sshx.WithSudo(testArgv)
		reloadArgv = sshx.WithSudo(reloadArgv)
	}

	rollback := func() bool {
		if _, err := runScript(ctx, ex, svc, rollbackScript,
			[]string{certTarget, keyTarget, timestamp}, sudo); err != nil {
			step("回滚失败，需要人工介入：%v", err)
			return false
		}
		res.RolledBack = true
		return true
	}

	// 1. 落临时文件
	if err := place(ctx, ex, svc, certTarget, m.FullChainPEM, sudo); err != nil {
		return res, fmt.Errorf("写入证书文件失败: %w", err)
	}
	if err := place(ctx, ex, svc, keyTarget, m.KeyPEM, sudo); err != nil {
		return res, fmt.Errorf("写入私钥失败: %w", err)
	}
	step("已写入临时文件 %s.new", certTarget)

	// 2. 原子替换（此时 nginx 仍在用内存里的旧证书，线上不受影响）
	owner, _ := NeedsChown(svc.ContainerUser)
	if _, err := runScript(ctx, ex, svc, commitScript,
		[]string{certTarget, keyTarget, timestamp, owner}, sudo); err != nil {
		return res, fmt.Errorf("替换证书文件失败: %w", err)
	}
	step("已原子替换并备份旧文件")

	// 3. 预检——这一步现在真正验证的是新证书
	if len(testArgv) > 0 {
		out, err := ex.Run(ctx, testArgv)
		if err != nil {
			rollback()
			return res, fmt.Errorf("执行预检命令失败: %w", err)
		}
		res.TestOutput = out.Combined()
		if out.ExitCode != 0 {
			if rollback() {
				step("预检未通过，已回滚到上一版证书；nginx 未重载，线上服务不受影响")
			}
			return res, fmt.Errorf("配置预检未通过（退出码 %d）：%s", out.ExitCode, out.Combined())
		}
		step("预检通过：%s", strings.Join(testArgv, " "))
	} else {
		step("该服务没有预检命令，重载失败时将自动回滚")
	}

	// 4. 重载
	out, err := ex.Run(ctx, reloadArgv)
	if err != nil || out.ExitCode != 0 {
		detail := "命令未能执行"
		if out != nil {
			detail = out.Combined()
		}
		if rollback() {
			// 回滚后再 reload 一次，让服务确实回到上一版证书。
			_, _ = ex.Run(ctx, reloadArgv)
			step("重载失败，已回滚到上一版证书")
		}
		return res, fmt.Errorf("重载 nginx 失败：%s", detail)
	}
	step("已重载：%s", strings.Join(reloadArgv, " "))

	// 5. 清理临时文件与过期备份（失败不影响部署结果）
	_ = cleanup(ctx, ex, svc, certTarget, keyTarget, sudo)
	return res, nil
}

// targetPaths 把服务视角的路径翻译成实际写入路径。
func targetPaths(svc *Service, m *Material) (cert, key string, err error) {
	// 辅助容器在容器内操作，用的就是容器内路径。
	if svc.WriteStrategy == WriteHelper {
		return m.CertPath, m.KeyPath, nil
	}
	if cert, err = svc.HostPathOf(m.CertPath); err != nil {
		return "", "", fmt.Errorf("证书路径 %s 无法映射到宿主机（%w），请为容器添加挂载或改用辅助容器策略",
			m.CertPath, err)
	}
	if key, err = svc.HostPathOf(m.KeyPath); err != nil {
		return "", "", fmt.Errorf("私钥路径 %s 无法映射到宿主机（%w）", m.KeyPath, err)
	}
	return cert, key, nil
}

// place 把内容写到目标旁边的 .new 文件。
//
// 统一用 base64 把内容作为「参数」传给一段固定脚本，而不是经 stdin 传内容——
// 脚本本身已经占用了 stdin，两者不能共用。代价是体积增加三分之一，
// 换来的是完全不必担心 PEM 里的换行、引号与元字符。
func place(ctx context.Context, ex Executor, svc *Service, target string, content []byte, sudo bool) error {
	args := []string{target, sshx.EncodeKey(content)}

	var (
		r   *sshx.Result
		err error
	)
	if svc.WriteStrategy == WriteHelper {
		argv := append(helperPrefix(svc), "sh", "-s", "--")
		argv = append(argv, args...)
		r, err = ex.PipeIn(ctx, argv, strings.NewReader(writeB64Script))
	} else {
		r, err = ex.RunScript(ctx, writeB64Script, args, sudo)
	}
	if err != nil {
		return err
	}
	if r.ExitCode != 0 {
		return fmt.Errorf("写入失败：%s", r.Combined())
	}
	return nil
}

// writeB64Script 用 base64 传内容，规避脚本与数据抢 stdin 的问题。
//
// 证书是 PEM 文本，base64 后体积增加三分之一，但换来的是
// 完全不用担心内容里的引号、换行与元字符。
const writeB64Script = `
set -eu
umask 077
dir=$(dirname "$1")
mkdir -p "$dir"
printf '%s' "$2" | base64 -d > "$1.new"
`

func runScript(ctx context.Context, ex Executor, svc *Service,
	script string, args []string, sudo bool) (*sshx.Result, error) {
	if svc.WriteStrategy == WriteHelper {
		argv := append(helperPrefix(svc), "sh", "-s", "--")
		argv = append(argv, args...)
		r, err := ex.PipeIn(ctx, argv, strings.NewReader(script))
		if err != nil {
			return nil, err
		}
		if r.ExitCode != 0 {
			return r, fmt.Errorf("脚本执行失败：%s", r.Combined())
		}
		return r, nil
	}
	r, err := ex.RunScript(ctx, script, args, sudo)
	if err != nil {
		return nil, err
	}
	if r.ExitCode != 0 {
		return r, fmt.Errorf("脚本执行失败：%s", r.Combined())
	}
	return r, nil
}

// helperPrefix 构造辅助容器的命令前缀。
//
// --volumes-from 继承 nginx 容器的全部挂载，镜像直接复用它自己的——
// 本来就在本地，零额外拉取。这条路径对 bind mount 与 named volume 一视同仁。
func helperPrefix(svc *Service) []string {
	image := svc.Image
	if image == "" {
		image = "alpine"
	}
	ref := svc.ContainerID
	if ref == "" {
		ref = svc.ContainerName
	}
	return []string{"docker", "run", "--rm", "-i", "--volumes-from", ref, image}
}

func cleanup(ctx context.Context, ex Executor, svc *Service, cert, key string, sudo bool) error {
	_, err := runScript(ctx, ex, svc, cleanupScript, []string{cert, key, "6"}, sudo)
	return err
}
