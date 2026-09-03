# CertPilot

<p align="center">
  免费 SSL 证书的全生命周期托管：自动签发、自动续期、自动部署，<br>
  并且拨测确认线上<strong>真的</strong>换成了新证书。
</p>

<p align="center">
  <img alt="Go" src="https://img.shields.io/badge/Go-1.26-00ADD8?logo=go&logoColor=white">
  <img alt="React" src="https://img.shields.io/badge/React-19-61DAFB?logo=react&logoColor=black">
  <img alt="License" src="https://img.shields.io/badge/License-MIT-green.svg">
</p>

---

## 这个项目解决什么问题

证书自动化工具很多，但大多停在「签出来了」。而线上真正的故障往往是：

- 证书续期成功了，**CDN 上还是旧的** —— 因为 API 调用返回成功不等于边缘节点已生效
- 脚本跑了三个月，**没人记得它怎么工作** —— 换个人接手就不敢动
- 为了让脚本能改 DNS，给了它**一把能改全站解析的 AccessKey**
- 证书装上了但**漏了中间证书** —— 浏览器正常，App 报错，排查一整天

CertPilot 针对这些做了具体设计：流水线的终点是 `已生效`（外部拨测确认指纹一致）而不是 `已签发`；
接入时录入一次凭据就自动扫描出能管哪些域名，之后只需输入域名；
可以让系统自己创建最小权限的 RAM 子账号，管理凭据用完即焚。

## 特性

**签发与续期**
- ACME v2（基于 [lego](https://github.com/go-acme/lego)），支持 Let's Encrypt 等任意 ACME CA
- DNS-01 与 HTTP-01；通配符证书；一张 SAN 证书里的域名可以分属不同云账号
- DNS provider：阿里云、Cloudflare（均支持 zone 自动扫描）
- 到期前 30 天自动续期，续期时间按配置名哈希打散，避免同一分钟集中冲击 CA
- **持久化状态机**：进程重启后从断点续跑，而不是重新向 CA 申请一张

**DNS 账号自动识别**
- 录入凭据即扫描该账号下全部托管域名
- 输入域名后按最长后缀匹配自动选定账号，并算出 TXT 该写在哪个 zone 的哪条记录上
- 输入的当下就告诉你能不能签，而不是提交后看日志排查

**最小权限**
- 可用一次性的管理凭据自动创建 RAM 子账号：按勾选的能力生成最小策略，**创建前展示完整策略 JSON**
- 管理凭据不入库、不落盘、不进日志；任一步失败自动回滚已创建的资源
- 所有密钥信封加密（AES-256-GCM + 独立数据密钥），主密钥不在数据库里

**部署与验证**
- 阿里云 CDN（经 CAS 两段式：一次上传，多域名绑定，可回滚到上一个 CertId）
- **自建 Nginx（经 SSH）**：自动识别宿主机 systemd / 宿主机直管 / Docker 三种形态
- **Kubernetes Secret**：直接调 API Server，用指纹注解确认写入的确实是这一版
- **通用 Webhook**：没有内置支持的场景都有出路，支持 HMAC 签名与「不发送私钥」
- 部署后带重试窗口拨测，指纹一致才算完成
- 单个目标失败不影响其余目标

**服务器接入**
- 添加一台机器后一键探测：认出 nginx 形态、解析 Docker 挂载映射、选定写入策略
- `nginx -T` 反向发现配置里已有的证书与域名，接入时不必手工录入
- 「试运行」只跑预检命令，不碰任何证书文件——配置错误在这里就暴露
- 写入权限与重载权限**分别探测**：能写证书目录不代表能向 root 启动的 master 进程发信号

**巡检与告警**
- 每天拨测所有域名：到期、证书链完整性、域名匹配、协议版本，
  并与本地最新一版**比对指纹**——「续了但没生效」只有这一项能发现
- 支持「仅监控不管理」的域名：证书是别人签的，但到期前仍要有人知道
- 钉钉 / 企业微信 / 飞书 / 通用 Webhook；**发现汇总成一条消息**，不刷屏
- Prometheus 指标，可接入已有告警体系

**运维能力**
- **证书回滚**：新证书出问题时退回上一个已知可用的版本，不必等重新签发
- **AK 轮换**：建新 → 验证 → 换用 → 删旧，全程不中断
- **CA 配额自保护**：接近上限时主动停下并告警——撞上 CA 的墙会被锁一整周
- **只读分享看板**：给不需要登录后台的人看状态，不暴露任何运维细节
- **CLI**：`certpilot cli status` 有严重问题时退出码为 1，可直接用于流水线卡点

**使用体验**
- 一条 `docker compose up` 起步，三个容器
- WebSocket 实时推送执行日志（签发是 1–5 分钟的长流程，值得看得见）
- 明暗双主题

## 快速开始

```bash
git clone https://github.com/shyx32/certpilot.git
cd certpilot
cp .env.example .env
make genkey          # 把输出填进 .env 的 CP_MASTER_KEY
make up
```

打开 http://localhost:8088 。初始管理员密码在启动日志里，**只显示一次**：

```bash
docker compose logs api | grep -A3 初始管理员
```

### 接下来

1. **CA 账号** → 添加一个，首次建议选 Let's Encrypt staging 跑通全流程
2. **凭据** → 「自动创建子账号」，或手动录入已有的 AccessKey
3. **部署目标** → 添加阿里云 CDN，填上加速域名
4. **证书列表** → 输入域名，点「检查域名归属」确认能签，创建

> [!IMPORTANT]
> **主密钥丢失后，所有凭据与私钥都无法恢复。** 它不入库，请与数据库备份**分开存放**——
> 把密文和解密它的钥匙放在同一个地方，等于没加密。

## 架构

三个容器，没有 Redis，没有独立 worker 进程。这是按 **1000 个域名以内**的规模刻意做的取舍：
按该规模测算，每天只有约 17 个签发任务，拆进程只会增加运维面。

```
   ┌─────────┐   前端页面 + 反向代理，唯一对外
   │   web   │   nginx :80
   └────┬────┘
        │  /api  /ws  /.well-known/acme-challenge
   ┌────▼────┐   接口 + 调度 + 执行（同一进程，多 goroutine）
   │   api   │   Go :8080
   └────┬────┘
        │  队列用 SELECT … FOR UPDATE SKIP LOCKED
   ┌────▼────┐   独立数据卷，单独备份
   │   db    │   postgres:16
   └─────────┘
```

`api` 镜像同时提供 `serve` 与 `worker` 子命令。规模远超预期时，
在编排文件里加一个 `command: ["worker"]` 的服务即可拆开——**改的是编排，不是代码**。

### 部署到 Nginx

三种写入策略在探测阶段自动判定：

| 探测到 | 策略 |
| --- | --- |
| bind mount，SSH 用户可写 | 直写宿主机 |
| bind mount，属主 root | sudo 直写 |
| named volume / 自定义 driver | 辅助容器（`docker run --rm --volumes-from`） |

named volume 默认走辅助容器：`/var/lib/docker/volumes` 是 700 的 root 目录，
在 `docker` 组里意味着能指挥 daemon，并不意味着能用自己的身份读写它。

下发顺序是**先替换、再预检、最后重载**：`nginx -t` 读的是配置里写死的路径，
新证书还在 `.new` 里时预检验的仍是旧文件，等于没验。而替换磁盘文件对正在运行的
nginx 是安全的（它用内存里已加载的证书，只有 reload 才重新读盘），
所以把替换提前，预检才真正验到新证书；任何一步失败都回滚。

### 签发流水线

```
pending → preflight → ordering → challenging → validating
        → finalizing → issued → deploying → verified
```

终点是 `verified` 而不是 `issued`：CDN 有分钟级生效延迟，
`nginx -s reload` 可能因配置语法错误静默失败。没有这一步，
整套系统只是个「看起来在工作」的定时任务。

## 配置

| 环境变量 | 说明 |
| --- | --- |
| `CP_DB_DSN` | PostgreSQL 连接串，必填 |
| `CP_MASTER_KEY` | 加密主密钥，`make genkey` 生成，必填 |
| `CP_ADMIN_PASSWORD` | 初始管理员密码；不设则随机生成并打印到启动日志 |
| `CP_ACME_DIRECTORY` | 默认 Let's Encrypt 生产环境 |
| `CP_RUN_WORKER` | `serve` 是否同进程跑调度，默认 `true` |
| `CP_SCAN_INTERVAL` | 到期扫描周期，默认 `1h` |

巡检默认每天 04:00 跑一次，保留 90 天记录；任务日志保留 180 天。

## 安全

这个系统集中持有全站证书私钥与多个云账号密钥，本身就是最高价值的攻击目标。

- **接口默认全部需要登录**，没有「内网所以不设防」的例外
- 密钥信封加密，主密钥来自环境变量而非数据库
- 初始密码随机生成，**不存在 admin/admin 这样的默认口令**
- 凭据的写操作与 RAM 子账号创建限管理员角色
- 敏感操作写审计日志，但绝不记录凭据本身

即便如此，**请不要把管理端口直接暴露在公网**，建议置于内网或 VPN 之后。

### 推荐做法：CNAME 委派

给平台一个能改生产 DNS 的 AccessKey，意味着它泄露就能劫持全站流量。
在生产域名上一次性加一条 CNAME，把验证委派到专用区：

```
_acme-challenge.example.com.  CNAME  example-com.acme-dv.your-zone.com.
```

之后 CertPilot 只需要对 `acme-dv.your-zone.com` 有写权限——
即使凭据泄露，能改的也只是一个没有业务流量的验证区。

### 推荐做法：HTTP-01 集中验证

在业务服务器的 Nginx 上一次性加一段配置：

```nginx
location ^~ /.well-known/acme-challenge/ {
    return 301 http://acme.your-domain.com$request_uri;
}
```

ACME 规范允许验证时跟随重定向，所以之后所有域名的 HTTP-01 验证
都由 CertPilot 直接应答，**续期路径上不再需要登录任何目标机器**。

## 开发

```bash
make test                    # go test + go vet
cd server && go test -race ./...
cd web && npm run dev        # 前端开发服务器，自动代理 /api 与 /ws
```

针对真实 SSH 目标机的集成测试见 [test/README.md](test/README.md)。

```
server/                      Go 后端
  internal/
    secretbox/               信封加密
    dnsx/                    域名 → DNS zone 的最长后缀匹配
    acme/                    ACME 客户端与错误翻译
    aliyun/                  阿里云凭据、RAM 策略与子账号创建
    pipeline/                签发流水线状态机
    sshx/                    SSH 连接、shell 转义、命令执行
    nginxsvc/                nginx 形态探测、挂载映射反查、证书下发
    health/                  TLS 拨测与证书判读
    notify/                  通知渠道与告警合并
    cli/                     命令行客户端
    provider/dns|deploy/     DNS 与部署适配器（注册表模式）
    scheduler/               到期扫描与任务执行
    store/                   数据访问与迁移
    httpapi/                 REST + WebSocket
web/                         React + shadcn/ui + Vite
```

新增一家云只需实现 `Deployer` 接口的三个方法：`Validate` / `Deploy` / `Verify`。
编排层里没有任何 `if aliyun` 的分支。

## CLI

走和界面完全相同的 HTTP 接口，因此权限校验与审计日志对它同样生效。

```bash
export CP_URL=http://localhost:8088 CP_PASSWORD=…

certpilot cli list      # 列出全部证书及剩余天数
certpilot cli status    # 巡检摘要；有严重问题时退出码为 1
certpilot cli issue 3   # 触发一次签发或续期
certpilot cli scan      # 触发一轮巡检
```

`status` 的退出码可以直接当流水线卡点用。

## 路线图

M1–M4 已完成：签发续期、SSH 与 nginx 部署、巡检告警、回滚与轮换。

后续可做：腾讯云 / 华为云 DNS、SLB / OSS 部署、多 CA 故障转移、
CNAME 委派向导、更细的 RBAC。

针对真实 SSH 目标机的集成测试见 [test/README.md](test/README.md)。

## License

MIT
