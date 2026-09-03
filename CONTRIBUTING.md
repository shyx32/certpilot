# 参与贡献

## 开发环境

需要 Go 1.26+、Node 22+、Docker。

```bash
cp .env.example .env
make genkey                  # 填进 .env
docker compose up -d db      # 只起数据库
cd server && go run ./cmd/certpilot migrate
cd server && go run ./cmd/certpilot serve
cd web && npm install && npm run dev
```

## 提交前

```bash
make test                    # go test + go vet
cd server && gofmt -l . && go test -race ./...
cd web && npx tsc --noEmit && npm run build
```

CI 会跑同样的检查，外加一轮针对真实 SSH + nginx 目标机的集成测试
（见 [test/README.md](test/README.md)）。

需要手工建用户或重置密码时，可以用这个辅助命令生成 bcrypt 哈希：

```bash
cd server && CP_HASH_PASSWORD='新密码' go test ./internal/auth/ -run TestGenerateHashForOps -v
```

## 分支命名

```
feat/<描述>    新功能
fix/<描述>     缺陷修复
docs/<描述>    文档
ci/<描述>      流水线与构建
chore/<描述>   杂项维护
```

## 代码约定

- **注释写「为什么」，不写「做了什么」。** 代码已经说明了做什么。
- **错误信息面向使用者。** 说清楚发生了什么、下一步怎么办；
  不要把 SDK 的原始错误（含 RequestId、响应头）直接抛给用户——
  参考 `internal/aliyun/errors.go` 与 `internal/acme/errors.go`。
- **敏感信息永不进日志。** 凭据、私钥、主密钥一律不得出现在 `slog` 调用里。
- **新增 provider 用注册表模式。** 在 `init()` 里 `Register`，不要在编排层加分支。

## 新增一个部署目标

实现 `deploy.Deployer` 的三个方法：

```go
Validate(ctx) error              // 保存配置时校验，无副作用
Deploy(ctx, *Bundle) error       // 下发证书，必须幂等
Verify(ctx, *Bundle) error       // 确认线上确实换了这张证书
```

`Verify` 不是可选的——它是流水线能走到 `verified` 的唯一依据。
如果目标有生效延迟，再实现 `WindowHinter` 返回合适的重试窗口。

## 新增一个 DNS provider

实现 `dns.Provider`（`Present` / `CleanUp`）。
如果该厂商支持列举托管域名，再实现 `dns.ZoneLister` —— 这样用户就能享受
「录入凭据即自动识别可管理域名」，而不必手工选账号。
