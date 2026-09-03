# 集成测试

针对一台真实的 SSH + nginx 目标机跑通探测与部署，而不必准备一台机器。

`test/target` 是一台刻意配置成生产常见形态的容器：
`deploy` 用户能写证书目录，但 nginx 主进程以 root 运行——
**写文件不需要提权，重载需要**。这个组合曾经暴露过一个真实缺陷
（写入权限与重载权限被当成了同一件事）。

## 运行

```bash
# 1. 生成测试密钥
ssh-keygen -t ed25519 -N "" -f /tmp/cp_test_key -q

# 2. 起目标机
docker build -t certpilot-test-target ./test/target
docker run -d --name certpilot-target \
  -p 2222:22 -p 8443:443 \
  -e AUTHORIZED_KEY="$(cat /tmp/cp_test_key.pub)" \
  certpilot-test-target

# 3. 跑测试
#    CP_TEST_HTTPS_ADDR 让测试自己拨测线上端口，确认证书真的换了
cd server && CP_TEST_SSH_HOST=127.0.0.1 CP_TEST_SSH_PORT=2222 \
  CP_TEST_SSH_USER=deploy CP_TEST_SSH_KEY=/tmp/cp_test_key \
  CP_TEST_HTTPS_ADDR=127.0.0.1:8443 \
  go test -tags integration ./internal/nginxsvc/ -v

# 4. 清理
docker rm -f certpilot-target
```

## 覆盖的场景

| 测试 | 验证什么 |
| --- | --- |
| `SSHConnectAndFingerprint` | 连接建立，主机指纹可固化 |
| `QuotingAgainstRealShell` | **shell 元字符在真实 shell 上确实失去特殊含义**——单元测试只能证明转义函数的输出形状，这条才证明它在对端成立 |
| `Detect` | 形态识别、`nginx -T` 证书发现、写入策略与重载提权分别判定 |
| `DeployReplacesLiveCertificate` | 完整下发：写入 → 替换 → 预检 → 重载；**拨测确认线上真的换了新证书**；私钥权限 600，备份保留，临时文件清理 |
| `PreflightFailureLeavesLiveFileIntact` | 下发非法证书时预检拦下并回滚，nginx 从未重载 |

最后一条是这套测试最有价值的地方：它验证的是**失败路径**，
而失败路径恰恰是平时最难验、出事时最要命的部分。

## 一个踩过的坑

「线上是否真的换证」这条断言最初写在 CI 里、放在全部测试跑完之后，
结果时灵时不灵——因为 `PreflightFailureLeavesLiveFileIntact` 跑在部署测试之后，
它故意制造一次失败，最终的 nginx 内存状态就不再确定了。

断言要紧挨着它验证的行为。现在这条拨测在部署测试内部完成，
不受后续测试的副作用影响。
