// Package config 集中读取运行配置。全部来自环境变量，便于容器化部署。
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	Addr          string
	DatabaseDSN   string
	MasterKey     string
	ACMEDirectory string
	// RunWorker 为 false 时只提供 HTTP 服务，调度与执行交给独立的 worker 进程。
	// 默认同进程运行——按测算，这个规模不需要拆。
	RunWorker    bool
	ScanInterval time.Duration
}

const LetsEncryptProd = "https://acme-v02.api.letsencrypt.org/directory"

// Load 读取配置并校验必填项。
func Load() (*Config, error) {
	c := &Config{
		Addr:          env("CP_ADDR", ":8080"),
		DatabaseDSN:   os.Getenv("CP_DB_DSN"),
		MasterKey:     os.Getenv("CP_MASTER_KEY"),
		ACMEDirectory: env("CP_ACME_DIRECTORY", LetsEncryptProd),
		RunWorker:     envBool("CP_RUN_WORKER", true),
		ScanInterval:  envDuration("CP_SCAN_INTERVAL", time.Hour),
	}
	var errs []error
	if c.DatabaseDSN == "" {
		errs = append(errs, errors.New("CP_DB_DSN 未设置"))
	}
	if c.MasterKey == "" {
		errs = append(errs, errors.New("CP_MASTER_KEY 未设置（用 `certpilot genkey` 生成一把，并离线备份）"))
	}
	return c, errors.Join(errs...)
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envBool(k string, def bool) bool {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

func envDuration(k string, def time.Duration) time.Duration {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}

func (c *Config) String() string {
	return fmt.Sprintf("addr=%s worker=%t scan=%s acme=%s", c.Addr, c.RunWorker, c.ScanInterval, c.ACMEDirectory)
}
