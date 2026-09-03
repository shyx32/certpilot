.PHONY: help genkey test build up down logs fmt

help:
	@echo "genkey  生成加密主密钥（写入 .env 的 CP_MASTER_KEY）"
	@echo "test    运行后端测试"
	@echo "build   构建两个镜像"
	@echo "up      启动三容器"
	@echo "down    停止"
	@echo "logs    跟踪日志"

genkey:
	@cd server && go run ./cmd/certpilot genkey

test:
	@cd server && go test ./... && go vet ./...

fmt:
	@cd server && go fmt ./...

build:
	docker compose build

up:
	docker compose up -d

down:
	docker compose down

logs:
	docker compose logs -f api
