# 构建阶段
#
# 缓存挂载让模块下载与编译结果跨构建复用：改一行代码不必重新拉取
# 全部依赖（阿里云 SDK 体积很大，没有缓存时每次都要几分钟）。
FROM golang:1.26-alpine AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/certpilot ./cmd/certpilot

# 运行阶段：distroless，没有 shell 可供攻击者利用
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/certpilot /certpilot
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/certpilot"]
CMD ["serve"]
