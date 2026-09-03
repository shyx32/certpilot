# 构建阶段
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/certpilot ./cmd/certpilot

# 运行阶段：distroless，没有 shell 可供攻击者利用
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/certpilot /certpilot
COPY --from=build /src/internal/store/migrations /migrations
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/certpilot"]
CMD ["serve"]
