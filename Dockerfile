# scanner-port: 端口扫描 Pod 镜像
# 构建上下文为本目录;Dockerfile 内部用 go mod init && go mod tidy 动态生成依赖。
# GitHub Actions(github-hosted ubuntu-latest)默认 GOPROXY=https://proxy.golang.org,direct 可直接拉取;
# 国内 self-hosted runner 或本地构建慢时,可解开下面的 ENV GOPROXY 一行切到 goproxy.cn。
#
# Pod 运行时支持下列环境变量(K8s Deployment 可通过 env 字段覆盖):
#   DAST_CONFIG       默认 /app/config/config.json   ConfigMap 挂载点
#   DAST_DB_USER      默认 root                       MySQL 账号
#   DAST_DB_PASS      代码默认 root                   MySQL 密码,可通过 ENV 覆盖
#   DAST_DB_NAME      默认 dast                       MySQL 数据库
#   DAST_REDIS_PASS   默认 redis                      Redis 密码(为空表示无密码)
# MySQL/Redis 地址、端口由 ConfigMap 中的 scheduler.internal_ip / mysql_port / redis_port 决定。

FROM golang:1.25-alpine AS builder
WORKDIR /src
# ENV GOPROXY=https://goproxy.cn,direct
COPY . .
RUN go mod init scanner-port \
 && go mod tidy \
 && CGO_ENABLED=0 GOOS=linux go build -o /out/scanner-port .

FROM alpine:latest
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=builder /out/scanner-port /app/scanner-port
ENV DAST_CONFIG=/app/config/config.json \
    DAST_DB_USER=root \
    DAST_DB_PASS=fupanC@123 \
    DAST_DB_NAME=dast \
    DAST_REDIS_PASS=redis \
    TZ=Asia/Shanghai
ENTRYPOINT ["/app/scanner-port"]
