# 使用官方 Go 镜像作为基础镜像
FROM golang:1.22 AS builder

ENV GOPROXY=https://mirrors.aliyun.com/goproxy/,direct
# 设置工作目录
WORKDIR /app
# 复制 go.mod 和 go.sum 文件并下载依赖
COPY go.mod go.sum ./
RUN go mod download

# 复制源码到容器
COPY . .

# 编译 Go 程序
RUN CGO_ENABLED=0 GOOS=linux go build -o goBlog .

# 使用更小的镜像来运行程序
FROM alpine:latest

# 安装必要的依赖（如 sqlite3）
RUN apk add --no-cache sqlite

# 设置工作目录
WORKDIR /app

# 从 builder 镜像中复制编译后的程序和配置文件
COPY --from=builder /app/goBlog /app/goBlog
COPY conf/ /app/conf/
COPY controllers/ /app/controllers/
COPY helpers/ /app/helpers/
COPY models/ /app/models/
COPY static/ /app/static/
COPY system/ /app/controllers/
COPY views/ /app/views/

# 暴露端口
EXPOSE 8090

# 设置启动命令
CMD ["./goBlog"]