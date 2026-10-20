#!/usr/bin/env bash
# ARTEX 安装脚本：① 全部 Docker（本地构建镜像）  ② 本地编译运行
set -euo pipefail
cd "$(cd "$(dirname "$0")" && pwd)"

info(){ printf '\033[36m[*]\033[0m %s\n' "$*"; }
ok(){   printf '\033[32m[+]\033[0m %s\n' "$*"; }
warn(){ printf '\033[33m[!]\033[0m %s\n' "$*"; }
die(){  printf '\033[31m[x]\033[0m %s\n' "$*" >&2; exit 1; }
ask(){  local p="$1" d="${2:-}" a; read -rp "$p${d:+ [$d]}: " a; echo "${a:-$d}"; }
rand(){ head -c 18 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 24; }

# ── docker 环境检测 / 自动安装 ───────────────────
ensure_docker(){
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    ok "已检测到 docker 与 docker compose"; return
  fi
  warn "未检测到 docker / docker compose"
  case "$(uname -s)" in
    Linux)
      if [ "$(ask '自动安装 Docker? (y/n)' y)" = y ]; then
        curl -fsSL https://get.docker.com | sh
        sudo usermod -aG docker "$USER" || true
        ok "Docker 安装完成（用户组变更需重新登录后免 sudo）"
      else
        die "请自行安装 docker 后重试"
      fi ;;
    Darwin) die "macOS 请安装 Docker Desktop：https://www.docker.com/products/docker-desktop/" ;;
    *)      die "请自行安装 docker 后重试" ;;
  esac
}

# ── ① 全部 Docker ───────────────────────────────
# 本分支默认本地构建镜像，避免 docker compose pull 拉到不含本分支改动的上游镜像。
host_arch(){
  case "$(uname -m)" in
    x86_64|amd64) echo amd64 ;;
    arm64|aarch64) echo arm64 ;;
    *) echo amd64 ;;
  esac
}

# 构建镜像所需的 Linux 单二进制 dist/<arch>/artex；缺 go/npm 时返回 1。
build_linux_binary(){
  local arch="$1"
  command -v go >/dev/null 2>&1 || return 1
  command -v npm >/dev/null 2>&1 || return 1
  info "未找到 dist/${arch}/artex，尝试从源码构建（可能需要几分钟）…"
  ( cd web && npm ci && npm run build:static )
  rm -rf server/webui/dist && cp -r web/out server/webui/dist
  CGO_ENABLED=0 GOOS=linux GOARCH="${arch}" \
    go build -tags embedui -trimpath -o "dist/${arch}/artex" ./cmd/artex
}

install_docker(){
  ensure_docker
  if [ ! -f .env ]; then
    cp .env.example .env 2>/dev/null || true
    local pw key
    pw="$(ask 'Postgres 密码（回车随机生成）' "$(rand)")"
    key="$(ask 'ANTHROPIC_API_KEY（可留空，后续在 UI 配）' '')"
    sed -i.bak "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=${pw}|" .env
    sed -i.bak "s|^ANTHROPIC_API_KEY=.*|ANTHROPIC_API_KEY=${key}|" .env
    rm -f .env.bak
    ok "已生成 .env（POSTGRES_PASSWORD 已设置）"
  else
    info "沿用已存在的 .env"
  fi

  local arch tag="local"
  arch="${TARGETARCH:-$(host_arch)}"
  if grep -q '^ARTEX_TAG=' .env; then
    sed -i.bak "s|^ARTEX_TAG=.*|ARTEX_TAG=${tag}|" .env && rm -f .env.bak
  else
    printf '\nARTEX_TAG=%s\n' "$tag" >> .env
  fi
  ok "ARTEX_TAG=${tag}（使用本地构建的镜像）"

  if [ ! -f "dist/${arch}/artex" ]; then
    build_linux_binary "$arch" || true
  fi
  if [ -f "dist/${arch}/artex" ]; then
    info "本地构建镜像 autumn27/artex:${tag} …"
    docker build --build-arg TARGETARCH="${arch}" -t "autumn27/artex:${tag}" .
  else
    warn "未找到 dist/${arch}/artex，无法本地构建镜像。"
    info "请先按 README「快速开始（本分支）」准备二进制，例如："
    info "  CGO_ENABLED=0 GOOS=linux GOARCH=${arch} go build -tags embedui -o dist/${arch}/artex ./cmd/artex"
    if [ "$(ask '仍要拉取上游镜像（不包含本分支改动）? (y/n)' n)" = y ]; then
      docker compose pull artex || true
    else
      die "已取消：请先构建 dist/${arch}/artex，或在有网环境执行 docker build。"
    fi
  fi

  info "启动…"
  docker compose up -d
  ok "启动完成 → http://localhost:8787"
  info "查看日志：docker compose logs -f artex"
}

# ── ② 本地编译运行 ──────────────────────────────
install_local(){
  echo "数据库安装方式："
  echo "  1) 连接已有 PostgreSQL"
  echo "  2) 用 Docker 起一个 PostgreSQL（需要 docker）"
  case "$(ask '选择' 1)" in
    2)
      ensure_docker
      local pw; pw="$(ask 'Postgres 密码（回车随机）' "$(rand)")"
      docker run -d --name artex-pg -p 5432:5432 \
        -e POSTGRES_USER=artex -e POSTGRES_PASSWORD="$pw" -e POSTGRES_DB=artex \
        -v artex-pg:/var/lib/postgresql/data postgres:16-alpine
      DB_HOST=127.0.0.1 DB_PORT=5432 DB_USER=artex DB_PASS="$pw" DB_NAME=artex DB_SSL=disable ;;
    *)
      DB_HOST="$(ask '数据库地址' 127.0.0.1)"
      DB_PORT="$(ask '端口' 5432)"
      DB_USER="$(ask '账号' artex)"
      DB_PASS="$(ask '密码' '')"
      DB_NAME="$(ask '数据库名' artex)"
      DB_SSL="$(ask 'sslmode (disable/require)' disable)" ;;
  esac

  # 生成 config.json
  cat > config.json <<JSON
{
  "database": {
    "host": "${DB_HOST}",
    "port": ${DB_PORT},
    "user": "${DB_USER}",
    "password": "${DB_PASS}",
    "dbname": "${DB_NAME}",
    "sslmode": "${DB_SSL}"
  }
}
JSON
  ok "已生成 config.json"

  # go 环境检查
  command -v go >/dev/null 2>&1 || die "未检测到 Go，请先安装 Go（>=1.26）：https://go.dev/dl/"
  ok "Go: $(go version)"

  # 内嵌前端需要 node 出静态产物
  if command -v npm >/dev/null 2>&1; then
    info "构建前端静态产物…"
    ( cd web && npm ci && npm run build:static )
    rm -rf server/webui/dist && cp -r web/out server/webui/dist
    info "编译内嵌单二进制…"
    CGO_ENABLED=0 go build -tags embedui -trimpath -o artex ./cmd/artex
  else
    warn "未检测到 npm：将编译**不内嵌前端**的后端（前端需另跑 npm run dev）"
    CGO_ENABLED=0 go build -o artex ./cmd/artex
  fi
  ok "编译完成 → ./artex"

  info "启动…（Ctrl-C 退出）"
  ./artex
}

echo "=============================="
echo "  ARTEX 安装"
echo "  1) 全部 Docker 安装（本地构建镜像）"
echo "  2) 本地运行（go 编译）"
echo "=============================="
case "$(ask '选择' 1)" in
  1) install_docker ;;
  2) install_local ;;
  *) die "无效选择" ;;
esac
