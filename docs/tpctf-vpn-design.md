# TPCTF 赛题专属 WireGuard VPN 容器化隔离设计（v0.8.1）

> 分支说明：本特性开发在独立 `tpctf` 分支上，版本标识为 `v0.8.1`。本文档记录完整设计方案、代码变更清单与后续按需回滚 / 拆卸指南。

## 1. 背景与需求

TPCTF 2026 人机协同赛道（初选赛阶段）采用“**一题一 WireGuard 配置文件（`ctfy-*.conf`）**”的 VPN 隔离接入机制：
- 每道题目分配独立的 WireGuard 隧道与内网网段（例如 `Address = 172.17.112.254/32`、`DNS = 172.17.112.3, 1.1.1.1, 8.8.8.8`、`AllowedIPs = 172.17.112.0/24`、`Endpoint = node7.tpctf.ctfy.run:44749`）。
- 题目服务域名通常为内网域名（如 `*.internal`），且反弹 Shell / 带外回连使用 `ctfy-callback:<port>`（转发到当前隧道 IP `172.17.112.254`）。

核心设计目标：
1. **宿主机零代理、零 WireGuard 客户端**：所有流量均在 Docker 容器网络命名空间内走 WireGuard 隧道，宿主机无需挂全局 VPN 或代理。
2. **多任务同网段并行互不冲突**：不同题目即使使用完全重叠的客户端 IP（如都是 `172.17.112.254/32`）和内网 DNS（`172.17.112.3`），也互不干扰。
3. **工具容器安全加固不降级**：`artex-ctf-*` 工具容器继续保持 `User: 1000:1000`、`ReadonlyRootfs: true`、`CapDrop: ["ALL"]`、`CapAdd: ["SYS_PTRACE"]`。
4. **规避 Docker 默认网段冲突**：Docker 默认 `bridge` 使用 `172.17.0.0/16`，直接冲突 `172.17.112.0/24`，必须让 VPN 容器运行在非冲突网段（默认 `10.220.0.0/16`）。

---

## 2. 总体架构（Per-Task WireGuard Sidecar 模式）

```text
+-----------------------------------------------------------------------+
| Host / WSL2 Kernel (wireguard.ko + /dev/net/tun)                      |
|                                                                       |
|  Docker Bridge Network: artex-ctf-vpn (10.220.0.0/16, 非 172.17.x)    |
|    │                                                                  |
|    ├─► [Sidecar Container: artex-ctf-wg-<taskID>]                     |
|    │     • Image: autumn27/artex-ctf-wg:0.8.1                         |
|    │     • CapAdd: NET_ADMIN, SYS_MODULE + /dev/net/tun               |
|    │     • eth0 (10.220.0.x) ──UDP──► node7.tpctf.ctfy.run:44749      |
|    │     • wg0 (172.17.112.254/32) ──► 172.17.112.0/24                |
|    │     • /etc/resolv.conf ──► 172.17.112.3 (*.internal + callback)  |
|    │                                                                  |
|    └─◄ NetworkMode: container:<artex-ctf-wg-<taskID>>                 |
|        [Tool Container: artex-ctf-<taskID>-<intent>-<hash>]           |
|          • User 1000:1000 / ReadonlyRootfs / CapDrop ALL + SYS_PTRACE |
|          • /work 挂载持久卷（更换/关闭 VPN 不丢失解题进度）            |
|          • ctf_http / ctf_probe_target / pwntools / curl 直连隧道      |
+-----------------------------------------------------------------------+
```

### 关键机制说明

1. **隔离网络（`artex-ctf-vpn`）**  
   `ctfrunner.Engine.EnsureVPNNetwork` 自动按需创建名为 `artex-ctf-vpn`（环境变量 `ARTEX_CTF_VPN_NETWORK` 可配）、网段 `10.220.0.0/16`（`ARTEX_CTF_VPN_SUBNET` 可配）的独立桥接网络，彻底避开 Docker 默认 `172.17.0.0/16`。
2. **Sidecar 启动与 DNS 时序**  
   - `docker/ctf-wg/entrypoint.sh` 启动时**先执行 `wg-quick up /run/wg/wg0.conf`**，使用 Docker 默认 DNS 解析 `node7.tpctf.ctfy.run` 建立隧道对端连接；
   - 建立 `wg0` 后再以**原位覆写（truncate 重写）**更新 bind-mounted `/etc/resolv.conf`，将 `.conf` 中的题目 DNS（如 `172.17.112.3`）置于最前；
   - 通过 `NetworkMode: "container:<wg_id>"` 共享网络命名空间的工具容器可自动继承 `wg0` 网卡、路由与 `/etc/resolv.conf`，直接解析 `*.internal` 并监听本地端口接收 `ctfy-callback` 回连。
3. **配置换新与热重建**  
   - `artex-ctf-*` 容器绑定 `artex.ctf.vpn=<sha256>` 与 `artex.ctf.wg_id=<containerID>` 标签；
   - 当用户更换或删除 `.conf` 时，`ctfrunner` 仅删除重建对应的 Sidecar 与工具容器，**完整保留 `<session>-work` 数据卷与 `/work/.inputs`、解题脚本**。
4. **安全策略**  
   - **`ctfrunner.ParseWireGuardConfig`** 仅白名单允许：
     - `[Interface]`：`PrivateKey`（校验 32 字节 Base64）、`Address`、`DNS`（严格校验 IP，防 `resolv.conf` 注入）、`MTU`；
     - `[Peer]`：`PublicKey`、`PresharedKey`、`Endpoint`、`AllowedIPs`、`PersistentKeepalive`。
   - **显式拒绝** `PreUp` / `PostUp` / `PreDown` / `PostDown` / `SaveConfig` / `Table` 等可触发命令执行或篡改路由表的危险字段，最大体积限制 `64 KiB`。
   - `PrivateKey` 仅保存在 PostgreSQL `tasks.ctf_vpn_config` 与运行时按需以 Docker Archive TAR（`0600`）投递至 Sidecar 内存/rootfs，**绝不写入 `/state/*.json`、Agent `/work/.inputs`、Prompt 上下文、TaskDTO 或任何 GET API 响应**。

---

## 3. 数据库、接口与前后端改造

- **PostgreSQL Schema (`db/schema.sql`)**：
  - `tasks` 表幂等新增三列：`ctf_vpn_config TEXT`、`ctf_vpn_hash TEXT`、`ctf_vpn_filename TEXT`。
  - `db/task_archives_restore.go` 在还原旧版冷归档快照时兼容默认值（`COALESCE(..., '')`）。
- **后端 HTTP API (`server/ctf_vpn.go`, `server/server.go`)**：
  - `POST /api/tasks` 新增可选参数 `ctf_vpn_config`、`ctf_vpn_filename`（仅 `mode === "ctf"` 有效），建任务前校验并在 Runner 就绪时自动预热拉起 Sidecar。
  - `GET /api/tasks/{id}/ctf/vpn`：返回脱敏摘要（`VPNSummary`）与实时 Sidecar 探测状态（`TunnelIP`、最近握手时间、流量统计）。
  - `PUT /api/tasks/{id}/ctf/vpn`：支持 `multipart/form-data`（`file` 字段）或 JSON（`{filename, content}`）上传/更换配置并立即同步 Sidecar。
  - `POST /api/tasks/{id}/ctf/vpn/check`：显式拉起并检查 WireGuard Sidecar 健康状态。
  - `DELETE /api/tasks/{id}/ctf/vpn`：清空配置并销毁对应 `artex-ctf-wg-<taskID>` Sidecar。
  - 删除任务时（`Manager.DeleteTask` -> `ctf.Service.CleanupTask` -> `DELETE /tasks/{id}`）联动销毁任务全部 CTF 容器、VPN Sidecar 与工作卷。
- **Agent 上下文 (`agent/task_inputs.go`)**：
  - 启用 VPN 时向 Planner / Worker 注入只读脱敏提示：配置文件名、隧道 IP、`DNS`、允许网段与 `ctfy-callback:<端口>` 回连提示。
- **前端界面 (`web/src/components/ctf-vpn-config.tsx`)**：
  - **新建任务抽屉**：选择 CTF 模式时出现「赛题专属 WireGuard VPN（可选）」，支持选择 `.conf` 文件或粘贴文本，实时本地解析预览非敏感摘要；
  - **任务详情「附件与产物」标签页**：集成 `CTFVpnConfig` 管理卡片，支持上传/更换 `.conf`、一键「检查 / 拉起隧道」、实时显示隧道 IP/握手/流量及 Sidecar 异常提示、移除 VPN。
  - **任务列表卡片 & 详情头部**：展示脱敏 `VPN` 标识徽章。

---

## 4. 新增与修改文件清单

### 新增文件
- `Dockerfile.ctf-wg` — WireGuard Sidecar 轻量镜像定义（基于 `python:3.12-slim-bookworm` + `wireguard-tools`、`iproute2`、`iptables`）
- `docker/ctf-wg/entrypoint.sh` — Sidecar 启动/DNS 热写/信号退出清理脚本
- `ctfrunner/vpn.go` & `ctfrunner/vpn_test.go` — 严格 WireGuard 配置解析器、安全白名单与单元测试
- `ctfrunner/vpn_engine.go` — Sidecar 容器生命周期管理、隔离网段 `artex-ctf-vpn`、`/tasks/{id}/vpn` Runner HTTP 路由
- `ctfrunner/vpn_client.go` — `ctfrunner.Client` VPN/Cleanup HTTP 客户端方法
- `ctf/vpn.go` — `ctf.Service` 的会话 `SessionSpec` VPN 状态拼接与任务清理方法
- `server/ctf_vpn.go` & `server/ctf_vpn_test.go` — 后端 `/api/tasks/{id}/ctf/vpn*` 接口与单元测试
- `web/src/components/ctf-vpn-config.tsx` — 前端新建与详情页 VPN 配置管理组件
- `docs/tpctf-vpn-design.md` — 本设计说明文档

### 修改文件
- `ctfrunner/engine.go` & `ctfrunner/server.go` — 支持 `EnsureSession` 与 `SessionSpec.VPNHash`，按 VPN 变化自动切换 `NetworkMode: "container:<wg_id>"`
- `ctf/service.go` — `prepareSession` 自动同步任务 VPN 并传递 `VPNHash`
- `agent/task_inputs.go` — 注入脱敏的 VPN 与 `ctfy-callback` 上下文说明
- `db/schema.sql`, `db/tasks.go`, `db/task_mode.go`, `db/task_archives_restore.go` — 任务级 VPN 持久化列与归档还原兼容
- `server/manager.go`, `server/dto.go`, `server/server.go` — 任务生命周期镜像、创建/删除联动与 HTTP 路由注册
- `web/src/lib/types.ts`, `web/src/lib/api.ts`, `web/src/app/(main)/function/tasks/page.tsx`, `web/src/app/(main)/function/tasks/detail/page.tsx` — 类型、API 与 UI 接入
- `web/src/config/app-config.ts`, `web/package.json`, `CHANGELOG.md`, `README.md`, `build.sh`, `docker-compose.ctf-preview.yml` — 版本升级至 `v0.8.1`

---

## 5. 后续如需移除 / 回滚指南

由于 `tpctf` 特性完全收敛在独立分支及明确文件中，如果赛后无需保留该功能，可按以下两种方式干净移除：
1. **Git 分支隔离回退（推荐）**：直接切回上游特性分支（如 `feat/finding-review` 或 `main`），不要将 `tpctf` 合并即可；
2. **代码内局部拆卸（如需保留后续部分改动）**：
   - 删除本节「新增文件」中列出的全部文件；
   - 回退上述「修改文件」中对应增量改动（`db` 表上的三列可保留空默认值或仅停止读写，对现有业务零影响）；
   - 清理运行环境中创建的 Sidecar 容器与网络：
     ```powershell
     docker ps -aq --filter "label=artex.ctf.role=wg" | ForEach-Object { docker rm -f $_ }
     docker network rm artex-ctf-vpn
     ```
