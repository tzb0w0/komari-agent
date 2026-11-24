# komari-agent（定制分支：线路识别 + TCP 重传采集）

Komari 的探针程序，运行在**每台被监控的服务器**上，定期向面板上报指标。

本分支在上游基础上新增：

- **自动识别出口线路**：探测本机出口 IP → 查 ASN → 按规则判定线路（CN2 GIA / 9929 / 4837 / CMIN / 163），随基础信息上报，**无需任何手动填写**
- **采集 TCP 重传率**：读取 `/proc/net/snmp` 的 `TcpRetransSegs` / `OutSegs`，计算区间重传率并随指标上报
- **自动更新只跟随本分支**：避免被官方版本覆盖而丢失上述功能

> 原版 README 已移除，本文档为本分支唯一说明。服务端与前端见 [komari](https://github.com/tzb0w0/komari) / [komari-web](https://github.com/tzb0w0/komari-web)。

---

## 一、安装（推荐：面板一键命令）

1. 面板 → **设置** → 复制「自动发现密钥」（≥12 位）
2. 面板 → **服务器** → **自动发现** → 复制生成的命令
3. 粘贴到目标服务器执行

命令形如：

```bash
curl -fsSL https://raw.githubusercontent.com/tzb0w0/komari-agent/main/install.sh | bash -s -- \
  --auto-discovery "<自动发现密钥>" --endpoint "http://<面板IP>:25774"
```

执行后自动注册绑定，凭据写入二进制同目录的 `auto-discovery.json`，**不需要手动创建 token**。

默认安装位置：

| 项目 | 值 |
|---|---|
| 安装目录 | `/opt/komari`（二进制名 `agent`） |
| 服务名 | `komari-agent` |
| 非 root 安装 | `~/.local/share/komari`（Linux user service） |

---

## 二、手动安装

```bash
# 脚本安装（支持 --install-dir / --install-service-name / --install-version / --install-ghproxy）
curl -fsSL https://raw.githubusercontent.com/tzb0w0/komari-agent/main/install.sh | bash -s -- \
  --endpoint "http://<面板IP>:25774" --token "<TOKEN>"

# 或直接下载二进制（命名规则：komari-agent-<os>-<arch>[.exe]）
curl -fsSLO https://github.com/tzb0w0/komari-agent/releases/latest/download/komari-agent-linux-amd64
chmod +x komari-agent-linux-amd64
./komari-agent-linux-amd64 --endpoint "http://<面板IP>:25774" --auto-discovery "<密钥>"
```

**Release 提供的平台**（tag `v0.1.0-fork`）：

`linux` 386 / amd64 / arm / arm64 / loong64 · `windows` 386 / amd64 / arm64 · `darwin-arm64` · `freebsd` 386 / amd64 / arm64

---

## 三、参数

参数可通过**命令行 / 环境变量 / JSON 配置文件**传入（`--config-file` 指定配置文件）。

| 命令行 | 环境变量 | 说明 |
|---|---|---|
| `--endpoint` `-e` | `AGENT_ENDPOINT` | 面板地址 |
| `--token` `-t` | `AGENT_TOKEN` | 节点 token |
| `--auto-discovery` | `AGENT_AUTO_DISCOVERY_KEY` | 自动发现密钥（与 token 二选一） |
| `--interval` | `AGENT_INTERVAL` | 采集间隔（秒） |
| `--info-report-interval` | `AGENT_INFO_REPORT_INTERVAL` | 基础信息上报间隔（分钟，默认 5） |
| `--disable-auto-update` | `AGENT_DISABLE_AUTO_UPDATE` | 禁用自动更新 |
| `--disable-web-ssh` | `AGENT_DISABLE_WEB_SSH` | 禁用远程控制（Web SSH / RCE） |
| `--ignore-unsafe-cert` `-u` | `AGENT_IGNORE_UNSAFE_CERT` | 忽略证书错误 |
| `--max-retries` `-r` | `AGENT_MAX_RETRIES` | 最大重试次数（默认 3） |
| `--reconnect-interval` `-c` | `AGENT_RECONNECT_INTERVAL` | 重连间隔（秒） |
| `--include-nics` | `AGENT_INCLUDE_NICS` | 仅统计指定网卡（逗号分隔，支持通配符） |
| `--exclude-nics` | `AGENT_EXCLUDE_NICS` | 排除指定网卡 |
| `--include-mountpoints` | `AGENT_INCLUDE_MOUNTPOINTS` | 磁盘统计的挂载点（分号分隔） |
| `--month-rotate` | `AGENT_MONTH_ROTATE` | 流量统计的月份重置日（0 禁用） |
| `--enable-gpu` | `AGENT_ENABLE_GPU` | 启用详细 GPU 监控 |
| `--prefer-ip-version` | `AGENT_PREFER_IP_VERSION` | 连接面板优先 IP 版本：4 或 6 |
| `--custom-dns` | `AGENT_CUSTOM_DNS` | 自定义 DNS |
| `--host-proc` | `HOST_PROC` | 容器内监控宿主机时，挂载的宿主机 `/proc` 路径 |

完整参数以 `./komari-agent --help` 为准。

---

## 四、自动更新

探针会从 **本仓库** 的 release 自动更新（`update.Repo` 已指向 `tzb0w0/komari-agent`），不会被官方版本覆盖。

如需关闭：

```bash
./komari-agent --endpoint ... --token ... --disable-auto-update
# 或 systemd 里加 Environment="AGENT_DISABLE_AUTO_UPDATE=true"
```

---

## 五、功能说明与限制

**线路识别**

| ASN | 判定线路 |
|---|---|
| 4809 / 4812 / 4816 | CN2 GIA |
| 9929 | 9929 |
| 4837 | 4837 |
| 58807 / 9808 | CMIN |
| 4134 | 163 |

识别结果缓存 30 分钟。需要本机能访问外网 CDN trace 端点（用于获取出口 IP），否则保持「未识别」。这只会影响线路名显示，不影响面板其他功能。

**TCP 重传率**

仅 **Linux** 可采集（读取 `/proc/net/snmp`）。macOS / Windows / FreeBSD 会自动降级为「不可用」，面板显示 `-`，不会报错。

---

## 六、从源码构建

```bash
# 本机平台
go build -o komari-agent .

# 交叉编译（无 CGO 依赖，可直接交叉）
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath \
  -ldflags="-s -w -X github.com/komari-monitor/komari-agent/update.CurrentVersion=v0.1.0-fork" \
  -o komari-agent-linux-amd64 .
```

若要构建整套系统（含服务端与前端），使用服务端仓库的一键脚本：
`curl -fsSL https://raw.githubusercontent.com/tzb0w0/komari/main/build-from-source.sh | bash`

---

## 七、常见问题

**Q：安装后面板没有线路 / 重传数据？**
- 确认装的是本分支版本（旧版二进制没有这些字段），可看 `./komari-agent --help` 是否有 `--auto-discovery`
- 非 Linux 系统没有重传数据（正常）
- 线路一直显示「检测中」：检查本机能否访问外网

**Q：报告 `Invalid AutoDiscovery Key`？**
密钥需 ≥12 位，且需与面板「设置」中的自动发现密钥完全一致。

**Q：一键脚本装上去还是官方版？**
`raw.githubusercontent.com` 分支 URL 有 CDN 缓存，更新后几分钟内可能仍是旧脚本，稍等重试即可。

---

## 八、许可证

MIT，见 [LICENSE](./LICENSE)。上游版权归 Komari Moniter 所有。
