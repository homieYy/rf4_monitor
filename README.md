# RF4 Monitor — 被动采集版

本 fork 将原项目的 HTTPS/TCP 代理改为 **Npcap 只接收流量副本**。游戏直接连接原服务器，监控结果显示在独立控制台，也可导出 JSONL。

在另一台电脑继续排查 Windows 11 问题，请先阅读 [Win11 调试交接文档](HANDOFF_WIN11.md)，其中包含当前状态、验证边界、分层调试步骤和可复制给新 GPT 会话的提示词。

程序不修改 hosts、不安装证书、不改写登录响应、不转发或发送游戏数据、不访问游戏进程内存、不向游戏聊天框注入消息。

## 双击开始（推荐）

1. 下载本仓库 ZIP 并**完整解压**到一个文件夹，保留里面的 Python 文件和数据文件。
2. 双击 **`rf4_monitor.bat`**。首次启动自动创建 `.venv` 并安装 Python 依赖；缺少 Python 或 Npcap 时会打开官方下载页，安装完成后再次双击即可，无需输入命令。
3. 看到“**自动监控已就绪**”后，再启动并登录游戏。程序会自动识别游戏使用的网卡和服务器端口，显示识别结果后开始输出鱼情。
4. 以后每次只需双击同一个文件。若游戏已经登录，请重新登录一次，以便捕获完整握手。`Ctrl+C` 停止监控。

第一次安装 Python/Npcap 仍需完成官方安装向导（以及 Windows 的权限确认）。建议使用 64 位 Python 3.10 或更新版本；传统 Python 安装器中勾选 **Add Python to PATH**。Npcap 免费版不提供静默安装，本仓库不捆绑驱动，参见 [Npcap 安装说明](https://npcap.com/guide/npcap-users-guide.html)。无需安装 Wireshark。

`安装依赖.bat` 现在是可选的“仅准备/检查环境”入口。通常直接双击 `rf4_monitor.bat` 即可。后续启动只做本地检查，依赖清单变化或依赖缺失时才再次运行 pip。首次安装失败会保留错误窗口，修复网络或 Python 后重新双击重试。

若使用加速器/VPN，请先启动它，再双击监控。自动模式会尝试可用的 Npcap 网卡；至少一个接口必须能看到游戏原始 TCP 流。运行期间新增虚拟网卡、网卡被移除或切换网络后，请重启监控并重新登录游戏。

## 环境与手动安装

- Python 3.10 或更新版本。
- 实时监控：Windows + [Npcap](https://npcap.com/#download)。Npcap 需要单独安装，pip 不会安装驱动。仅安装 Npcap 即可，无需 Wireshark；不要使用旧 WinPcap。
- 离线回放和自动化测试：无需 Npcap，支持 Windows/Linux。

如需自行管理环境，可执行：

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

## 从旧版迁移

1. 关闭旧代理和游戏。
2. **手动恢复旧版修改的 hosts**：检查 `C:\Windows\System32\drivers\etc\hosts`，删除旧版 `RF4 MONITOR` / `RF4 MITM CHAT` 托管块，或恢复确认过的备份。也检查是否有手动添加的 `127.0.0.1 api.rf4game.ru` 条目；保留其他应用的配置。
3. 若域名缓存仍保留旧地址，可手动执行 `ipconfig /flushdns`。
4. 新版无需原项目的根证书。可在证书管理器中核对并移除当时为旧版导入的证书，不要删除其他证书。
5. 双击 `rf4_monitor.bat`，看到“自动监控已就绪”后再启动/重新登录游戏。

本程序不会自动执行上述系统修改。仓库删除了旧证书、hosts 示例和代理启动逻辑，Git 历史仍可查看旧实现。旧 `--set`、`--prepare-only` 等代理选项不再支持。

## 自动识别与高级选项

不带参数启动即自动模式，也可显式指定 `--auto`。默认查找 `rf4_x64.exe` 和 `rf4.exe`（不区分大小写），读取操作系统的进程名称及 TCP 连接归属，**不读取游戏内存、不向游戏注入任何组件**。

自动模式先开启网卡捕获，再每 250 毫秒查询游戏连接表。只有同时满足“属于游戏进程”和“完整 RF4 协议握手通过”的连接才进入业务监控；不会把游戏的 HTTPS 登录连接当作鱼情连接。端口从连接中自动取得，不限定为旧版 9341/9216。同一连接在多个网卡上出现时只选取其中一个副本。

为避免查询连接表时漏掉起始握手，自动模式会短暂缓存尚未确认归属的 TCP 流量副本：最多 128 条候选，每条最多 128 KiB（含计量开销）/512 包，最多等待 8 秒；未确认的数据不写文件、不输出内容。忙碌网络、进程权限不足、过短连接或握手过慢仍可能导致识别失败，需要重新登录；它不具备从已有连接中恢复解密状态的能力。

如果客户端进程文件名不同，可指定一次自己的快捷方式参数：

```powershell
.\rf4_monitor.bat --auto --process-name 实际游戏进程名.exe
.\rf4_monitor.bat --auto --jsonl fish-events.jsonl
```

自动模式下 `--port` 是可选的端口限制；通常不需要。手动指定网卡的方式仍保留用于排查：

```powershell
.\rf4_monitor.bat --list-interfaces
.\rf4_monitor.bat --iface 1
```

将 `1` 替换为实际联网网卡的编号，也可直接传入列表中的 `\Device\NPF_...` 设备名。使用加速器/VPN时，所选接口必须能看到游戏原始 TCP 流，而非隧道外层密文。

手动网卡模式和离线模式默认监控 TCP **9341 和 9216**；自动模式不限端口。手动模式可显式指定，重复参数表示多个端口：

```powershell
.\rf4_monitor.bat --iface 1 --port 9341
.\rf4_monitor.bat --iface 1 --port 9341 --port 9216 --telemetry none
.\rf4_monitor.bat --iface 1 --jsonl fish-events.jsonl
```

- Npcap 若安装为管理员专用模式，或提示不能读取游戏 TCP 连接表，请关闭窗口后右键 `rf4_monitor.bat` → “以管理员身份运行”。
- `--telemetry fish,player,feed` 是默认值。`none` 关闭附加遥测，来鱼、入护响应、频道事件仍输出。
- JSONL 文件必须尚不存在，防止覆盖以前的记录；只写业务事件，不写认证 token 或原始包。
- `Ctrl+C` 停止，输出采集统计。没有目标连接时检查网卡、端口和启动时机。
- 必须捕获连接起始 SYN、双向握手和认证数据；**不支持半途附加到已有连接**。

## 显示内容与准确性边界

保留鱼种中文映射、钓组 ID、鱼 ID、来鱼、入护响应、频道鱼获/聊天及原有坐标/搏鱼遥测。

```text
【我自己·来鱼】钓组=11111111-2222-3333-4444-555555555555 鱼=鲈鱼 预估重量=262 克
【我自己·入护响应】钓组=11111111-2222-3333-4444-555555555555 鱼=鲈鱼 重量=270 克
```

以上为合成示例，不是实际游戏采集结果。

- 钓组显示协议提供的 GUID，并不凭空推断它是游戏里的“1号/2号/3号竿”。
- 来鱼重量沿用原协议的 `weight_hint_raw`，显示为预估重量。
- 入护响应沿用上游的启发式字段提取。若只找到来鱼缓存重量，会标为预估值；**这不是对服务器成功入护状态的独立验证**。
- JSONL 的 `weight_source` 为 `setup_hint` 或 `response`，便于区分来源。
- 坐标/搏鱼遥测保留上游的部分启发式扫描，不应视为经过完整协议文档验证的字段。
- 目前只包含原项目 `4.0.24799` 协议配置。客户端更新后仍需实测核验。

## 离线回放与无需游戏的演示

读取具有完整连接起始阶段的 pcap 或 pcapng：

```powershell
.\rf4_monitor.bat --read recording.pcapng --jsonl events.jsonl
```

没有实际流量时，可生成仅包含虚构地址、标识和认证字符串的离线示例：

```powershell
.\.venv\Scripts\python.exe -m tests.make_demo demo.pcapng
.\rf4_monitor.bat --read demo.pcapng --jsonl demo-events.jsonl
```

示例生成器只写文件，不发送任何包。实际游戏抓包文件可能含认证信息，不应上传；pcap、pcapng、JSONL 已加入 `.gitignore`。

支持经典 pcap 大小端、微秒/纳秒时间戳，以及 pcapng Enhanced Packet Block、多接口和多 section。支持 Ethernet/VLAN、原始 IPv4/IPv6、Linux cooked v1/v2、NULL/LOOP 链路类型。pcapng Simple/旧 Packet Block 暂不支持，请导出为经典 pcap 或 Enhanced Packet Block 格式。

## 工作原理

```text
游戏客户端 <========== 原有 TCP 连接 ==========> 游戏服务器
                           |
                      Npcap 流量副本
                           |
                TCP 排序、去重、缺口和连接检查
                           |
                原协议握手、双向 RC4、业务拆帧
                           |
                 鱼情关联 -> 控制台 / JSONL
```

- 按连接和方向维护 TCP 序列号，处理分段、乱序、重传、部分重叠和 32 位回绕。
- 根据 TCP ACK 依赖安排跨方向交付，避免乱序导致入护响应先于对应请求被解析。
- 每个方向维护独立 RC4 状态；收到的数据只解密一次，不生成用于转发的密文。
- TCP ACK/FIN 的处理只发生在监控程序内部，**不会向网络发送 ACK、重传请求或任何业务包**。
- 发现冲突、截断、采集丢包、缺口超时或协议错误后停止解析相应连接，等待新 SYN；不跳过密文或猜测恢复状态。
- 采集丢包统计每秒检查一次。丢包发现前已经输出的事件不会自动撤回，出现警告时不能认为该时段的事件完整。
- 默认最多保留 32 条连接、每方向 1 MiB 乱序数据/2048 片段和 64 KiB 已交付历史；每方向协议缓冲 2 MiB；每个业务关联缓存 1024 项。缓存驱逐会给出提示。
- TCP 缺口/跨方向等待超过 10 秒、协议握手超过 30 秒会停止解析；空闲 120 秒清理连接。
- 超出历史窗口的旧重传只忽略已交付部分，不保证检测其内容冲突。
- 当前不重组 IP 分片。采集层发现无法安全归属的截断/分片时，会保守停止当前活动连接的解析。校验和不用于判断丢包，因为网卡 checksum offload 可能让本地副本的校验和尚未完成。

实时捕获使用非混杂模式和 IP/VLAN 捕获过滤器，再在本地筛选，以免端口级过滤漏掉分片或 IPv6 扩展头。自动模式的未确认流量仅存在于上述有界内存缓存中，不持久保存。多网卡自动捕获仍有 CPU/内存/驱动开销，不能宣称零影响或不会被反作弊识别。

## 测试

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m pytest -q
```

测试包括独立 RC4 已知向量、双鱼竿关联、入护重量来源、频道发送者关联、坐标、随机拆分/双向乱序/重传、序列回绕、半关闭/RST、截断文件、pcap/pcapng、IPv4/IPv6/VLAN、Npcap 接口模拟、驱动丢包报告及禁止主动传输 API 的结构检查。

GitHub Actions 在 Windows/Linux 和 Python 3.10/3.13 上运行离线测试及演示回放。模拟测试不等于真实驱动测试；本次改造尚未在真实 RF4 会话上验证，也没有反作弊兼容性或允许使用的保证。

退出码：`0` 正常处理；`1` 参数外的运行/文件/依赖错误；`2` 数据不完整、半途捕获、未发现目标连接，或 argparse 参数错误。

## 文件职责

| 文件 | 职责 |
|---|---|
| `rf4_monitor.py` | 参数、控制台和 JSONL 生命周期 |
| `rf4_capture.py` | Npcap 只读 API、严格的 pcap/pcapng 读取和链路解析 |
| `rf4_auto.py` | 游戏 TCP 连接归属、网卡/端口自动识别、有界候选缓存 |
| `bootstrap.py` | 双击入口的虚拟环境、依赖和驱动检查 |
| `rf4_stream.py` | TCP 重组、连接生命周期、RF4 握手和解密 |
| `rf4_protocol.py` | 从上游抽出的二进制协议解析 |
| `rf4_events.py` | 鱼情关联与中文显示 |
| `tests/` | 合成流量、自动化测试和离线演示生成器 |

原项目：[T3rry7f/rf4_monitor](https://github.com/T3rry7f/rf4_monitor)，协议解析基于提交 `98fee2e85e960e550d36e2465bba31c69e9a3543`。
