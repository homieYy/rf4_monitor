# RF4 Monitor：Windows 11 调试交接

交接日期：2026-10-22（Asia/Hong_Kong）。面向在另一台电脑上接手的 GPT/Codex 会话。

**当前任务是定位并修复用户在 Windows 11 上的启动或运行失败。失败尚未复现，具体报错尚未取得；不能把依赖官方支持 Win11 当作本项目已在 Win11 联机验证通过。**

## 1. 接手后的第一步

先阅读本文、[README.md](README.md)、[VALIDATION.md](VALIDATION.md)，然后检查当前 Git 状态和源码。不要重新执行旧版代理的安装、证书或 hosts 修改流程。

用户希望最终达到：**完整解压后双击启动，自动准备依赖、自动识别游戏网卡和端口，显示钓组、鱼种、重量等信息。** 调试阶段可以使用命令，但最终普通使用不应要求每次输入命令。

本次用户反馈原话：“该脚本需要运行于 win11 我昨天测试了 win11 不支持你使用的工具”。之后要求核查工具及依赖的 Win11 支持情况。尚未提供错误文字、截图、失败阶段、CPU 架构、Python/Npcap 实际版本。请在目标机器上取得这些证据，不要把“装错了 WinPcap”“ARM 不兼容”“权限不足”等猜测写成已确认根因。

当前会话仅完成兼容性资料核查，**没有为该反馈实施新的兼容性代码修复**。本文及 README 入口属于交接文档更新。

## 2. 仓库、提交与授权背景

| 项目 | 值 |
|---|---|
| 用户仓库，后续修改的目标 | https://github.com/homieYy/rf4_monitor |
| 用户仓库交付分支 | `main` |
| 上游，仅用于参考 | https://github.com/T3rry7f/rf4_monitor |
| 上游参考提交 | `98fee2e85e960e550d36e2465bba31c69e9a3543` |
| 被动捕获重构 | `6633e5140b31fe704da482bb643f6fd07dd8970e` |
| 自动识别及双击启动的代码基线 | `c3a9275de49c254c83030d2f30dc70fe1609a447` |

本文写入时，远端 `main` 的代码基线已核实为 `c3a9275`。本文的文档提交会在其后；接手时重新确认远端最新状态。

用户此前已要求修改完成后推送自己的 GitHub。继续调试时保留他人改动，不强制推送；不要向上游仓库推送。新电脑的 GitHub 身份验证需单独确认，不能假设旧电脑的凭据已迁移，也不要要求用户将令牌发到聊天或写进仓库。

旧电脑本地曾使用 `feat/passive-npcap` 分支，并将其 HEAD 正常推送到用户仓库 `main`。新电脑直接从 `origin/main` 接手即可；不依赖旧电脑的绝对路径、本地虚拟环境或合成样本。

## 3. 必须保留的设计边界

- 当前已选定 Npcap 被动捕获方案；最初讨论过读内存，但没有实现该方案。
- 游戏直接连接原服务器。监控只读取流量副本，不代理、不改包、不发包、不改传输路径。
- 不读写游戏进程内存、不注入 DLL/代码、不向游戏聊天框注入结果。psutil 只用于进程名称与操作系统 TCP 连接表查询。
- 不自动修改 hosts、安装根证书、关闭防护或绕过反作弊。旧版遗留配置按 README 单独核对。
- Npcap 驱动需官方安装器；pip 只安装 Python 包。免费 Npcap 不提供 OEM 静默安装能力，仓库没有捆绑驱动。
- 不承诺零性能开销、反作弊允许使用或不会被检测。
- 实际抓包可能含认证信息；不要提交原始抓包、token、密钥、真实聊天内容或凭据。默认不保存原始包，候选缓存仅在内存中存在。

## 4. 当前实现与阅读入口

| 文件／符号 | 职责与关键行为 |
|---|---|
| `rf4_monitor.bat` | 双击入口：优先有效 `.venv`，其次 `py -3`，再 `python`；设置 UTF-8；错误时暂停窗口 |
| `安装依赖.bat` | 调用同一入口的 `--setup-only`，仅准备和检查环境 |
| `bootstrap.py`：`prepare()`、`main()` | 创建或更新 `.venv`；依赖清单摘要或导入检查变化时安装依赖；检查 Npcap；最后启动 CLI |
| `rf4_monitor.py`：`main()` | 无参数默认自动模式；保留手动网卡、端口、离线回放、JSONL 输出 |
| `rf4_auto.py`：`GameDiscovery` | 默认识别 `rf4_x64.exe`、`rf4.exe`；每 250 ms 查询进程 TCP 连接归属 |
| `rf4_auto.py`：`ReceiveHandle`、`auto_capture()` | 先打开启动时枚举到的可用 Npcap 网卡，非混杂、非阻塞接收；再查询游戏连接，避免等识别完成才开捕获而丢 SYN |
| `rf4_auto.py`：`AutoRouter` | 候选先暂存；只有游戏归属和 RF4 握手均通过才选定接口并回放给业务解析；每条连接只选一个接口以避免重复输出 |
| `rf4_capture.py`：`pcap_api()`、`devices()` | 加载 Npcap、验证版本字符串、枚举接口；失败的排查重点 |
| `rf4_capture.py`：`parse_packet()`、`read_capture()` | 链路/TCP 解析和严格的 pcap/pcapng 读取；`ports=None` 表示不限制端口 |
| `rf4_stream.py`：`Direction`、`Connection`、`SessionDecoder`、`Monitor` | TCP 排序、重传去重、ACK 依赖、握手、双向 RC4；自动模式通过 `client_key` 明确方向，避免端口冲突 |
| `rf4_protocol.py` | 上游协议解析与版本配置，目前只有 `4.0.24799` |
| `rf4_events.py`：`EventFormatter` | 鱼情/入护/频道关联、中文显示和事件导出 |
| `tests/test_auto.py`、`tests/test_bootstrap.py` | 自动识别和启动流程测试 |
| `tests/test_stream.py`、`tests/test_capture.py`、`tests/fixtures.py` | 重组、协议、抓包接口模拟，以及完全合成的数据 |
| `tests/make_demo.py` | 只生成离线文件，不发送网络流量 |

其他事实：

- 自动模式不限服务器端口；手动网卡与离线模式默认端口为 9341、9216。
- 自动候选最多 128 条，每条最多 128 KiB（含计量开销）/512 包，TTL 为 8 秒。上限或超时可能导致必须重连；不能无界增加缓存。
- 活动连接默认最多 32 条；缺口等待超过 10 秒、握手超过 30 秒会停止解析，空闲 120 秒清理。
- **必须捕获连接起始 SYN 和完整协议握手。已登录后才启动监控时，需要用户重新登录；程序不会自动断开连接。**
- 自动模式没有运行中新增网卡的重新枚举功能。加速器/VPN 应先启动；新增虚拟网卡或网络改变后应重启监控再重新登录。
- VPN/加速器场景至少要有一个可捕获接口呈现与游戏连接表可关联的原始 TCP 流；仅看到隧道密文不能解析。
- 发现采集丢包、截断、分片或协议不完整时保守停止解析。当前不做 IP 分片重组。
- 钓组显示 GUID，尚未映射游戏中的 1/2/3 号竿。来鱼重量是预估值；入护响应字段仍有上游启发式，不应宣称独立验证了服务器入护成功。
- `fish_labels_zh.json` 是很大的映射文件，避免整份打印；只查询需要的键。

## 5. 已有证据与未验证事项

### 已完成

- 旧开发机实际为 **Windows 10，build 19045，AMD64，Python 3.13.10**，不是 Win11。
- 在 Scapy 2.8.0 / psutil 7.2.2 和 Scapy 2.6.1 / psutil 6.0.0 两组依赖下，完整测试均为 **94 passed**。
- 原 70 项测试覆盖重组、双向乱序、回绕、重传、缺口、文件截断、协议解析、鱼情关联等。新增 24 项覆盖自动归属延迟、多接口去重、任意端口、重连、缓存上限、进程权限/退出、驱动接口模拟、启动安装等。
- 真实 `cmd.exe` 下测试过启动入口、中文与空格文件路径、依赖安装后重复启动；合成回放为 14 包、1 条连接正常关闭、4 条业务事件。
- 对上游 6 类正常业务消息做过一次 codec 差分核验。它是历史验证记录，并不是当前测试目录中的独立可重复测试脚本。
- `c3a9275` 的 [GitHub Actions 运行](https://github.com/homieYy/rf4_monitor/actions/runs/39569635489) 已于交接前再次核查为 **success**：Windows/Linux × Python 3.10/3.13 四组均通过；Windows 还验证首次准备环境、批处理离线回放和再次启动。

### 尚未完成

- 旧开发机没有可用 Npcap，因此真实 DLL/驱动、网卡捕获行为没有验证。
- 没有真实 RF4 会话或用户抓包，无法证明当前游戏版本、服务区和握手与上游参考版本一致。
- 没有 Win11 实机安装到联机显示鱼情的端到端验收。
- 没有真实长时间运行、性能压力或反作弊兼容性验证。

Windows CI 的离线成功不能替代 Win11 实机及 Npcap 驱动测试；“94 项通过”也不是实际鱼情准确性的完整证明。

## 6. Win11 兼容性资料核查（2026-10-22）

| 组件 | 已核查的官方资料 |
|---|---|
| Python 3.13 | [Windows 文档](https://docs.python.org/3.13/using/windows.html) 支持 Windows 8.1 及更新版本，包含 Win11 |
| pip / venv | [Python venv 文档](https://docs.python.org/3.13/library/venv.html) 明确支持 Windows；无需激活脚本也能直接调用环境中的解释器 |
| Npcap | [官网](https://npcap.com/) 明确列出 Windows 11，提供 x64/ARM64 等架构支持；[安装说明](https://npcap.com/guide/npcap-users-guide.html) 区分管理员专用模式与 OEM 静默安装 |
| Scapy 2.8.0 | [Windows 安装说明](https://scapy.readthedocs.io/en/latest/installation.html#windows) 推荐 Npcap，旧 WinPcap 已不受支持 |
| psutil 7.2.2 | [发布页](https://pypi.org/project/psutil/7.2.2/) 明确列出 Windows 11，并提供 Windows x64/ARM64 安装包 |
| BAT / cmd.exe | [微软文档](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd) 明确适用于 Windows 11 |

`scapy.libs.winpcapy` 是 Scapy 接口模块名，不等于要求安装旧 WinPcap。[Scapy 2.8.0 源码](https://github.com/secdev/scapy/blob/v2.8.0/scapy/libs/winpcapy.py) 优先从 Windows 的 Npcap 目录加载 DLL。本项目还会检查版本字符串包含 `npcap`，拒绝旧 WinPcap。

项目自身没有调用 WMIC，也没有要求使用 PowerShell 激活虚拟环境。不能仅凭 Win11 移除了某个旧工具，就认定本项目依赖该工具。

已识别但**尚未修复、也未证实为此次故障根因**的改进点：

1. Python 检查仅要求 `>=3.10`，没有上限或已验证版本选择。`py -3` 可能选中未测试的新版本；排查时优先明确使用标准版 Python 3.13，架构与目标电脑及驱动匹配，不要默认所有未来版本都兼容。
2. `requirements.txt` 使用范围 `scapy>=2.6.1,<2.9`、`psutil>=6.0,<8`，不是固定版本锁。记录实际安装版本，避免把不同电脑的环境视为相同。
3. `pcap_api()` 将导入、DLL 加载和属性错误合并为 Npcap 不可用，底层原因不直接呈现给用户。启动器会输出这一概括错误并打开官网；更细的异常诊断值得改进。
4. 单一游戏进程命名、短期候选缓存、启动时网卡快照均有适用边界；不要通过更改协议或取消完整性检查来掩盖识别失败。

## 7. 新电脑的分层调试流程

以下命令均在仓库根目录的 PowerShell 中执行。命令用于调试，不改变最终双击使用目标。不要复制旧电脑的 `.venv`；它通常不可移植。已有环境先保留版本和错误证据，避免未经检查就删除或重建。

### A. 先保留原始失败证据

1. 核对下载的是用户仓库最新代码，已完整解压，入口是 `rf4_monitor.bat`。
2. 记录失败发生于：查找 Python、创建环境、pip 安装、Npcap 加载、打开网卡、发现进程、握手还是业务显示。
3. 若窗口闪退，从已打开的终端运行下面命令，以便保留屏幕。暂时不安装、卸载或重配驱动。

```powershell
git status --short
git log -1 --oneline
cmd /d /k rf4_monitor.bat
```

ZIP 下载没有 `.git` 时，前两条可跳过，但应记录下载的提交或时间。保留完整报错，不只摘录最后一句。

### B. 记录最小环境信息

```powershell
Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, OSArchitecture
Get-CimInstance Win32_Processor | Select-Object Name, Architecture
Get-Command py, python -ErrorAction SilentlyContinue | Select-Object Name, Source
Get-Service -Name npcap -ErrorAction SilentlyContinue | Select-Object Name, Status, StartType
```

如果 `.venv` 已能运行，再执行：

```powershell
.\.venv\Scripts\python.exe -c "import sys, platform, struct; print(sys.executable); print(sys.version); print(platform.machine(), struct.calcsize('P') * 8)"
.\.venv\Scripts\python.exe -m pip show scapy psutil
```

确认 Npcap 安装器版本、是否管理员专用、是否重启，以及有无旧 WinPcap。CPU 架构与 Python 进程架构要分别记录。只读取 `npcap` 服务状态不能证明 DLL 可加载或实际捕获成功。

### C. 单独验证 Python 与离线业务链路

在新克隆且没有 `.venv` 的目录中，如果已安装 Python 3.13，可使用：

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m pytest -q
```

每一步成功后再继续。若 `py -3.13` 找不到解释器，先处理 Python 安装/定位，不要把它归为 Npcap 故障。如需重现旧环境，可在记录当前版本后将 Scapy/psutil 分别固定为 2.8.0/7.2.2。

下面只创建虚构离线数据；使用新文件名，JSONL 不能覆盖已有文件：

```powershell
.\.venv\Scripts\python.exe -m tests.make_demo handoff-demo.pcapng
.\.venv\Scripts\python.exe rf4_monitor.py --read handoff-demo.pcapng
.\rf4_monitor.bat --read handoff-demo.pcapng
```

预期：两个来鱼、一个入护响应、一个频道业务事件，统计 14 包、1 条连接正常关闭，退出码 0。直接 Python 成功而 BAT 失败，应先排查启动器而不是协议。

### D. 单独验证 Npcap DLL 与网卡枚举

```powershell
.\.venv\Scripts\python.exe -c "from scapy.libs import winpcapy; print(winpcapy.pcap_lib_version())"
.\.venv\Scripts\python.exe rf4_monitor.py --list-interfaces
```

第一条绕过项目概括错误，保留 Scapy/DLL 原始 traceback，用来区分找不到 DLL、架构不符或导入问题。出现错误时先分析证据，不要直接复制 DLL 到系统目录。

能加载版本但不能枚举或打开网卡，再检查服务、安装权限、Npcap 管理员专用选项和接口情况。需要提升时让用户在 Windows 上按正常流程确认；不要绕过权限控制。

### E. 验证自动识别与真实协议

先启动加速器/VPN（如使用），再启动监控，看到“自动监控已就绪”后登录游戏：

```powershell
.\.venv\Scripts\python.exe rf4_monitor.py --auto
```

观察输出是否依次包含：可用网卡数量、发现游戏进程、识别服务器端口、开始监控。实际进程名不匹配时，用 `--process-name` 明确指定已核实的名字。

若自动识别失败，但已确认正确接口和服务器端口，可手动对照：

```powershell
.\.venv\Scripts\python.exe rf4_monitor.py --iface 1 --port 9341
```

这里的 `1` 和 `9341` 只是示例，须换成目标机器实际值；再次登录以捕获新连接。手动成功而自动失败，优先检查归属、候选缓存与网卡选择；两者都失败，再按日志区分捕获不完整和协议版本变化。

不要要求用户公开上传登录抓包。若确实需要协议样本，应先明确最小必要内容和本地处理方式；能用脱敏结构和合成回归样本表达的问题，不提交原始真实流量。

## 8. 后续修改与验收要求

每个修复应说明：原始错误、环境、可复现触发条件、修改位置、测试结果和剩余限制。必要时增加具体回归测试；不要仅调整提示文字就宣布 Win11 故障已修复。

建议最终验收至少覆盖：

1. Win11 上首次完整解压后的启动、依赖准备，以及关闭后再次双击。
2. 实际 Npcap 版本加载、网卡打开和权限错误提示。
3. 游戏未运行时等待；已登录时提示重新登录；正常识别网卡和非默认端口（如适用）。
4. 多钓组鱼情与游戏界面对照，预估重量和入护响应重量区分清楚。
5. 断线重连、重复接口、丢包/缺口失败、Ctrl+C 退出和资源释放。
6. 原有离线测试、针对新问题的回归测试、`git diff --check`；推送后核对对应提交的 CI。

更新 README 的实际使用步骤和 VALIDATION 的**真实**验证记录后，推送用户仓库。不要上传 `.venv`、个人路径清单、密钥或真实抓包。不要把模拟结果写成真实游戏验证结果。

## 9. 可复制到新 GPT 会话的开场消息

> 请接手 https://github.com/homieYy/rf4_monitor 的 Windows 11 调试。先阅读仓库根目录 HANDOFF_WIN11.md、README.md 和 VALIDATION.md，再检查最新 main 和工作区状态。当前已有 Npcap 被动监控、网卡/端口自动识别与双击启动；用户在 Win11 上遇到尚未定位的运行失败。请在这台电脑上先取得错误及环境证据，分层验证启动器、Python 依赖、Npcap、自动发现和真实游戏协议，再修复、测试并推送我的仓库。保留不改 hosts、不代理、不发包、不读写游戏内存、不注入的设计。不要把此前 94 项离线测试或依赖官方支持 Win11 当作本机已验证成功，也不要上传认证信息或真实抓包。
