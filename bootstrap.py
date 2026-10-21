"""Double-click setup/launch entry; installers run outside the capture pipeline."""
from __future__ import annotations

import hashlib
from pathlib import Path
import subprocess
import sys
import webbrowser

ROOT = Path(__file__).resolve().parent


def prepare(root=ROOT):
    if sys.version_info < (3, 10):
        raise RuntimeError("需要 Python 3.10 或更新版本，请从 https://www.python.org/downloads/windows/ 安装。")
    python = root / ".venv" / "Scripts" / "python.exe"
    if not python.exists():
        print("首次启动：正在创建独立 Python 环境……", flush=True)
        subprocess.run([sys.executable, "-m", "venv", str(root / ".venv")], check=True)
    version = subprocess.run([str(python), "-c", "import sys; sys.exit(sys.version_info < (3,10))"],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if version.returncode:
        print("正在更新旧 Python 虚拟环境……", flush=True)
        subprocess.run([sys.executable, "-m", "venv", "--upgrade", str(root / ".venv")], check=True)
    requirements = root / "requirements.txt"
    stamp = root / ".venv" / "rf4-requirements.sha256"
    digest = hashlib.sha256(requirements.read_bytes()).hexdigest()
    probe = subprocess.run([str(python), "-c",
        "import sys; assert sys.version_info >= (3,10); import scapy, psutil"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if probe.returncode or not stamp.exists() or stamp.read_text().strip() != digest:
        print("首次启动或依赖更新：正在安装依赖（需要联网）……", flush=True)
        subprocess.run([str(python), "-m", "pip", "install", "-r", str(requirements)], check=True)
        stamp.write_text(digest, encoding="ascii")
    return python


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    setup_only = args == ["--setup-only"]
    try:
        python = prepare()
        if setup_only or not any(arg in ("--read", "--help", "-h") or arg.startswith("--read=") for arg in args):
            check = subprocess.run([str(python), "-c",
                "from rf4_capture import pcap_api, CaptureError\n"
                "try: pcap_api()\n"
                "except (CaptureError, ImportError, OSError) as exc:\n"
                " print(exc)\n raise SystemExit(1)"],
                cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace")
            if check.returncode:
                print((getattr(check, "stdout", "") or getattr(check, "stderr", "")).strip())
                print("尚未检测到可用 Npcap。已打开官方下载页，请安装 Npcap 后再次双击启动。")
                print("无需安装 Wireshark。若已安装，请检查 Python/驱动架构、Npcap 服务和安装权限。")
                webbrowser.open("https://npcap.com/#download")
                return 1
        if setup_only:
            print("环境检查完成。以后双击 rf4_monitor.bat 即可开始自动监控。")
            return 0
        return subprocess.run([str(python), str(ROOT / "rf4_monitor.py"), *args], cwd=ROOT).returncode
    except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"启动失败：{exc}")
        print("请检查 Python 安装和网络；修复后重新双击即可重试。")
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
