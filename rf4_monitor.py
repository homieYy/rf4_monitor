"""Receive-only RF4 monitor: Windows/Npcap live capture or offline pcap replay."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from rf4_events import EventFormatter
from rf4_protocol import KNOWN_PROFILES
from rf4_stream import Monitor


def port_number(value):
    port = int(value)
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return port


def main(argv=None):
    parser = argparse.ArgumentParser(description="RF4 被动监控：读取流量副本，不代理、不改包、不注入。")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--list-interfaces", action="store_true", help="列出 Npcap 网卡")
    mode.add_argument("--iface", help="采集网卡编号（从 1 开始）或 Npcap 设备名")
    mode.add_argument("--read", type=Path, metavar="PCAP", help="离线回放 pcap/pcapng，无需 Npcap")
    parser.add_argument("--port", action="append", type=port_number, help="realtime 端口，可重复；默认 9341 和 9216")
    parser.add_argument("--profile", choices=sorted(KNOWN_PROFILES), default="4.0.24799")
    parser.add_argument("--telemetry", default="fish,player,feed", help="遥测类别，如 fish,player 或 none；鱼情事件始终输出")
    parser.add_argument("--jsonl", type=Path, help="保存结构化鱼情/频道事件（不保存认证数据或原始包）")
    args = parser.parse_args(argv)
    if not (args.list_interfaces or args.iface or args.read):
        parser.print_help()
        print("\n首次使用：python rf4_monitor.py --list-interfaces，然后指定 --iface 编号。")
        return 0
    from rf4_capture import CaptureError, CaptureConsumer, devices, pcap_api, live_capture, read_capture
    event_file = None
    monitor = None
    code = 0
    try:
        if args.list_interfaces:
            api, version = pcap_api()
            print(version)
            for i, (name, description) in enumerate(devices(api), 1):
                print(f"{i}. {description}\n   {name}")
            return 0
        if args.jsonl:
            if args.read and args.jsonl.resolve() == args.read.resolve():
                parser.error("--jsonl cannot overwrite the input capture")
            event_file = args.jsonl.open("x", encoding="utf-8")

        def save_event(event):
            if event_file:
                event_file.write(json.dumps(event, ensure_ascii=False)+"\n")
                event_file.flush()

        formatter = EventFormatter(event_output=save_event, telemetry=args.telemetry)
        monitor = Monitor(formatter, ports=args.port or (9341, 9216), profile=args.profile,
                          warning=lambda message: print(f"[警告] {message}", file=sys.stderr))
        print("被动监控模式：游戏必须直接连接服务器。旧版 hosts 重定向请先手动恢复。")
        if args.read:
            consumer = CaptureConsumer(monitor)
            for record in read_capture(args.read):
                consumer.feed(record)
        else:
            live_capture(args.iface, monitor)
    except KeyboardInterrupt:
        print("\n已停止采集。")
    except (CaptureError, OSError, ImportError, ValueError) as exc:
        print(f"[错误] {exc}", file=sys.stderr)
        code = 1
    finally:
        if monitor:
            stats = monitor.finish()
            print("采集统计："+json.dumps(stats, ensure_ascii=False, sort_keys=True))
            if stats.get("invalid_connections") or stats.get("capture_faults") or stats.get("midstream"):
                code = code or 2
            if not stats.get("connections"):
                code = code or 2
                print("未发现从 SYN 开始的目标连接；请检查网卡、端口和采集启动时间。", file=sys.stderr)
        if event_file:
            event_file.close()
    return code


if __name__ == "__main__":
    raise SystemExit(main())
