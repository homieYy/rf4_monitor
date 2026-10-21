"""Automatic receive-only capture, selected by process TCP ownership + RF4 handshake.

Process enumeration reads OS metadata only, never process memory. All adapters
are opened before discovery so a delayed TCP-table poll cannot lose the SYN.
Unconfirmed candidates are bounded, ephemeral, and never logged or saved.
"""
from __future__ import annotations

from collections import OrderedDict
from contextlib import ExitStack
import ctypes
from dataclasses import dataclass, field
import ipaddress
import struct
import time

from rf4_capture import (CaptureError, Record, SUPPORTED_LINKTYPES, devices,
                         parse_packet, pcap_api)
from rf4_stream import BoundedMap, Connection, SessionDecoder

DEFAULT_NAMES = ("rf4_x64.exe", "rf4.exe")


def normalized_ip(value):
    # Windows connection tables may append an IPv6 scope ID; pcap has no scope.
    return str(ipaddress.ip_address(value.split("%", 1)[0]))


class GameDiscovery:
    def __init__(self, names=None, output=print, backend=None):
        if backend is None:
            import psutil as backend
        self.backend = backend
        self.names = {name.casefold() for name in (names or DEFAULT_NAMES)}
        self.output = output
        self.denied = False

    def snapshot(self):
        owners = set()
        found, denied = False, False
        ps = self.backend
        for process in ps.process_iter(["name"]):
            try:
                if (process.info.get("name") or "").casefold() not in self.names:
                    continue
                found = True
                for conn in process.net_connections(kind="tcp"):
                    if conn.laddr and conn.raddr:
                        owners.add((normalized_ip(conn.laddr.ip), conn.laddr.port,
                                    normalized_ip(conn.raddr.ip), conn.raddr.port))
                        if len(owners) >= 1024:
                            raise CaptureError("游戏 TCP 连接数超过自动识别上限")
            except ps.AccessDenied:
                denied = True
            except (ps.NoSuchProcess, ps.ZombieProcess):
                continue
        if denied and not self.denied:
            self.output("无法读取游戏的 TCP 连接表，请关闭监控后右键以管理员身份运行。")
        self.denied = denied
        return owners, found


class NullFormatter:
    def handle(self, *args):
        pass


@dataclass
class Candidate:
    key: tuple
    syn: object
    packets: list = field(default_factory=list)
    size: int = 0
    probe: object = None
    checked: int = 0


class AutoRouter:
    MAX_CANDIDATES = 128
    MAX_BYTES = 128 * 1024
    MAX_PACKETS = 512
    TTL = 8.0

    def __init__(self, monitor, ports=None, output=print):
        self.monitor, self.ports, self.output = monitor, set(ports or ()), output
        self.owners = set()
        self.candidates = OrderedDict()
        self.selected = OrderedDict()  # key -> (interface, initial seq, last time)
        self.notices = BoundedMap(limit=256)

    def tick(self, now):
        for candidate_id, candidate in list(self.candidates.items()):
            if now-candidate.syn.time > self.TTL:
                del self.candidates[candidate_id]
                if candidate.key in self.owners:
                    self.notice(candidate.key, "游戏连接未通过 RF4 握手识别；若尚无鱼情，请重新登录并检查协议版本。")
        for key, (_, _, last) in list(self.selected.items()):
            if now-last > self.monitor.idle_timeout:
                del self.selected[key]
        self.monitor.tick(now)

    def notice(self, key, text):
        if key not in self.notices:
            self.notices[key] = True
            self.output(text)

    def set_owners(self, owners):
        self.owners = set(owners)
        for candidate_id in list(self.candidates):
            self.promote(candidate_id)

    def promote(self, candidate_id):
        candidate = self.candidates.get(candidate_id)
        if candidate is None or candidate.key not in self.owners:
            return
        key = candidate.key
        if candidate.probe is None:
            candidate.probe = Connection(key, candidate.syn,
                SessionDecoder(NullFormatter(), profile=self.monitor.profile))
        try:
            while candidate.checked < len(candidate.packets):
                packet = candidate.packets[candidate.checked]
                index = 0 if (packet.src, packet.sport, packet.dst, packet.dport) == key else 1
                candidate.probe.feed(index, packet)
                candidate.checked += 1
        except (ValueError, IndexError, struct.error):
            # HTTPS/login/other game sockets are not RF4 realtime sessions.
            del self.candidates[candidate_id]
            return
        if not candidate.probe.decoder.ready:
            return
        iface = candidate_id[0]
        self.selected[key] = (iface, candidate.syn.seq, candidate.packets[-1].time)
        while len(self.selected) > self.monitor.max_connections:
            self.selected.popitem(last=False)
        self.output(f"已识别游戏数据连接：网卡={iface}，服务器={key[2]}，端口={key[3]}。开始监控。")
        for packet in candidate.packets:
            self.monitor.feed(packet, client_key=key)
        for other_id in list(self.candidates):
            if self.candidates[other_id].key == key:
                del self.candidates[other_id]

    def feed(self, iface, packet):
        forward = (packet.src, packet.sport, packet.dst, packet.dport)
        reverse = (packet.dst, packet.dport, packet.src, packet.sport)
        syn = bool(packet.flags & 2 and not packet.flags & 0x10)
        key = forward if syn else (forward if forward in self.selected else reverse)
        selected = self.selected.get(key)
        if selected:
            if syn and packet.seq != selected[1]:
                del self.selected[key]
            else:
                if iface == selected[0]:
                    self.selected[key] = (iface, selected[1], packet.time)
                    self.monitor.feed(packet, client_key=key)
                return
        if syn:
            if self.ports and packet.dport not in self.ports:
                return
            candidate_id = (iface, forward)
            old = self.candidates.get(candidate_id)
            if old is None or old.syn.seq != packet.seq:
                self.candidates[candidate_id] = Candidate(forward, packet)
                while len(self.candidates) > self.MAX_CANDIDATES:
                    self.candidates.popitem(last=False)
                    self.monitor.stats["discovery_evictions"] += 1
        else:
            candidate_id = (iface, forward)
            if candidate_id not in self.candidates:
                candidate_id = (iface, reverse)
        candidate = self.candidates.get(candidate_id)
        if candidate is None:
            owned = forward if forward in self.owners else reverse
            if owned in self.owners and packet.payload:
                self.notice(owned, "检测到游戏连接，但未捕获完整起始握手。若已登录，请重新登录游戏；监控不会断开连接。")
            return
        candidate.size += len(packet.payload) + 64
        if candidate.size > self.MAX_BYTES or len(candidate.packets) >= self.MAX_PACKETS:
            del self.candidates[candidate_id]
            self.monitor.stats["discovery_evictions"] += 1
            if candidate.key in self.owners:
                self.notice(candidate.key, "游戏连接识别缓存达到上限，请重新登录游戏。")
            return
        candidate.packets.append(packet)
        self.promote(candidate_id)

    def fault(self, reason):
        self.candidates.clear()
        self.monitor.capture_fault(reason)


class ReceiveHandle:
    """Nonblocking libpcap reader; no transmit APIs or promiscuous mode."""
    def __init__(self, api, name):
        self.api, self.name = api, name
        error = ctypes.create_string_buffer(256)
        self.handle = api.pcap_open_live(name.encode(), 262144, 0, 100, error)
        self.last_drop = 0
        self.stats_missing = False
        if not self.handle:
            raise CaptureError("网卡无法打开（可能需要管理员权限）")
        program, compiled = api.bpf_program(), False
        try:
            self.link = api.pcap_datalink(self.handle)
            if self.link not in SUPPORTED_LINKTYPES:
                raise CaptureError(f"不支持的链路类型 {self.link}")
            expression = b"ip or ip6 or (ether proto 0x8100) or (ether proto 0x88a8)" if self.link == 1 else b"ip or ip6"
            if api.pcap_compile(self.handle, ctypes.byref(program), expression, 1, 0xffffffff) != 0:
                raise CaptureError("捕获过滤器编译失败")
            compiled = True
            if api.pcap_setfilter(self.handle, ctypes.byref(program)) != 0:
                raise CaptureError("捕获过滤器设置失败")
            if api.pcap_setnonblock(self.handle, 1, error) != 0:
                raise CaptureError("无法启用非阻塞捕获")
        except BaseException:
            self.close()
            raise
        finally:
            if compiled:
                api.pcap_freecode(ctypes.byref(program))

    def read(self):
        header = ctypes.POINTER(self.api.pcap_pkthdr)()
        data = ctypes.POINTER(ctypes.c_ubyte)()
        status = self.api.pcap_next_ex(self.handle, ctypes.byref(header), ctypes.byref(data))
        if status == 0:
            return None
        if status != 1:
            raise CaptureError("网卡捕获中断；请重新启动监控以重新检测网卡")
        h = header.contents
        if h.caplen > 262144 or h.caplen > h.len:
            raise CaptureError("invalid Npcap record length")
        return Record(ctypes.string_at(data, h.caplen), self.link, time.monotonic(), h.len)

    def check_stats(self, router):
        stats = self.api.pcap_stat()
        if self.api.pcap_stats(self.handle, ctypes.byref(stats)) != 0:
            if not self.stats_missing:
                router.output(f"警告：无法读取网卡 {self.name} 的丢包统计。")
                self.stats_missing = True
            return
        dropped = stats.ps_drop + stats.ps_ifdrop
        if dropped > self.last_drop:
            router.monitor.stats["driver_dropped"] += dropped-self.last_drop
            router.fault("Npcap 报告丢包，停止当前连接解析；请重新登录游戏。")
        self.last_drop = dropped

    def close(self):
        if self.handle:
            self.api.pcap_close(self.handle)
            self.handle = None


def auto_capture(monitor, names=None, ports=None, output=print):
    api, version = pcap_api()
    discovery = GameDiscovery(names, output)
    router = AutoRouter(monitor, ports, output)
    readers = []
    cleanup = ExitStack()
    try:
        for name, description in devices(api):
            try:
                reader = ReceiveHandle(api, name)
                cleanup.callback(reader.close)
                readers.append(reader)
            except CaptureError as exc:
                output(f"跳过网卡 {description or name}：{exc}")
        if not readers:
            raise CaptureError("没有可用网卡；检查 Npcap，或右键以管理员身份运行。")
        output(f"{version}；已开启 {len(readers)} 个网卡的只读捕获。")
        output("自动监控已就绪。请启动/登录游戏；已登录时请重新登录。Ctrl+C 停止。")
        output("等待进程：" + "、".join(sorted(discovery.names)))
        last_scan, last_stats, found_before = float("-inf"), float("-inf"), None
        while True:
            now = time.monotonic()
            if now-last_scan >= 0.25:
                owners, found = discovery.snapshot()
                router.set_owners(owners)
                if found != found_before:
                    output("已找到游戏，等待完整数据连接……" if found else "等待游戏启动……")
                    found_before = found
                last_scan = now
            busy = False
            for reader in readers:
                for _ in range(64):
                    record = reader.read()
                    if record is None:
                        break
                    busy = True
                    monitor.stats["captured_packets"] += 1
                    try:
                        packet = parse_packet(record, ports)
                    except CaptureError:
                        router.fault("采集到截断、分片或无效数据，当前连接停止解析。")
                        continue
                    if packet:
                        router.feed(reader.name, packet)
            if now-last_stats >= 1:
                for reader in readers:
                    reader.check_stats(router)
                last_stats = now
            router.tick(time.monotonic())
            if not busy:
                time.sleep(0.01)
    finally:
        try:
            for reader in readers:
                try:
                    reader.check_stats(router)
                except Exception:
                    output(f"警告：退出时无法读取网卡 {reader.name} 的丢包统计。")
        finally:
            cleanup.close()
