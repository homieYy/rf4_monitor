"""Read-only capture adapters. Live mode calls only libpcap receive APIs.

Offline reading has no Npcap requirement. Strict file-length checks distinguish
clean EOF from truncated records (which many packet readers silently ignore).
"""
from __future__ import annotations

import ctypes
from dataclasses import dataclass, replace
import os
import struct
import time

from rf4_stream import Segment

MAX_RECORD = 16 * 1024 * 1024
SUPPORTED_LINKTYPES = {0, 1, 12, 101, 108, 113, 228, 229, 276}


class CaptureError(ValueError):
    pass


@dataclass(frozen=True)
class Record:
    data: bytes
    linktype: int
    timestamp: float
    wirelen: int


def exact(stream, count):
    if count < 0 or count > MAX_RECORD:
        raise CaptureError("capture record length outside supported bounds")
    data = stream.read(count)
    if len(data) != count:
        raise CaptureError("truncated capture file")
    return data


def options(data, endian):
    offset = 0
    while offset < len(data):
        if offset + 4 > len(data):
            raise CaptureError("truncated pcapng option")
        code, size = struct.unpack_from(endian + "HH", data, offset)
        offset += 4
        padded = (size + 3) & ~3
        if offset + padded > len(data):
            raise CaptureError("truncated pcapng option value")
        if code == 0:
            if size:
                raise CaptureError("invalid pcapng end option")
            if any(data[offset:]):
                raise CaptureError("nonzero bytes after pcapng end option")
            return
        yield code, data[offset:offset+size]
        offset += padded


def read_capture(path):
    with open(path, "rb") as stream:
        magic = exact(stream, 4)
        formats = {b"\xd4\xc3\xb2\xa1": ("<", 1e6), b"\xa1\xb2\xc3\xd4": (">", 1e6),
                   b"\x4d\x3c\xb2\xa1": ("<", 1e9), b"\xa1\xb2\x3c\x4d": (">", 1e9)}
        if magic in formats:
            endian, scale = formats[magic]
            major, minor, _, _, snaplen, link = struct.unpack(endian+"HHIIII", exact(stream, 20))
            if (major, minor) != (2, 4) or not 0 < snaplen <= MAX_RECORD:
                raise CaptureError("unsupported pcap header")
            while True:
                header = stream.read(16)
                if not header:
                    return
                if len(header) != 16:
                    raise CaptureError("truncated pcap record header")
                sec, frac, size, wire = struct.unpack(endian+"IIII", header)
                if size > snaplen or size > wire or frac >= scale:
                    raise CaptureError("invalid pcap packet header")
                yield Record(exact(stream, size), link, sec+frac/scale, wire)
        elif magic == b"\x0a\x0d\x0d\x0a":
            stream.seek(0)
            yield from read_pcapng(stream)
        else:
            raise CaptureError("expected pcap or pcapng file")


def read_pcapng(stream):
    endian, interfaces, last_time = None, [], 0.0
    while True:
        header = stream.read(8)
        if not header:
            return
        if len(header) != 8:
            raise CaptureError("truncated pcapng block header")
        if header[:4] == b"\x0a\x0d\x0d\x0a":
            bom = exact(stream, 4)
            endian = {b"\x4d\x3c\x2b\x1a": "<", b"\x1a\x2b\x3c\x4d": ">"}.get(bom)
            if endian is None:
                raise CaptureError("invalid pcapng byte order")
            length = struct.unpack(endian+"I", header[4:])[0]
            if length < 28 or length % 4:
                raise CaptureError("invalid section length")
            body = bom + exact(stream, length-12)
            if struct.unpack(endian+"I", body[-4:])[0] != length:
                raise CaptureError("pcapng section length mismatch")
            if struct.unpack_from(endian+"HH", body, 4) != (1, 0):
                raise CaptureError("unsupported pcapng version")
            interfaces = []
            continue
        if endian is None:
            raise CaptureError("pcapng section missing")
        kind, length = struct.unpack(endian+"II", header)
        if length < 12 or length % 4:
            raise CaptureError("invalid pcapng block length")
        body = exact(stream, length-8)
        if struct.unpack(endian+"I", body[-4:])[0] != length:
            raise CaptureError("pcapng block length mismatch")
        body = body[:-4]
        if kind == 1:
            if len(body) < 8:
                raise CaptureError("truncated interface block")
            link, _, snaplen = struct.unpack_from(endian+"HHI", body)
            scale, offset = 1e6, 0
            for code, value in options(body[8:], endian):
                if code == 9:
                    if len(value) != 1:
                        raise CaptureError("invalid timestamp resolution")
                    scale = (2 if value[0] & 128 else 10) ** (value[0] & 127)
                elif code == 14:
                    if len(value) != 8:
                        raise CaptureError("invalid timestamp offset")
                    offset = struct.unpack(endian+"q", value)[0]
            if len(interfaces) >= 256:
                raise CaptureError("too many pcapng interfaces")
            interfaces.append((link, snaplen, scale, offset))
        elif kind == 6:
            if len(body) < 20:
                raise CaptureError("truncated enhanced packet block")
            iface, hi, lo, size, wire = struct.unpack_from(endian+"IIIII", body)
            if iface >= len(interfaces):
                raise CaptureError("unknown pcapng interface")
            link, snaplen, scale, offset = interfaces[iface]
            padded = (size+3) & ~3
            if size > wire or (snaplen and size > snaplen) or 20+padded > len(body):
                raise CaptureError("invalid enhanced packet length")
            # Validate options too, even when unused.
            list(options(body[20+padded:], endian))
            last_time = ((hi << 32) | lo) / scale + offset
            yield Record(body[20:20+size], link, last_time, wire)
        elif kind in (2, 3):
            raise CaptureError("legacy/simple pcapng packet blocks are unsupported; export as pcap or enhanced pcapng")


def parse_packet(record, ports):
    # Lazy import keeps protocol tests and --help independent of capture setup.
    from scapy.all import Ether, IP, IPv6, TCP, Dot1Q, CookedLinux, CookedLinuxV2, Loopback
    from scapy.layers.inet6 import IPv6ExtHdrFragment
    from scapy.packet import NoPayload

    classes = {1: Ether, 101: None, 12: None, 228: IP, 229: IPv6,
               113: CookedLinux, 276: CookedLinuxV2, 0: Loopback, 108: Loopback}
    if record.linktype not in classes:
        raise CaptureError(f"unsupported link type {record.linktype}")
    if len(record.data) < record.wirelen:
        raise CaptureError("captured packet is truncated")
    minimum = {1: 14, 113: 16, 276: 20, 0: 4, 108: 4}.get(record.linktype, 1)
    if len(record.data) < minimum:
        raise CaptureError("truncated link-layer header")
    # DLT_NULL uses host byte order, DLT_LOOP network byte order. Strip its
    # family header explicitly so offline captures are portable across hosts.
    if record.linktype in (0, 108):
        value = record.data[:4]
        families = [int.from_bytes(value, "big")]
        if record.linktype == 0:
            families.append(int.from_bytes(value, "little"))
        link = 228 if 2 in families else 229 if any(f in (10, 23, 24, 28, 30) for f in families) else None
        if link is None:
            return None
        return parse_packet(Record(record.data[4:], link, record.timestamp, record.wirelen-4), ports)
    cls = classes[record.linktype]
    if cls is None:
        if not record.data:
            raise CaptureError("empty raw IP packet")
        version = record.data[0] >> 4
        cls = {4: IP, 6: IPv6}.get(version)
        if cls is None:
            raise CaptureError("invalid raw IP version")
    try:
        packet = cls(record.data)
        layer = packet
        # Only outer IP, never interpret TCP inside an unrelated tunnel as a
        # second connection. Ethernet VLAN encapsulation is supported.
        while isinstance(layer, (Ether, Dot1Q, CookedLinux, CookedLinuxV2, Loopback)):
            protocol = getattr(layer, "type", getattr(layer, "proto", None))
            layer = layer.payload
            if protocol in (0x800, 0x86dd) and not isinstance(layer, (IP, IPv6)):
                raise CaptureError("truncated/invalid IP header")
        if not isinstance(layer, (IP, IPv6)):
            return None
        ip = layer
        raw = bytes(ip.original) if ip.original else bytes(ip)
        if isinstance(ip, IP):
            if ip.version != 4 or ip.ihl is None or ip.ihl < 5 or ip.len < ip.ihl*4 or ip.len > len(raw):
                raise CaptureError("invalid/truncated IPv4 packet")
            if ip.proto != 6:
                return None
            if ip.frag or int(ip.flags) & 1:
                raise CaptureError("IPv4 fragmentation is unsupported")
            tcp_bytes = raw[ip.ihl*4:ip.len]
        else:
            if ip.version != 6 or ip.plen == 0 or 40+ip.plen > len(raw):
                raise CaptureError("invalid/truncated IPv6 packet")
            current = ip.payload
            while not isinstance(current, (TCP, NoPayload)):
                if isinstance(current, IPv6ExtHdrFragment):
                    raise CaptureError("IPv6 fragmentation is unsupported")
                if current.__class__.__name__ not in {"IPv6ExtHdrHopByHop", "IPv6ExtHdrDestOpt", "IPv6ExtHdrRouting"}:
                    if ip.nh == 6:
                        raise CaptureError("invalid/truncated IPv6 TCP header")
                    return None
                current = current.payload
            if not isinstance(current, TCP):
                return None
            tcp_bytes = bytes(current.original) if current.original else bytes(current)
        if len(tcp_bytes) < 20:
            raise CaptureError("truncated TCP header")
        sport, dport, seq, ack = struct.unpack_from("!HHII", tcp_bytes)
        if ports is not None and sport not in ports and dport not in ports:
            return None
        size = (tcp_bytes[12] >> 4) * 4
        if size < 20 or size > len(tcp_bytes):
            raise CaptureError("invalid TCP data offset")
        # Checksum validation is intentionally omitted: local transmit checksum
        # offload commonly leaves an unfinished checksum in captured copies.
        return Segment(ip.src, sport, ip.dst, dport, seq, ack,
                       tcp_bytes[13], tcp_bytes[size:], record.timestamp)
    except (IndexError, struct.error) as exc:
        raise CaptureError("malformed packet") from exc


class CaptureConsumer:
    def __init__(self, monitor):
        self.monitor = monitor

    def feed(self, record, live=False):
        self.monitor.stats["captured_packets"] += 1
        try:
            segment = parse_packet(record, self.monitor.ports)
        except CaptureError as exc:
            self.monitor.capture_fault(str(exc))
            return
        if segment:
            if live:
                segment = replace(segment, time=time.monotonic())
            self.monitor.feed(segment)
        elif not live:
            self.monitor.tick(record.timestamp)


def pcap_api():
    if os.name != "nt":
        raise CaptureError("live capture requires Windows and Npcap; offline replay works on this OS")
    try:
        from scapy.libs import winpcapy
        version = winpcapy.pcap_lib_version().decode("utf-8", "replace")
    except (ImportError, OSError, AttributeError) as exc:
        raise CaptureError("Npcap is unavailable; install it from https://npcap.com/ and match Python architecture") from exc
    if "npcap" not in version.lower():
        raise CaptureError("Npcap is required; an old WinPcap library was loaded")
    return winpcapy, version


def devices(api):
    head = ctypes.POINTER(api.pcap_if_t)()
    error = ctypes.create_string_buffer(256)
    if api.pcap_findalldevs(ctypes.byref(head), error) != 0:
        raise CaptureError("cannot enumerate Npcap adapters")
    result = []
    try:
        current = head
        while current:
            item = current.contents
            result.append((item.name.decode(), (item.description or b"").decode("utf-8", "replace")))
            current = item.next
    finally:
        api.pcap_freealldevs(head)
    return result


def live_capture(iface, monitor, output=print):
    api, version = pcap_api()
    available = devices(api)
    if iface.isdecimal():
        index = int(iface)-1
        if not 0 <= index < len(available):
            raise CaptureError("adapter index out of range; use --list-interfaces")
        iface = available[index][0]
    if iface not in [name for name, _ in available]:
        raise CaptureError("unknown adapter; use --list-interfaces")
    error = ctypes.create_string_buffer(256)
    handle = api.pcap_open_live(iface.encode(), 262144, 0, 100, error)
    if not handle:
        raise CaptureError("cannot open adapter; check Npcap service and capture permissions (admin-only installation needs elevation)")
    program = api.bpf_program()
    compiled = False
    try:
        # Capture IP copies, including VLANs/fragments/IPv6 extension headers.
        # Port selection happens after decoding, avoiding filters that silently
        # omit fragments. No promiscuous mode and no packet transmit APIs.
        link = api.pcap_datalink(handle)
        if link not in SUPPORTED_LINKTYPES:
            raise CaptureError(f"unsupported link type {link}")
        expression = b"ip or ip6 or (ether proto 0x8100) or (ether proto 0x88a8)" if link == 1 else b"ip or ip6"
        if api.pcap_compile(handle, ctypes.byref(program), expression, 1, 0xffffffff) != 0:
            raise CaptureError("cannot compile capture filter")
        compiled = True
        if api.pcap_setfilter(handle, ctypes.byref(program)) != 0:
            raise CaptureError("cannot install capture filter")
        output(f"{version}; adapter={iface}; linktype={link}; snaplen=262144; promiscuous=off")
        output("采集已就绪。请现在启动/重新登录游戏；Ctrl+C 停止。")
        consumer = CaptureConsumer(monitor)
        header = ctypes.POINTER(api.pcap_pkthdr)()
        data = ctypes.POINTER(ctypes.c_ubyte)()
        last_check, last_drop = 0.0, 0
        stats_missing = False

        def check_stats():
            nonlocal last_drop, stats_missing
            stats = api.pcap_stat()
            if api.pcap_stats(handle, ctypes.byref(stats)) != 0:
                if not stats_missing:
                    output("警告：无法读取驱动丢包统计，不能确认采集完整性。")
                    stats_missing = True
                return
            monitor.stats["driver_received"] = stats.ps_recv
            monitor.stats["driver_dropped"] = stats.ps_drop
            monitor.stats["interface_dropped"] = stats.ps_ifdrop
            dropped = stats.ps_drop + stats.ps_ifdrop
            if dropped > last_drop:
                monitor.capture_fault("Npcap 报告采集丢包；当前连接停止解析")
            last_drop = dropped

        try:
            while True:
                status = api.pcap_next_ex(handle, ctypes.byref(header), ctypes.byref(data))
                now = time.monotonic()
                monitor.tick(now)
                if now-last_check >= 1:
                    check_stats()
                    last_check = now
                if status == 0:
                    continue
                if status != 1:
                    raise CaptureError("Npcap capture stopped unexpectedly")
                h = header.contents
                if h.caplen > 262144 or h.caplen > h.len:
                    raise CaptureError("invalid Npcap record length")
                consumer.feed(Record(ctypes.string_at(data, h.caplen), link,
                                     h.ts.tv_sec+h.ts.tv_usec/1e6, h.len), live=True)
        finally:
            check_stats()
    finally:
        if compiled:
            api.pcap_freecode(ctypes.byref(program))
        api.pcap_close(handle)
