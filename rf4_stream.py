"""Bounded, receive-only TCP reassembly and RF4 session decoding.

No sockets are opened here. Only ordered copies of captured bytes are consumed.
Missing/corrupt streams are abandoned until a new SYN, never guessed or repaired
by sending traffic. Sequence comparisons use the TCP modulo-2**32 convention.
"""
from __future__ import annotations

from collections import OrderedDict, Counter
from dataclasses import dataclass
import struct

from rf4_protocol import (
    MAX_FRAME_BYTES, RC4Stream, get_profile, try_parse_auth_packet,
    try_parse_uuid_packet, try_parse_first_frame,
)


class StreamError(ValueError):
    pass


def relative(seq, reference):
    return ((seq - reference + 0x80000000) & 0xffffffff) - 0x80000000


class BoundedMap(OrderedDict):
    def __init__(self, limit=1024, warning=lambda text: None):
        super().__init__()
        self.limit, self.warning = limit, warning
        self.reported = False

    def __setitem__(self, key, value):
        if key in self:
            del self[key]
        super().__setitem__(key, value)
        if len(self) > self.limit:
            self.popitem(last=False)
            if not self.reported:
                self.warning("业务缓存达到上限；最早的未完成关联已移除")
                self.reported = True


class SessionDecoder:
    def __init__(self, formatter, connection="", profile="4.0.24799", warning=lambda text: None):
        self.formatter, self.connection = formatter, connection
        self.profile = get_profile(profile)
        self.buffers = [bytearray(), bytearray()]  # client, server
        self.auth_seen = self.uuid_seen = self.hermes_seen = False
        self.ciphers = None
        self.frames = 0
        self.fish_setup_cache = BoundedMap(warning=warning)
        self.keep_requests = BoundedMap(warning=warning)
        self.room_events = BoundedMap(warning=warning)
        self.room_ack_calls = BoundedMap(warning=warning)
        self.announced = BoundedMap(warning=warning)

    @property
    def ready(self):
        return self.auth_seen and self.uuid_seen and self.hermes_seen

    @property
    def incomplete(self):
        return not self.ready or any(self.buffers)

    def feed(self, direction, data):
        buffer = self.buffers[direction]
        if len(buffer) + len(data) > 2 * MAX_FRAME_BYTES:
            raise StreamError("协议缓冲达到上限")
        buffer.extend(data)
        client, server = self.buffers
        if not self.auth_seen:
            auth = try_parse_auth_packet(client)
            if auth:
                token, size = auth
                # Never log or persist authentication bytes.
                self.ciphers = [RC4Stream(token.encode("utf-8")) for _ in range(2)]
                self.auth_seen = True
                del client[:size]
        if not self.uuid_seen:
            handshake = try_parse_uuid_packet(server)
            if handshake:
                self.uuid_seen = True
                del server[:handshake[1]]
        if self.auth_seen and not self.hermes_seen:
            frame = try_parse_first_frame(client)
            if frame:
                if b"<hermes>" not in frame.payload:
                    raise StreamError("缺少 Hermes 握手")
                self.hermes_seen = True
                del client[:len(frame.raw)]
        if self.ready:
            # Drain both buffers: the last handshake byte can arrive in either
            # direction, after the other direction already buffered app frames.
            for index in (0, 1):
                buffer = self.buffers[index]
                while buffer:
                    frame = try_parse_first_frame(buffer)
                    if frame is None:
                        break
                    del buffer[:len(frame.raw)]
                    if frame.frame_type == 1 or not frame.payload:
                        continue
                    plain = self.ciphers[index].crypt(frame.payload)
                    self.frames += 1
                    self.formatter.handle(self, index == 0, plain)


@dataclass(frozen=True)
class Segment:
    src: str
    sport: int
    dst: str
    dport: int
    seq: int
    ack: int = 0
    flags: int = 0x10
    payload: bytes = b""
    time: float = 0.0


@dataclass
class Piece:
    start: int
    data: bytes
    ack: int | None


class Direction:
    MAX_PENDING = 1024 * 1024
    MAX_PIECES = 2048
    HISTORY = 65536

    def __init__(self, isn):
        self.isn = isn
        self.next = isn + 1  # unwrapped sequence, SYN consumes one byte
        self.pending = []
        self.history = b""
        self.fin = None
        self.fin_ack = None
        self.closed = False
        self.observed_ack = self.next

    def absolute(self, seq):
        return self.next + relative(seq, self.next)

    def add(self, segment):
        start = self.absolute((segment.seq + bool(segment.flags & 2)) & 0xffffffff)
        data = segment.payload
        end = start + len(data)
        if data and (start > self.next + self.MAX_PENDING or end > self.next + self.MAX_PENDING):
            raise StreamError("TCP 序列超出重组窗口")
        if self.fin is not None and data and end > self.fin:
            raise StreamError("FIN 之后存在数据")
        history_end = self.next - int(self.closed)
        history_start = history_end - len(self.history)
        left, right = max(start, history_start), min(end, history_end)
        if left < right and data[left-start:right-start] != self.history[left-history_start:right-history_start]:
            raise StreamError("TCP 重传内容冲突")
        if start < self.next:
            data = data[max(0, self.next-start):]
            start = self.next
        ack = segment.ack if segment.flags & 0x10 else None
        new = [Piece(start, data, ack)] if data else []
        # Retain first-seen bytes; overlapping retransmissions must agree.
        for old in self.pending:
            remaining = []
            for piece in new:
                a, b = max(piece.start, old.start), min(piece.start+len(piece.data), old.start+len(old.data))
                if a >= b:
                    remaining.append(piece)
                    continue
                if piece.data[a-piece.start:b-piece.start] != old.data[a-old.start:b-old.start]:
                    raise StreamError("TCP 乱序片段内容冲突")
                if piece.start < a:
                    remaining.append(Piece(piece.start, piece.data[:a-piece.start], piece.ack))
                if b < piece.start+len(piece.data):
                    remaining.append(Piece(b, piece.data[b-piece.start:], piece.ack))
            new = remaining
        self.pending.extend(new)
        self.pending.sort(key=lambda item: item.start)
        if len(self.pending) > self.MAX_PIECES or sum(len(p.data) for p in self.pending) > self.MAX_PENDING:
            raise StreamError("TCP 重组缓冲达到上限")
        if segment.flags & 1:
            if self.fin is not None and self.fin != end:
                raise StreamError("FIN 序列冲突")
            if self.fin is None and end < self.next:
                raise StreamError("FIN 早于已交付数据")
            if any(p.start+len(p.data) > end for p in self.pending):
                raise StreamError("FIN 与缓存数据冲突")
            self.fin, self.fin_ack = end, ack

    def pop(self, peer):
        # Respect the other direction's ACK dependency. A response captured
        # before a reordered request must not consume correlation state early.
        def allowed(ack):
            return ack is None or (peer is not None and relative(ack, peer.next) <= 0)
        if self.pending and self.pending[0].start == self.next and allowed(self.pending[0].ack):
            piece = self.pending.pop(0)
            self.next += len(piece.data)
            self.history = (self.history + piece.data)[-self.HISTORY:]
            return piece.data
        if not self.closed and self.fin == self.next and allowed(self.fin_ack):
            self.next += 1
            self.closed = True
            return b""
        return None

    @property
    def waiting(self):
        return bool(self.pending) or (self.fin is not None and not self.closed) or self.observed_ack > self.next


class Connection:
    def __init__(self, key, syn, decoder):
        self.key, self.isn, self.decoder = key, syn.seq, decoder
        self.directions = [Direction(syn.seq), None]
        self.started = self.last = syn.time
        self.wait_since = None
        self.failed = False

    def feed(self, index, segment):
        self.last = max(self.last, segment.time)
        if index == 1 and segment.flags & 2:
            if not segment.flags & 0x10 or relative(segment.ack, self.isn+1) != 0:
                raise StreamError("SYN/ACK 不匹配")
            if self.directions[1] is None:
                self.directions[1] = Direction(segment.seq)
            elif self.directions[1].isn != segment.seq:
                raise StreamError("服务端初始序列冲突")
        direction = self.directions[index]
        if direction is None:
            raise StreamError("缺少服务端 SYN/ACK；请在连接前启动采集")
        peer = self.directions[1-index]
        if peer is not None and segment.flags & 0x10:
            peer.observed_ack = max(peer.observed_ack, peer.absolute(segment.ack))
        direction.add(segment)
        while True:
            changed = False
            for i, stream in enumerate(self.directions):
                if stream is None:
                    continue
                data = stream.pop(self.directions[1-i])
                if data is not None:
                    if data:
                        self.decoder.feed(i, data)
                    changed = True
            if not changed:
                break
        waiting = any(d is not None and d.waiting for d in self.directions)
        if not waiting:
            self.wait_since = None
        elif self.wait_since is None:
            self.wait_since = self.last

    @property
    def closed(self):
        return all(d is not None and d.closed for d in self.directions)

    @property
    def incomplete(self):
        return self.decoder.incomplete or any(d is not None and d.waiting for d in self.directions)


class Monitor:
    def __init__(self, formatter, ports=(9341, 9216), profile="4.0.24799", warning=print,
                 max_connections=32, idle_timeout=120, gap_timeout=10):
        self.formatter, self.ports, self.profile = formatter, set(ports), profile
        self.warning = warning
        self.max_connections = max_connections
        self.idle_timeout, self.gap_timeout = idle_timeout, gap_timeout
        self.connections = OrderedDict()
        self.ignored = BoundedMap(limit=256)
        self.stats = Counter()
        self.now = 0.0

    def _fail(self, connection, reason):
        if connection.failed:
            return
        connection.failed = True
        connection.directions = [None, None]
        connection.decoder = None  # release keys, protocol and reassembly buffers
        self.stats["invalid_connections"] += 1
        self.warning(f"连接 {connection.key} 停止解析：{reason}；等待新连接")

    def tick(self, now):
        self.now = max(self.now, now)
        for key, connection in list(self.connections.items()):
            if not connection.failed:
                if connection.wait_since is not None and self.now-connection.wait_since > self.gap_timeout:
                    self._fail(connection, "TCP 缺口或跨方向依赖超时")
                elif not connection.decoder.ready and self.now-connection.started > 30:
                    self._fail(connection, "握手超时或非 RF4 协议")
            if self.now-connection.last > self.idle_timeout:
                if not connection.failed and connection.incomplete:
                    self._fail(connection, "空闲连接存在未完成数据")
                del self.connections[key]
                self.stats["expired"] += 1

    def feed(self, segment, client_key=None):
        if client_key is not None:
            forward = (segment.src, segment.sport, segment.dst, segment.dport)
            reverse = (segment.dst, segment.dport, segment.src, segment.sport)
            if client_key not in (forward, reverse):
                raise ValueError("segment does not match selected connection")
            key, index = client_key, 0 if client_key == forward else 1
        elif segment.dport in self.ports:
            key = (segment.src, segment.sport, segment.dst, segment.dport)
            index = 0
        elif segment.sport in self.ports:
            key = (segment.dst, segment.dport, segment.src, segment.sport)
            index = 1
        else:
            return
        self.stats["tcp_packets"] += 1
        self.tick(segment.time)
        connection = self.connections.get(key)
        syn = index == 0 and segment.flags & 2 and not segment.flags & 0x10
        if syn and (connection is None or connection.isn != segment.seq):
            if connection is not None and not connection.failed and connection.incomplete:
                self._fail(connection, "新 SYN 替换了未完成连接")
            decoder = SessionDecoder(self.formatter, str(key), self.profile, self.warning)
            connection = Connection(key, segment, decoder)
            self.connections[key] = connection
            self.ignored.pop(key, None)
            self.stats["connections"] += 1
            while len(self.connections) > self.max_connections:
                _, old = self.connections.popitem(last=False)
                self._fail(old, "连接数达到上限")
        if connection is None:
            if segment.payload and key not in self.ignored:
                self.ignored[key] = True
                self.stats["midstream"] += 1
                self.warning(f"连接 {key} 缺少起始 SYN；请重新登录或等待游戏重新连接")
            return
        self.connections.move_to_end(key)
        connection.last = max(connection.last, segment.time)
        if connection.failed:
            return
        if segment.flags & 4:
            if connection.incomplete:
                self._fail(connection, "RST 结束了未完成连接")
            else:
                connection.failed = True
                connection.decoder = None
                connection.directions = [None, None]
            self.stats["resets"] += 1
            return
        try:
            connection.feed(index, segment)
            if connection.closed:
                if connection.incomplete:
                    self._fail(connection, "连接关闭时仍有不完整协议数据")
                else:
                    connection.failed = True
                    connection.decoder = None
                    connection.directions = [None, None]
                    self.stats["closed"] += 1
        except (ValueError, IndexError, struct.error) as exc:
            # Exception contents (e.g. UnicodeDecodeError) can include tokens.
            reason = str(exc) if isinstance(exc, StreamError) else "协议格式错误或版本不匹配"
            self._fail(connection, reason)

    def capture_fault(self, reason):
        self.stats["capture_faults"] += 1
        if self.stats["capture_faults"] <= 3 or self.stats["capture_faults"] % 1000 == 0:
            self.warning(reason)
        for connection in self.connections.values():
            self._fail(connection, "采集数据不完整")

    def finish(self):
        for connection in self.connections.values():
            if not connection.failed and connection.incomplete:
                self._fail(connection, "采集结束时仍有未完成数据")
        self.connections.clear()
        return dict(self.stats)
