from dataclasses import replace
from types import SimpleNamespace

import pytest

from rf4_auto import AutoRouter, GameDiscovery, ReceiveHandle, auto_capture
from rf4_capture import CaptureError, Record, parse_packet
from rf4_monitor import main
from tests.fixtures import trace, packet_bytes, TOKEN
from tests.test_stream import setup_monitor, run
from tests.test_capture import FakePcap


def key(packet):
    return packet.src, packet.sport, packet.dst, packet.dport


@pytest.mark.parametrize("delay", [0, 1, 3, 5, 14])
def test_auto_delayed_ownership_and_duplicate_interfaces(delay):
    packets = trace(close=True)
    monitor, lines, events, warnings = setup_monitor()
    router = AutoRouter(monitor, output=lines.append)
    for i, packet in enumerate(packets):
        if i == delay:
            router.set_owners({key(packets[0])})
        router.feed("wifi", packet)
        router.feed("duplicate-vpn", packet)
    router.set_owners({key(packets[0])})
    assert events == run(packets)[1]
    assert not warnings
    assert monitor.stats["connections"] == 1
    assert monitor.stats["closed"] == 1
    assert not router.candidates
    assert TOKEN.decode() not in str(lines)


def test_auto_unknown_port_and_equal_local_remote_ports():
    packets = [replace(p, sport=55000 if p.sport == 9341 else p.sport,
                       dport=55000 if p.dport == 9341 else p.dport) for p in trace(close=True)]
    monitor, lines, events, warnings = setup_monitor()
    router = AutoRouter(monitor, output=lines.append)
    router.set_owners({key(packets[0])})
    for p in packets:
        router.feed("wifi", p)
    assert len(events) == 4 and not warnings
    assert monitor.stats["closed"] == 1


def test_other_process_and_optional_port_filter():
    monitor, _, events, _ = setup_monitor()
    router = AutoRouter(monitor, output=lambda _: None)
    for packet in trace():
        router.feed("wifi", packet)
    assert not events and not monitor.stats["connections"]
    router = AutoRouter(monitor, ports=[443], output=lambda _: None)
    router.set_owners({key(trace()[0])})
    for packet in trace():
        router.feed("wifi", packet)
    assert not events and not router.candidates


def test_game_non_rf4_connection_not_promoted():
    monitor, _, events, warnings = setup_monitor()
    router = AutoRouter(monitor, output=lambda _: None)
    packets = trace()
    router.set_owners({key(packets[0])})
    for p in packets[:2]:
        router.feed("wifi", p)
    router.feed("wifi", replace(packets[2], payload=b"HTTP/1.1 200 OK\r\n"*4))
    assert not router.selected and not events and not warnings


def test_midstream_notice_no_false_events_and_reconnect():
    monitor, lines, events, warnings = setup_monitor()
    router = AutoRouter(monitor, output=lines.append)
    router.set_owners({key(trace()[0])})
    for p in trace()[2:]:
        router.feed("wifi", p)
    assert len(lines) == 1 and "重新登录" in lines[0] and not events
    for p in trace(close=True):
        router.feed("wifi", p)
    for p in trace(client_isn=2222, server_isn=3333, close=True):
        router.feed("ethernet", replace(p, time=p.time+1))
    assert len(events) == 8 and not warnings
    assert monitor.stats["connections"] == 2


def test_candidate_bounds_and_timeout():
    monitor, _, events, _ = setup_monitor()
    router = AutoRouter(monitor, output=lambda _: None)
    for i in range(200):
        router.feed("wifi", replace(trace()[0], sport=40000+i))
    assert len(router.candidates) == router.MAX_CANDIDATES
    router.tick(10)
    assert not router.candidates
    router.feed("wifi", trace()[0])
    router.feed("wifi", replace(trace()[3], payload=b"x"*router.MAX_BYTES))
    assert not router.candidates and not events


def test_fault_drops_pending_and_abandons_selected_until_new_syn():
    monitor, _, events, _ = setup_monitor()
    router = AutoRouter(monitor, output=lambda _: None)
    router.set_owners({key(trace()[0])})
    for p in trace()[:4]:
        router.feed("wifi", p)
    assert router.selected
    router.fault("test loss")
    for p in trace()[4:]:
        router.feed("wifi", p)
    assert not events
    for p in trace(client_isn=5678, close=True):
        router.feed("wifi", p)
    assert len(events) == 4


def test_packet_parser_all_ports():
    raw = packet_bytes(replace(trace()[0], dport=20001))
    record = Record(raw, 1, 0, len(raw))
    assert parse_packet(record, None).dport == 20001
    assert parse_packet(record, {9341}) is None


def test_process_discovery_name_scope_exit_and_permission():
    import psutil
    address = lambda ip, port: SimpleNamespace(ip=ip, port=port)
    connection = SimpleNamespace(laddr=address("fe80::1%12", 55555), raddr=address("fe80::2%12", 12345))
    def denied(**kwargs):
        raise psutil.AccessDenied(42)
    def exited(**kwargs):
        raise psutil.NoSuchProcess(43)
    processes = [SimpleNamespace(info={"name": "RF4_X64.EXE"}, net_connections=lambda **kw: [connection]),
                 SimpleNamespace(info={"name": "rf4.exe"}, net_connections=denied),
                 SimpleNamespace(info={"name": "rf4.exe"}, net_connections=exited),
                 SimpleNamespace(info={"name": "browser.exe"}, net_connections=lambda **kw: pytest.fail("unrelated process"))]
    backend = SimpleNamespace(process_iter=lambda attrs: processes, AccessDenied=psutil.AccessDenied,
                              NoSuchProcess=psutil.NoSuchProcess, ZombieProcess=psutil.ZombieProcess)
    messages = []
    scanner = GameDiscovery(output=messages.append, backend=backend)
    assert scanner.snapshot() == ({("fe80::1", 55555, "fe80::2", 12345)}, True)
    scanner.snapshot()
    assert len(messages) == 1 and "管理员" in messages[0]


def fake_nonblocking():
    api = FakePcap()
    api.pcap_setnonblock = lambda *args: 0
    return api


def test_auto_capture_real_ctypes_mock(monkeypatch):
    api = fake_nonblocking()
    monkeypatch.setattr("rf4_auto.pcap_api", lambda: (api, "Npcap mock"))
    monkeypatch.setattr("rf4_auto.devices", lambda _: [("wifi", "test adapter")])
    def snapshot(self):
        assert not api.closed and api.freed  # capture opened before polling
        return {key(trace()[0])}, True
    monkeypatch.setattr(GameDiscovery, "snapshot", snapshot)
    monitor, lines, events, warnings = setup_monitor()
    with pytest.raises(KeyboardInterrupt):
        auto_capture(monitor, output=lines.append)
    assert len(events) == 4 and not warnings and api.closed


def test_auto_driver_drop_and_cleanup():
    api = fake_nonblocking()
    monitor, _, _, warnings = setup_monitor()
    router = AutoRouter(monitor, output=lambda _: None)
    reader = ReceiveHandle(api, "wifi")
    router.feed("wifi", trace()[0])
    api.drops = 1
    reader.check_stats(router)
    reader.check_stats(router)
    reader.close()
    assert monitor.stats["capture_faults"] == 1 and not router.candidates
    assert api.closed and warnings


def test_auto_nonblocking_failure_closes_handle():
    api = fake_nonblocking()
    api.pcap_setnonblock = lambda *args: -1
    with pytest.raises(CaptureError):
        ReceiveHandle(api, "wifi")
    assert api.closed and api.freed


def test_cli_defaults_to_auto(monkeypatch):
    called = []
    def capture(monitor, **kwargs):
        called.append(kwargs)
        for packet in trace(close=True):
            monitor.feed(packet)
    monkeypatch.setattr("rf4_auto.auto_capture", capture)
    assert main([]) == 0
    assert called == [{"names": None, "ports": None}]


def test_all_adapters_close_even_when_final_stats_raise(monkeypatch):
    closed = []
    class Reader:
        def __init__(self, api, name):
            self.name = name
        def read(self):
            raise KeyboardInterrupt
        def check_stats(self, router):
            raise OSError("driver disappeared")
        def close(self):
            closed.append(self.name)
    monkeypatch.setattr("rf4_auto.ReceiveHandle", Reader)
    monkeypatch.setattr("rf4_auto.pcap_api", lambda: (None, "Npcap mock"))
    monkeypatch.setattr("rf4_auto.devices", lambda _: [("a", "A"), ("b", "B")])
    monkeypatch.setattr(GameDiscovery, "snapshot", lambda _: (set(), False))
    monitor, *_ = setup_monitor()
    with pytest.raises(KeyboardInterrupt):
        auto_capture(monitor, output=lambda _: None)
    assert set(closed) == {"a", "b"}


def test_discovery_process_exits_while_reading_name():
    import psutil
    class Gone:
        @property
        def info(self):
            raise psutil.NoSuchProcess(42)
    backend = SimpleNamespace(process_iter=lambda attrs: [Gone()], AccessDenied=psutil.AccessDenied,
                              NoSuchProcess=psutil.NoSuchProcess, ZombieProcess=psutil.ZombieProcess)
    assert GameDiscovery(backend=backend).snapshot() == (set(), False)
