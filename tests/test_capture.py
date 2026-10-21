import ctypes
import json
import struct
import subprocess
import sys
import os
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from rf4_capture import (read_capture, Record, CaptureError, parse_packet,
                         CaptureConsumer, live_capture, devices)
from rf4_monitor import main
from tests.fixtures import *
from tests.test_stream import setup_monitor, run


@pytest.mark.parametrize("endian",["<",">"])
@pytest.mark.parametrize("kind",["pcap","nano","pcapng"])
@pytest.mark.parametrize("ipv6",[False,True])
def test_file_replay_end_to_end(tmp_path,endian,kind,ipv6):
    packets=trace(close=True)
    data=pcapng_bytes(packets,endian,ipv6) if kind=="pcapng" else pcap_bytes(packets,endian,kind=="nano",ipv6)
    path=tmp_path/"test.capture"
    path.write_bytes(data)
    monitor,lines,events,warnings=setup_monitor()
    consumer=CaptureConsumer(monitor)
    for record in read_capture(path): consumer.feed(record)
    stats=monitor.finish()
    assert not warnings and stats["closed"]==1
    assert [e["type"] for e in events]==["incoming","incoming","keep_response","room"]
    assert [e["weight_g"] for e in events]==[262,1384,270,500]


def test_vlan_and_ethernet_padding(tmp_path):
    p=trace()[4]
    for ipv6 in (False,True):
        for vlan in (False,True):
            raw=packet_bytes(p,ipv6,vlan)+b"\x00"*32
            parsed=parse_packet(Record(raw,1,0,len(raw)),{9341})
            assert parsed.payload==p.payload


def test_supported_link_types():
    from scapy.all import IP, IPv6, TCP, Raw, CookedLinux, CookedLinuxV2, Loopback
    ip=IP(src=CLIENT,dst=SERVER)/TCP(sport=55000,dport=9341,seq=123,flags="PA")/Raw(b"abc")
    for link,packet in [(101,ip),(12,ip),(228,ip),(113,CookedLinux(proto=0x800)/ip),
                        (276,CookedLinuxV2(proto=0x800)/ip),(0,Loopback(type=2)/ip)]:
        raw=bytes(packet)
        assert parse_packet(Record(raw,link,0,len(raw)),{9341}).payload==b"abc"


def test_ipv6_extension_header():
    from scapy.all import Ether, IPv6, TCP, Raw
    from scapy.layers.inet6 import IPv6ExtHdrDestOpt
    raw=bytes(Ether(src="02:00:00:00:00:01",dst="02:00:00:00:00:02")/IPv6(src="2001:db8::1",dst="2001:db8::2")/IPv6ExtHdrDestOpt()/TCP(sport=55000,dport=9341)/Raw(b"abc"))
    assert parse_packet(Record(raw,1,0,len(raw)),{9341}).payload==b"abc"


@pytest.mark.parametrize("cut",[1,5,10])
@pytest.mark.parametrize("ng",[False,True])
def test_truncated_file_is_error(tmp_path,cut,ng):
    data=(pcapng_bytes if ng else pcap_bytes)(trace())
    path=tmp_path/"cut.capture"
    path.write_bytes(data[:-cut])
    with pytest.raises(CaptureError): list(read_capture(path))


def test_malformed_capture_headers(tmp_path):
    path=tmp_path/"bad.capture"
    for data in [b"",b"xxxx",b"\xd4\xc3\xb2\xa1",b"\x0a\x0d\x0d\x0a"+b"\xff"*12]:
        path.write_bytes(data)
        with pytest.raises(CaptureError): list(read_capture(path))
    data=bytearray(pcapng_bytes(trace()))
    data[-1]^=1
    path.write_bytes(data)
    with pytest.raises(CaptureError): list(read_capture(path))


def test_multiple_pcapng_sections(tmp_path):
    path=tmp_path/"multi.pcapng"
    path.write_bytes(pcapng_bytes(trace(),"<")+pcapng_bytes(trace(),">"))
    assert len(list(read_capture(path)))==2*len(trace())


def test_pcapng_resolution_offset_and_unknown_block(tmp_path):
    raw=packet_bytes(trace()[0])
    data=ng_block(0x0a0d0d0a,struct.pack("<IHHq",0x1a2b3c4d,1,0,-1))
    opts=struct.pack("<HH",9,1)+b"\x8a\x00\x00\x00" # 2**10 ticks/second
    opts+=struct.pack("<HHq",14,8,100)
    data+=ng_block(1,struct.pack("<HHI",1,0,262144)+opts)
    data+=ng_block(0xabcdef,b"ignored")
    data+=ng_block(6,struct.pack("<IIIII",0,0,1536,len(raw),len(raw))+raw)
    path=tmp_path/"resolution.pcapng"
    path.write_bytes(data)
    assert list(read_capture(path))[0].timestamp==101.5


def test_truncation_and_fragmentation_invalidate_stream():
    from scapy.all import Ether, IP, TCP, Raw
    packets=trace()
    for case in ("truncated","fragment","tcp_header"):
        monitor,_,events,warnings=setup_monitor()
        consumer=CaptureConsumer(monitor)
        for p in packets[:4]:
            raw=packet_bytes(p)
            consumer.feed(Record(raw,1,p.time,len(raw)))
        raw=packet_bytes(packets[4])
        wire=len(raw)
        if case=="truncated": raw=raw[:-1]
        elif case=="fragment":
            raw=bytes(Ether(src="02:00:00:00:00:01",dst="02:00:00:00:00:02")/IP(src=SERVER,dst=CLIENT,flags="MF")/TCP(sport=9341,dport=55000)/Raw(b"abc"))
            wire=len(raw)
        else:
            raw=bytearray(raw)
            raw[14+20+12]=0x10
            raw=bytes(raw)
        consumer.feed(Record(raw,1,2,wire))
        assert not events and monitor.stats["capture_faults"]==1
        assert warnings


def test_unknown_linktype_is_explicit():
    with pytest.raises(CaptureError,match="link type"):
        parse_packet(Record(b"abc",9999,0,3),{9341})


def test_cli_replay_and_json(tmp_path):
    path=tmp_path/"good.pcap"
    out=tmp_path/"events.jsonl"
    path.write_bytes(pcap_bytes(trace(close=True)))
    env=dict(os.environ,PYTHONUTF8="1")
    proc=subprocess.run([sys.executable,"rf4_monitor.py","--read",str(path),"--jsonl",str(out)],
                        capture_output=True,text=True,encoding="utf-8",env=env)
    assert proc.returncode==0,proc.stdout+proc.stderr
    events=[json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
    assert len(events)==4 and events[0]["gear_id"]==GEAR1
    assert "鲈鱼" in proc.stdout
    assert TOKEN.decode() not in proc.stdout+proc.stderr+out.read_text(encoding="utf-8")
    assert main(["--read",str(path),"--jsonl",str(out)])==1


def test_cli_incomplete_returns_nonzero(tmp_path):
    path=tmp_path/"midstream.pcap"
    path.write_bytes(pcap_bytes(trace()[3:]))
    assert main(["--read",str(path)])==2


def test_cli_bad_input_and_args(tmp_path):
    path=tmp_path/"bad.pcap"
    path.write_bytes(b"broken")
    assert main(["--read",str(path)])==1
    with pytest.raises(SystemExit): main(["--read",str(path),"--iface","1"])
    with pytest.raises(SystemExit): main(["--port","65536"])
    with pytest.raises(SystemExit): main(["--read",str(path),"--jsonl",str(path)])


class FakePcap:
    """Exercise the actual ctypes receive loop, including pointer lifetimes."""
    class timeval(ctypes.Structure):
        _fields_=[("tv_sec",ctypes.c_long),("tv_usec",ctypes.c_long)]
    class pcap_pkthdr(ctypes.Structure):
        pass
    pcap_pkthdr._fields_=[("ts",timeval),("caplen",ctypes.c_uint),("len",ctypes.c_uint)]
    class pcap_stat(ctypes.Structure):
        _fields_=[("ps_recv",ctypes.c_uint),("ps_drop",ctypes.c_uint),("ps_ifdrop",ctypes.c_uint)]
    class bpf_program(ctypes.Structure):
        _fields_=[("dummy",ctypes.c_int)]

    def __init__(self, fail_filter=False, drops=0):
        self.raw=[packet_bytes(p) for p in trace(close=True)]
        self.index=0
        self.closed=False
        self.freed=False
        self.fail_filter,self.drops=fail_filter,drops

    def pcap_open_live(self,name,snap,promisc,timeout,error):
        assert snap==262144 and promisc==0 and timeout==100
        return 1
    def pcap_datalink(self,h): return 1
    def pcap_compile(self,*args): return 0
    def pcap_setfilter(self,*args): return -1 if self.fail_filter else 0
    def pcap_freecode(self,*args): self.freed=True
    def pcap_close(self,*args): self.closed=True
    def pcap_stats(self,handle,pointer):
        stats=ctypes.cast(pointer,ctypes.POINTER(self.pcap_stat)).contents
        stats.ps_recv=self.index
        stats.ps_drop=self.drops
        stats.ps_ifdrop=0
        return 0
    def pcap_next_ex(self,handle,header_ptr,data_ptr):
        if self.index>=len(self.raw): raise KeyboardInterrupt
        raw=self.raw[self.index]
        self.header=self.pcap_pkthdr(self.timeval(1,0),len(raw),len(raw))
        self.data=(ctypes.c_ubyte*len(raw)).from_buffer_copy(raw)
        ctypes.cast(header_ptr,ctypes.POINTER(ctypes.POINTER(self.pcap_pkthdr)))[0]=ctypes.pointer(self.header)
        ctypes.cast(data_ptr,ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte)))[0]=ctypes.cast(self.data,ctypes.POINTER(ctypes.c_ubyte))
        self.index+=1
        return 1


def test_mock_live_capture_receive_only_and_cleanup(monkeypatch):
    api=FakePcap()
    monkeypatch.setattr("rf4_capture.pcap_api",lambda:(api,"Npcap mock"))
    monkeypatch.setattr("rf4_capture.devices",lambda api:[("device","test adapter")])
    monitor,lines,events,warnings=setup_monitor()
    with pytest.raises(KeyboardInterrupt): live_capture("1",monitor,lines.append)
    assert len(events)==4 and not warnings
    assert api.closed and api.freed
    assert monitor.stats["driver_received"]==len(trace(close=True))


def test_mock_live_filter_failure_closes_handle(monkeypatch):
    api=FakePcap(fail_filter=True)
    monkeypatch.setattr("rf4_capture.pcap_api",lambda:(api,"Npcap mock"))
    monkeypatch.setattr("rf4_capture.devices",lambda api:[("device","test")])
    monitor,*_=setup_monitor()
    with pytest.raises(CaptureError): live_capture("1",monitor)
    assert api.closed and api.freed


def test_production_has_no_active_transport_or_process_api():
    import ast
    forbidden={"send","sendto","sendall","sendp","sendpfast","sr","srp","socket",
               "connect","bind","listen","pcap_sendpacket","pcap_inject","WriteProcessMemory",
               "ReadProcessMemory","OpenProcess","Popen","run","system"}
    for path in Path('.').glob('rf4_*.py'):
        tree=ast.parse(path.read_text(encoding="utf-8-sig"))
        for node in ast.walk(tree):
            if isinstance(node,ast.Call):
                name=node.func.attr if isinstance(node.func,ast.Attribute) else node.func.id if isinstance(node.func,ast.Name) else ""
                assert name not in forbidden,(path,name)
            if isinstance(node,ast.ImportFrom):
                assert node.module!="mitmproxy"


def test_ipv6_declared_payload_excludes_trailing_bytes():
    raw=bytearray(packet_bytes(trace()[4],ipv6=True))
    struct.pack_into("!H",raw,14+4,20)
    packet=parse_packet(Record(bytes(raw),1,0,len(raw)),{9341})
    assert packet.payload==b""


@pytest.mark.parametrize("link,endian",[(0,"<"),(0,">"),(108,">")])
def test_loopback_byte_order(link,endian):
    raw=packet_bytes(trace()[4])[14:]
    data=struct.pack(endian+"I",2)+raw
    assert parse_packet(Record(data,link,0,len(data)),{9341}).payload==trace()[4].payload


def test_live_drop_counter_is_reported(monkeypatch):
    api=FakePcap()
    original=api.pcap_stats
    def stats(handle,pointer):
        api.drops=int(api.index>=4)
        return original(handle,pointer)
    api.pcap_stats=stats
    counter=iter(range(1000))
    monkeypatch.setattr("rf4_capture.time.monotonic",lambda:next(counter)/2)
    monkeypatch.setattr("rf4_capture.pcap_api",lambda:(api,"Npcap mock"))
    monkeypatch.setattr("rf4_capture.devices",lambda api:[("device","test")])
    monitor,_,events,warnings=setup_monitor()
    with pytest.raises(KeyboardInterrupt): live_capture("1",monitor,lambda _:None)
    assert monitor.stats["capture_faults"]==1
    assert monitor.stats["driver_dropped"]==1
    assert not events and warnings and api.closed


def test_live_timeout_and_read_error_cleanup(monkeypatch):
    api=FakePcap()
    values=iter([0,-1])
    api.pcap_next_ex=lambda *args:next(values)
    monkeypatch.setattr("rf4_capture.pcap_api",lambda:(api,"Npcap mock"))
    monkeypatch.setattr("rf4_capture.devices",lambda api:[("device","test")])
    monitor,*_=setup_monitor()
    with pytest.raises(CaptureError): live_capture("1",monitor,lambda _:None)
    assert api.closed and api.freed


def test_malformed_link_header():
    with pytest.raises(CaptureError): parse_packet(Record(b"abc",1,0,3),{9341})


def test_capture_consumer_ignores_non_target_tcp():
    monitor,*_=setup_monitor()
    consumer=CaptureConsumer(monitor)
    raw=packet_bytes(replace(trace()[0],dport=443))
    consumer.feed(Record(raw,1,0,len(raw)))
    assert monitor.stats=={"captured_packets":1}


def test_truncated_ipv4_header_is_not_silently_ignored():
    raw=bytes.fromhex("0200000000020200000000010800")+b"\x45\x00"
    with pytest.raises(CaptureError): parse_packet(Record(raw,1,0,len(raw)),{9341})


def test_ipv6_fragment_fails_explicitly():
    from scapy.all import Ether,IPv6,TCP,Raw
    from scapy.layers.inet6 import IPv6ExtHdrFragment
    raw=bytes(Ether(src="02:00:00:00:00:01",dst="02:00:00:00:00:02")/
              IPv6(src="2001:db8::1",dst="2001:db8::2")/IPv6ExtHdrFragment(m=1)/
              TCP(sport=55000,dport=9341)/Raw(b"abc"))
    with pytest.raises(CaptureError): parse_packet(Record(raw,1,0,len(raw)),{9341})


def test_cli_empty_capture_is_not_reported_as_success(tmp_path):
    path=tmp_path/"empty.pcap"
    path.write_bytes(pcap_bytes([]))
    assert main(["--read",str(path)])==2


def test_device_enumeration_frees_list():
    class Device(ctypes.Structure): pass
    Device._fields_=[("next",ctypes.POINTER(Device)),("name",ctypes.c_char_p),
                     ("description",ctypes.c_char_p)]
    first=Device(None,b"device",b"fake adapter")
    released=[]
    def find(pointer,error):
        ctypes.cast(pointer,ctypes.POINTER(ctypes.POINTER(Device)))[0]=ctypes.pointer(first)
        return 0
    api=SimpleNamespace(pcap_if_t=Device,pcap_findalldevs=find,
                        pcap_freealldevs=lambda head:released.append(True))
    assert devices(api)==[("device","fake adapter")]
    assert released==[True]
