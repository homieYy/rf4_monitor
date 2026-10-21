"""Synthetic RF4 traffic only. These identifiers/tokens are not real accounts.

Encoders are test-only; the production program has no transmission interface.
"""
import struct
import uuid
from dataclasses import replace
from rf4_stream import Segment

GEAR1 = "11111111-2222-3333-4444-555555555555"
GEAR2 = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
FISH1 = "12345678-1234-5678-1234-567812345678"
FISH2 = "87654321-4321-8765-4321-876543218765"
TOKEN = b"synthetic|offline|test|only"
SERVER_UUID = b"ABCDEF01-2345-6789-ABCD-EF0123456789"
CLIENT, SERVER = "192.0.2.10", "198.51.100.20"


def reference_rc4(key):
    table = list(range(256))
    cursor = 0
    for index in range(256):
        cursor = (cursor + table[index] + key[index % len(key)]) % 256
        table[index], table[cursor] = table[cursor], table[index]
    a = b = 0
    while True:
        a = (a+1) % 256
        b = (b+table[a]) % 256
        table[a], table[b] = table[b], table[a]
        yield table[(table[a]+table[b]) % 256]


def encrypt(generator, data):
    return bytes(value ^ next(generator) for value in data)


def short(text):
    value = text.encode()
    return bytes([len(value)])+value


def guid(value, marker=True):
    return (b"\x0c" if marker else b"")+uuid.UUID(value).bytes_le


def args(count):
    return b"\x03\x03507"+struct.pack("<H", count)


def request(call, main, sub, payload):
    return b"\x01"+struct.pack("<iI", -1, call)+bytes([main, sub])+payload


def response(call, payload):
    return b"\x01"+struct.pack("<iI", -2, call)+payload


def frame(payload, wire=1, kind=0):
    return struct.pack("<IBQ", 9+len(payload), kind, wire)+payload


def incoming(gear=GEAR1, fish=FISH1, key="perch", weight=262, call=10):
    body = args(2)+guid(gear)+b"\x01"+struct.pack("<I", 123)
    body += guid(fish, False)+short(key)+b"\x01"+struct.pack("<fI", 0.25, weight)
    return request(call, 14, 14, body)


def keep(gear=GEAR1, fish=FISH1, call=20):
    return request(call, 14, 5, args(2)+guid(gear)+guid(fish))


def catch(call=20, key="perch", weight=270):
    return response(call, short(key)+struct.pack("<I", weight))


def room():
    # Same typed wire layout that the original parser consumes, independent
    # from production builders (which were removed with the injection path).
    body = args(3)+b"\x01"+struct.pack("<I", 401)+b"\x03\xff\xff"
    body += struct.pack("<IQ", 100, 0)+b"\x03\x03135\x02\x00"
    body += b"\x01"+struct.pack("<I", 400)+b"\x01\x14"+short("perch")
    body += b"\x01"+struct.pack("<I", 400)+b"\x02\x10"+struct.pack("<I", 500)
    body += b"\x14"+short("test_lake")+b"\x10"+struct.pack("<I", 5)
    return request(30, 24, 27, body)


def room_request():
    return request(31, 24, 19, args(1)+b"\x10"+struct.pack("<I", 100))


def room_response():
    block = b"\x01"+struct.pack("<II", 2002, 100)+short("OfflineTester")
    return response(31, b"\x08"+struct.pack("<I", len(block))+block)


def trace(client_isn=1234, server_isn=9000, close=False):
    c, s = client_isn+1, server_isn+1
    result = [Segment(CLIENT, 55000, SERVER, 9341, client_isn, flags=2),
              Segment(SERVER, 9341, CLIENT, 55000, server_isn, c & 0xffffffff, 0x12)]
    def add(from_client, payload=b"", flags=0x18):
        nonlocal c, s
        if from_client:
            result.append(Segment(CLIENT, 55000, SERVER, 9341, c & 0xffffffff, s & 0xffffffff, flags, payload))
            c += len(payload)+bool(flags & 1)
        else:
            result.append(Segment(SERVER, 9341, CLIENT, 55000, s & 0xffffffff, c & 0xffffffff, flags, payload))
            s += len(payload)+bool(flags & 1)
    add(False, SERVER_UUID)
    add(True, b"\x01\x00"+struct.pack("<I", len(TOKEN))+TOKEN+frame(b"<hermes>test</hermes>"))
    client_cipher, server_cipher = reference_rc4(TOKEN), reference_rc4(TOKEN)
    add(False, b"".join(frame(encrypt(server_cipher, p), i+2) for i, p in enumerate([
        incoming(), incoming(GEAR2, FISH2, "tench", 1384, 11), room()])))
    add(True, frame(encrypt(client_cipher, keep()), 5))
    add(False, frame(encrypt(server_cipher, catch()), 6))
    add(True, frame(encrypt(client_cipher, room_request()), 7))
    add(False, frame(encrypt(server_cipher, room_response()), 8))
    add(True, frame(encrypt(client_cipher, request(40, 3, 9,
        args(1)+struct.pack("<ffff", 368.702, 16.208, 444.658, 1.0))), 9))
    add(False, frame(b"", 9, 1))
    if close:
        add(True, flags=0x11)
        add(False, flags=0x11)
        add(True, flags=0x10)
    return [replace(p, time=1+i/100) for i, p in enumerate(result)]


def packet_bytes(segment, ipv6=False, vlan=False):
    from scapy.all import Ether, IP, IPv6, TCP, Raw, Dot1Q
    network = IPv6(src="2001:db8::1" if segment.src==CLIENT else "2001:db8::2",
                   dst="2001:db8::2" if segment.src==CLIENT else "2001:db8::1") if ipv6 else IP(src=segment.src,dst=segment.dst)
    packet = Ether(src="02:00:00:00:00:01",dst="02:00:00:00:00:02")
    if vlan:
        packet /= Dot1Q(vlan=10)
    packet /= network/TCP(sport=segment.sport,dport=segment.dport,seq=segment.seq,
                          ack=segment.ack,flags=segment.flags)/Raw(segment.payload)
    return bytes(packet)


def pcap_bytes(segments, endian="<", nano=False, ipv6=False, vlan=False):
    magic = 0xa1b23c4d if nano else 0xa1b2c3d4
    data = struct.pack(endian+"IHHIIII", magic,2,4,0,0,262144,1)
    for p in segments:
        raw = packet_bytes(p, ipv6, vlan)
        data += struct.pack(endian+"IIII", int(p.time),int((p.time%1)*(1e9 if nano else 1e6)),len(raw),len(raw))+raw
    return data


def ng_block(kind, body, endian="<"):
    body += b"\x00"*((-len(body)) % 4)
    length = len(body)+12
    return struct.pack(endian+"II",kind,length)+body+struct.pack(endian+"I",length)


def pcapng_bytes(segments, endian="<", ipv6=False):
    data = ng_block(0x0a0d0d0a,struct.pack(endian+"IHHq",0x1a2b3c4d,1,0,-1),endian)
    data += ng_block(1,struct.pack(endian+"HHI",1,0,262144),endian)
    for p in segments:
        raw = packet_bytes(p, ipv6)
        stamp = int(p.time*1e6)
        body = struct.pack(endian+"IIIII",0,stamp>>32,stamp&0xffffffff,len(raw),len(raw))+raw
        data += ng_block(6,body,endian)
    return data
