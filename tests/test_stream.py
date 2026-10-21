import random
import struct
from dataclasses import replace
import pytest

from rf4_events import EventFormatter
from rf4_protocol import RC4Stream, try_parse_auth_packet, try_parse_first_frame, read_short_string
from rf4_stream import Monitor, Direction, Segment, StreamError, SessionDecoder, BoundedMap
from tests.fixtures import *


def setup_monitor(**kwargs):
    lines, events, warnings = [], [], []
    formatter = EventFormatter(lines.append, events.append)
    monitor = Monitor(formatter, warning=warnings.append, **kwargs)
    return monitor, lines, events, warnings


def run(packets, **kwargs):
    monitor, lines, events, warnings = setup_monitor(**kwargs)
    for p in packets:
        monitor.feed(p)
    stats = monitor.finish()
    return lines, events, warnings, stats


def test_rc4_known_vector_and_chunking():
    expected = bytes.fromhex("BBF316E8D940AF0AD3")
    assert RC4Stream(b"Key").crypt(b"Plaintext") == expected
    cipher = RC4Stream(b"Key")
    assert cipher.crypt(b"Plain")+cipher.crypt(b"text") == expected


def test_two_rods_keep_room_and_coordinates():
    lines, events, warnings, stats = run(trace(close=True))
    assert not warnings
    assert stats["closed"] == 1
    assert [(e["type"],e.get("gear_id"),e.get("weight_g")) for e in events] == [
        ("incoming",GEAR1,262),("incoming",GEAR2,1384),
        ("keep_response",GEAR1,270),("room",None,500)]
    assert events[0]["fish_key"] == "perch"
    assert events[1]["fish_key"] == "tench"
    assert events[0]["weight_source"] == "setup_hint"
    assert events[2]["weight_source"] == "response"
    assert events[3]["sender"] == "OfflineTester"
    assert any("人物坐标" in line and "368.702" in line for line in lines)
    assert not any(TOKEN.decode() in line for line in lines+warnings)


def test_random_segmentation_reordering_duplicates_and_wrap():
    baseline = run(trace())[1]
    for seed in range(50):
        rng = random.Random(seed)
        packets = trace(0xffffffe0, 0xfffffff0)
        changed = packets[:2]
        fragments = []
        for packet in packets[2:]:
            offset = 0
            while offset < len(packet.payload):
                size = rng.randint(1, 35)
                part = replace(packet, seq=(packet.seq+offset)&0xffffffff,
                               payload=packet.payload[offset:offset+size])
                fragments.append(part)
                if rng.random() < .4:
                    fragments.append(part)
                offset += size
        rng.shuffle(fragments)
        # Arbitrarily interleave both directions. ACK dependencies preserve the
        # request-before-response relation despite capture delivery disorder.
        changed += [replace(p,time=2+i/10000) for i,p in enumerate(fragments)]
        _, events, warnings, _ = run(changed)
        assert events == baseline, (seed, warnings, events)
        assert not warnings, (seed, warnings)


def test_cross_direction_response_waits_for_request():
    packets = trace()
    packets[5],packets[6] = packets[6],packets[5]
    assert run(packets)[1] == run(trace())[1]


def test_buffered_server_frames_drained_when_client_handshake_finishes():
    lines, events = [], []
    decoder = SessionDecoder(EventFormatter(lines.append,events.append))
    cipher = reference_rc4(TOKEN)
    decoder.feed(1,SERVER_UUID+frame(encrypt(cipher,incoming())))
    decoder.feed(0,b"\x01\x00"+struct.pack("<I",len(TOKEN))+TOKEN+frame(b"<hermes>"))
    assert len(events)==1
    assert not decoder.incomplete


def test_missing_data_fails_closed_without_fake_fish():
    packets = trace()
    packet = packets[4]
    packets[4] = replace(packet,seq=packet.seq+10,payload=packet.payload[10:])
    _, events, warnings, stats = run(packets)
    assert not events
    assert stats["invalid_connections"]==1
    assert warnings


def test_midstream_is_not_decoded():
    _, events, warnings, stats = run(trace()[2:])
    assert not events and stats["midstream"]==1 and len(warnings)==1


def test_conflicting_retransmission_invalidates_connection():
    packets = trace()
    bad = replace(packets[3], payload=b"x"+packets[3].payload[1:])
    _,events,warnings,stats=run(packets[:4]+[bad]+packets[4:])
    assert not events and stats["invalid_connections"]==1
    assert "冲突" in warnings[0]


def test_pending_overlap_conflict_and_matching_overlap():
    stream=Direction(99)
    stream.add(Segment(CLIENT,1,SERVER,2,103,flags=0,payload=b"def"))
    with pytest.raises(StreamError):
        stream.add(Segment(CLIENT,1,SERVER,2,102,flags=0,payload=b"cX"))
    stream=Direction(99)
    stream.add(Segment(CLIENT,1,SERVER,2,103,flags=0,payload=b"def"))
    stream.add(Segment(CLIENT,1,SERVER,2,100,flags=0,payload=b"abcde"))
    assert stream.pop(None)+stream.pop(None)==b"abcdef"
    assert stream.pop(None) is None


def test_gap_timeout_then_new_syn_recovers():
    monitor,_,events,warnings=setup_monitor(gap_timeout=1)
    packets=trace()
    for p in packets[:4]: monitor.feed(p)
    p=packets[4]
    monitor.feed(replace(p,seq=p.seq+1,payload=p.payload[1:]))
    monitor.tick(10)
    assert monitor.stats["invalid_connections"]==1
    for p in packets[4:]: monitor.feed(replace(p,time=11))
    assert not events
    for p in trace(20000,30000): monitor.feed(replace(p,time=12+p.time))
    assert len(events)==4


def test_duplicate_syn_does_not_reset_state():
    packets=trace()
    assert run(packets[:4]+packets[:2]+packets[4:])[1]==run(packets)[1]


def test_rst_drops_state_and_requires_new_syn():
    monitor,_,events,_=setup_monitor()
    packets=trace()
    for p in packets[:4]: monitor.feed(p)
    monitor.feed(replace(packets[4],payload=b"",flags=4))
    for p in packets[4:]: monitor.feed(p)
    assert not events
    assert all(c.decoder is None for c in monitor.connections.values())


def test_connection_limits_and_idle_expiry():
    monitor,_,_,_=setup_monitor(max_connections=2,idle_timeout=5)
    for port in range(55000,55005):
        monitor.feed(replace(trace()[0],sport=port))
    assert len(monitor.connections)==2
    monitor.tick(100)
    assert not monitor.connections


def test_bounds_and_malformed_protocol():
    with pytest.raises(ValueError): try_parse_auth_packet(b"\x01\x00"+struct.pack("<I",2**31))
    with pytest.raises(ValueError): try_parse_first_frame(struct.pack("<I",2**31))
    with pytest.raises(ValueError): read_short_string(b"\x10abc",0)
    stream=Direction(0)
    with pytest.raises(StreamError):
        stream.add(Segment(CLIENT,1,SERVER,2,2**25,payload=b"x"))
    cache=BoundedMap(limit=2)
    for i in range(10): cache[i]=i
    assert list(cache)==[8,9]


def test_malformed_auth_does_not_leak_token_or_crash():
    packets=trace()
    packets[3]=replace(packets[3],payload=b"\x01\x00\x08\x00\x00\x00secret\xff\xff")
    _,events,warnings,stats=run(packets)
    assert not events and stats["invalid_connections"]==1
    assert "secret" not in str(warnings)


def test_capture_fault_invalidates_existing_sessions():
    monitor,_,events,_=setup_monitor()
    packets=trace()
    for p in packets[:4]: monitor.feed(p)
    monitor.capture_fault("synthetic capture loss")
    for p in packets[4:]: monitor.feed(p)
    assert not events
    assert monitor.stats["capture_faults"]==1


def test_fin_payload_reordering_and_duplicate_fin():
    packets=trace(close=True)
    # Last server payload plus FIN, with the client's FIN captured afterwards.
    server_data=replace(packets[10],flags=0x19)
    altered=packets[:10]+[server_data,packets[11],server_data,packets[12],packets[13]]
    _,events,warnings,stats=run(altered)
    assert len(events)==4 and not warnings and stats["closed"]==1


def test_fin_before_missing_data_waits_and_then_recovers():
    stream=Direction(99)
    stream.add(Segment(CLIENT,1,SERVER,2,106,flags=1))
    assert stream.pop(None) is None
    stream.add(Segment(CLIENT,1,SERVER,2,103,flags=0,payload=b"def"))
    stream.add(Segment(CLIENT,1,SERVER,2,100,flags=0,payload=b"abc"))
    assert stream.pop(None)==b"abc"
    assert stream.pop(None)==b"def"
    assert stream.pop(None)==b"" and stream.closed and stream.next==107


def test_conflicting_fin_and_data_after_fin():
    stream=Direction(99)
    stream.add(Segment(CLIENT,1,SERVER,2,103,flags=1))
    with pytest.raises(StreamError): stream.add(Segment(CLIENT,1,SERVER,2,104,flags=1))
    with pytest.raises(StreamError): stream.add(Segment(CLIENT,1,SERVER,2,103,flags=0,payload=b"x"))


def test_ack_only_reveals_missing_tail():
    monitor,_,_,warnings=setup_monitor(gap_timeout=1)
    packets=trace()
    for p in packets[:4]: monitor.feed(p)
    # A peer acknowledges bytes the capture never saw, without a later segment
    # in that direction to make the hole otherwise visible.
    monitor.feed(replace(packets[5],payload=b"",time=2))
    monitor.tick(4)
    assert monitor.stats["invalid_connections"]==1 and warnings


def test_handshake_timeout_and_missing_synack():
    monitor,_,_,warnings=setup_monitor()
    monitor.feed(trace()[0])
    monitor.tick(40)
    assert monitor.stats["invalid_connections"]==1
    _,events,warnings,stats=run([trace()[0]]+trace()[2:])
    assert not events and stats["invalid_connections"]==1


def test_retransmission_partly_before_history_window():
    stream=Direction(0)
    data=b"a"*(Direction.HISTORY+100)
    stream.add(Segment(CLIENT,1,SERVER,2,1,flags=0,payload=data))
    assert stream.pop(None)==data
    stream.add(Segment(CLIENT,1,SERVER,2,1,flags=0,payload=data+b"xyz"))
    assert stream.pop(None)==b"xyz"
    assert len(stream.history)==Direction.HISTORY


def test_pending_segment_count_limit():
    stream=Direction(0)
    stream.MAX_PIECES=2
    for seq in (10,20): stream.add(Segment(CLIENT,1,SERVER,2,seq,flags=0,payload=b"x"))
    with pytest.raises(StreamError): stream.add(Segment(CLIENT,1,SERVER,2,30,flags=0,payload=b"x"))


def test_same_tuple_new_syn_resets_independent_keys():
    first=trace(close=True)
    second=[replace(p,time=p.time+1) for p in trace(90000,120000,close=True)]
    _,events,warnings,stats=run(first+second)
    assert not warnings and len(events)==8 and stats["closed"]==2


def test_keep_fallback_is_explicitly_estimated():
    monitor,_,events,_=setup_monitor()
    packets=trace()
    for p in packets[:6]: monitor.feed(p)
    session=next(iter(monitor.connections.values())).decoder
    session.formatter.handle(session,False,response(20,b""))
    assert events[-1]["type"]=="keep_response"
    assert events[-1]["weight_source"]=="setup_hint"
    assert events[-1]["weight_g"]==262


def test_non_target_port_does_not_allocate_connection():
    monitor,*_=setup_monitor()
    monitor.feed(replace(trace()[0],dport=443))
    assert not monitor.connections and not monitor.stats
