"""Console formatting and correlation of decoded RF4 business events."""
from __future__ import annotations
import json
import math
import struct
from pathlib import Path
from types import SimpleNamespace
from typing import Dict, List, Optional, Tuple, TYPE_CHECKING
from rf4_protocol import *
if TYPE_CHECKING:
    from rf4_stream import SessionDecoder as FlowSession

class EventFormatter:
    def __init__(self, output=print, event_output=None, telemetry="all"):
        self.output = output
        self.event_output = event_output or (lambda event: None)
        self.options = SimpleNamespace(
            rf4_log_telemetry=True, rf4_telemetry_categories=telemetry,
            rf4_log_room_protocol_details=False,
            rf4_log_low_level_telemetry=False, rf4_log_unknown_telemetry=False,
        )
        self._fish_labels_zh = dict(self.DEFAULT_FISH_LABELS_ZH)
        path = Path(__file__).with_name("fish_labels_zh.json")
        if path.exists():
            labels = json.loads(path.read_text(encoding="utf-8"))
            self._fish_labels_zh.update(labels.get("labels", labels))

    def handle(self, session, from_client, plain):
        # Formatting runs before correlation consumes pending requests.
        telemetry = self._describe_telemetry_frame(session, from_client, plain)
        if telemetry and self._telemetry_enabled(telemetry[0]):
            self.output(telemetry[1])
        envelope = parse_envelope(plain)
        if envelope is None:
            return
        if from_client:
            request = parse_keep_fish_request(envelope, session.profile)
            if request:
                session.keep_requests[request.call_id] = request
            chat = parse_public_chat_request(envelope, session.profile)
            if chat and chat.message:
                self.output(f"你: {self._clean_text(chat.message)}")
            ack = parse_room_ack_request(envelope, session.profile)
            if ack and ack.event_id is not None:
                session.room_ack_calls[envelope.call_id] = ack.event_id
            return

        fish = parse_fish_setup_push(envelope, session.profile)
        if fish:
            session.fish_setup_cache[fish.fish_setup_id] = fish
            if fish.weight_hint_raw and fish.fish_setup_id not in session.announced:
                session.announced[fish.fish_setup_id] = True
                self._fish_event(session, "incoming", fish.fishing_gear_id,
                                 fish.fish_setup_id, fish.fish_key,
                                 fish.weight_hint_raw, "setup_hint")
            return
        broadcast = parse_room_broadcast(envelope, session.profile)
        if broadcast:
            session.room_events[broadcast.event_id] = broadcast
            return
        if envelope.marker != -2:
            return
        request = session.keep_requests.pop(envelope.call_id, None)
        if request:
            catch = extract_catch_summary_from_response(plain)
            meta = session.fish_setup_cache.pop(request.fish_setup_id, None)
            session.announced.pop(request.fish_setup_id, None)
            key = catch.fish_key or (meta.fish_key if meta else None)
            weight = catch.weight_raw or (meta.weight_hint_raw if meta else None)
            if key and weight:
                # Upstream heuristically extracts the result, without a proven
                # success flag. Never present the cached hint as confirmed weight.
                self._fish_event(session, "keep_response", request.fishing_gear_id
                                 or (meta.fishing_gear_id if meta else None),
                                 request.fish_setup_id, key, weight,
                                 "response" if catch.weight_raw else "setup_hint")
            return
        event_id = session.room_ack_calls.pop(envelope.call_id, None)
        ack = parse_room_ack_response(envelope, session.profile)
        if ack:
            event_id = ack.event_id if ack.event_id is not None else event_id
            broadcast = session.room_events.pop(event_id, None)
            line = self._format_room_chat_line(ack.sender_name, broadcast)
            if line:
                self.output(line)
                self.event_output(dict(type="room", connection=session.connection,
                                       event_id=event_id, sender=ack.sender_name,
                                       fish_key=broadcast.fish_key,
                                       weight_g=broadcast.weight_raw, text=line))

    def _fish_event(self, session, phase, gear_id, fish_id, fish_key, weight, source):
        label = "来鱼" if phase == "incoming" else "入护响应"
        qualifier = "预估重量" if source == "setup_hint" else "重量"
        name = self._format_fish_name(fish_key)
        self.output(f"【我自己·{label}】钓组={gear_id or 'unknown'} "
                    f"鱼={name} {qualifier}={self._format_chat_weight(weight)}")
        self.event_output(dict(type=phase, connection=session.connection,
                               gear_id=gear_id, fish_id=fish_id, fish_key=fish_key,
                               fish_name=name, weight_g=weight, weight_source=source))

    SELF_EVENT_PHASE_INCOMING = "incoming"


    SELF_EVENT_PHASE_KEPT = "kept"


    TELEMETRY_CATEGORY_LABELS = {
        "fish": "钓鱼",
        "player": "人物",
        "feed": "投喂",
        "chat": "聊天",
        "room": "房间",
        "session": "会话",
        "unknown": "未知",
    }


    SESSION_COMMAND_LABELS = {
        7: "设置语言",
        8: "反作弊报告",
        9: "反作弊标志",
        15: "进入地图",
        18: "硬件/区域信息",
    }


    PLAYER_COMMAND_LABELS = {
        8: "训练状态",
        9: "人物坐标",
        10: "船只使用",
        11: "篝火操作",
        12: "落水状态",
        13: "厨房进食",
        14: "钓具辅助",
        15: "纺车辅助",
        16: "领奖",
        17: "鱼获奖杯",
        18: "警告列表",
        19: "已读警告",
        20: "改名",
        21: "改地区",
        22: "读取邮箱",
        23: "设置邮箱",
        24: "验证邮箱",
        25: "提交封禁信息",
        26: "封禁信息",
        27: "弹吉他",
    }


    SERVER_PLAYER_COMMAND_LABELS = {
        1: "下发玩家资料",
        2: "下发玩家状态",
        6: "下发技能信息",
        8: "下发成就信息",
    }


    FISHING_COMMAND_LABELS = {
        1: "准备抛竿",
        2: "抛竿",
        3: "落点/实钩上下文",
        4: "结束钓鱼",
        5: "入护请求",
        6: "放生鱼",
        7: "钓鱼过程位置上报",
        8: "搏鱼拉力",
        9: "拉线动作",
        10: "请求鱼讯",
        11: "进入搏鱼阶段",
        12: "接触/脱离",
        14: "来鱼信息",
        15: "鱼同步",
    }


    FEEDING_COMMAND_LABELS = {
        1: "打窝/投喂",
    }


    DEFAULT_FISH_LABELS_ZH = {
        "a.sleeper": "葛氏鲈塘鳢",
        "a_smelt": "亚洲胡瓜鱼",
        "barsch": "俄罗斯梭吻鲈",
        "c.carp": "金鲫",
        "c_bleak": "欧鲌",
        "c_nase": "大鼻软口鱼",
        "c.roach": "常见拟鲤",
        "crucian": "银鲫",
        "dace": "雅罗鱼",
        "e.chub": "诸子鲦",
        "osetr_ship": "裸腹鲟",
        "perch": "鲈鱼",
        "ripus": "拉多加白鲑",
        "ruffe": "梅花鲈",
        "ruffe_n": "长吻梅花鲈",
        "s.bream": "银鲷鱼",
        "s.orfe": "圆腹雅罗鱼",
        "tench": "丁鱥",
    }


    GRADE_LABELS_BY_LINE_TYPE = {
        26: "蓝",
    }


    RECORD_CLASS_LABELS = {
        "BL": "底钓",
        "DEF": "常规",
        "L": "轻",
        "PICKER": "Picker",
        "SEA": "海钓",
        "TL": "手竿",
        "UL": "超轻",
    }


    def _telemetry_enabled(self, category: str) -> bool:
        if not bool(getattr(self.options, "rf4_log_telemetry", True)):
            return False
        raw_categories = str(getattr(self.options, "rf4_telemetry_categories", "all") or "all")
        categories = {item.strip().lower() for item in raw_categories.split(",") if item.strip()}
        if not categories or "all" in categories or "*" in categories:
            return True
        if "none" in categories or "off" in categories or "false" in categories:
            return False
        return category.lower() in categories


    def _room_protocol_details_enabled(self) -> bool:
        return bool(getattr(self.options, "rf4_log_room_protocol_details", False))


    def _low_level_telemetry_enabled(self) -> bool:
        return bool(getattr(self.options, "rf4_log_low_level_telemetry", False))


    def _describe_telemetry_frame(
        self,
        session: FlowSession,
        from_client: bool,
        plain_body: bytes,
    ) -> Optional[tuple[str, str]]:
        envelope = parse_envelope(plain_body)
        if envelope is None:
            if not bool(getattr(self.options, "rf4_log_unknown_telemetry", False)):
                return None
            direction = "C->S" if from_client else "S->C"
            return "unknown", f"{self._format_direction(direction)} 原始包 | 可读文本={self._format_ascii_strings(plain_body, limit=4)}"

        direction = "C->S" if from_client else "S->C"
        kind = "request" if envelope.marker == -1 else "response"
        prefix = self._telemetry_prefix(direction, kind, envelope)

        if from_client:
            keep_request = parse_keep_fish_request(envelope, session.profile)
            if keep_request:
                return (
                    "fish",
                    f"请求把鱼入护 | 钓组={self._short_id(keep_request.fishing_gear_id)} "
                    f"鱼编号={self._short_id(keep_request.fish_setup_id)}",
                )

            public_chat = parse_public_chat_request(envelope, session.profile)
            if public_chat:
                return "chat", f"发送公共聊天 | 内容={self._quote_text(self._clean_text(public_chat.message or ''))}"

            ack_request = parse_room_ack_request(envelope, session.profile)
            if ack_request:
                if self._room_protocol_details_enabled():
                    return "room", f"{prefix} 补全房间消息发送者 | 消息ID={ack_request.event_id}"
                return None

            known = self._describe_known_client_business_telemetry(session, prefix, envelope)
            if known:
                return known

        else:
            fish_setup = parse_fish_setup_push(envelope, session.profile)
            if fish_setup:
                weight = self._format_chat_weight(fish_setup.weight_hint_raw) if fish_setup.weight_hint_raw else "unknown"
                length = f"{fish_setup.length_hint:.3f}" if fish_setup.length_hint is not None else "unknown"
                return (
                    "fish",
                    f"有鱼靠近 | 鱼={self._format_fish_name(fish_setup.fish_key)} "
                    f"鱼名key={fish_setup.fish_key} 预估重量={weight} 长度={length} "
                    f"鱼编号={self._short_id(fish_setup.fish_setup_id)} 钓组={self._short_id(fish_setup.fishing_gear_id)}",
                )

            broadcast = parse_room_broadcast(envelope, session.profile)
            if broadcast:
                if not self._room_protocol_details_enabled():
                    return None
                summary = self._format_room_push_summary(broadcast)
                if summary:
                    return "room", f"{prefix} {summary}"
                return None

            request_event_id = session.room_ack_calls.get(envelope.call_id)
            ack_response = parse_room_ack_response(envelope, session.profile)
            if ack_response:
                if not self._room_protocol_details_enabled():
                    return None
                event_id = ack_response.event_id if ack_response.event_id is not None else request_event_id
                return (
                    "room",
                    f"{prefix} 房间消息发送者已补全 | 消息ID={event_id} "
                    f"玩家={self._quote_text(ack_response.sender_name or '')} 等级={ack_response.sender_rank}",
                )

            keep_request = session.keep_requests.get(envelope.call_id)
            if keep_request and envelope.marker == -2:
                catch = extract_catch_summary_from_response(plain_body)
                fish_key = catch.fish_key
                weight_raw = catch.weight_raw
                if keep_request.fish_setup_id:
                    meta = session.fish_setup_cache.get(keep_request.fish_setup_id)
                    if meta:
                        fish_key = fish_key or meta.fish_key
                        weight_raw = weight_raw or meta.weight_hint_raw
                fish_name = self._format_fish_name(fish_key) if fish_key else "unknown"
                weight = self._format_chat_weight(weight_raw) if weight_raw else "unknown"
                weight_label = "重量" if catch.weight_raw else "预估重量"
                return (
                    "fish",
                    f"入护响应 | 鱼={fish_name} 鱼名key={fish_key or 'unknown'} "
                    f"{weight_label}={weight} 规格={catch.size_enum} 鱼编号={self._short_id(keep_request.fish_setup_id)}",
                )

            known = self._describe_known_server_business_telemetry(session, prefix, envelope)
            if known:
                return known

        if not bool(getattr(self.options, "rf4_log_unknown_telemetry", False)):
            return None
        if envelope.main_cmd is not None and envelope.sub_cmd is not None:
            return "unknown", f"{prefix} 未识别业务包 | 可读文本={self._format_ascii_strings(envelope.payload, limit=4)}"
        return "unknown", f"{prefix} 未识别响应包 | 可读文本={self._format_ascii_strings(envelope.payload, limit=4)}"


    def _describe_known_client_business_telemetry(
        self,
        session: FlowSession,
        prefix: str,
        envelope: RpcEnvelope,
    ) -> Optional[tuple[str, str]]:
        if envelope.marker != -1 or envelope.main_cmd is None or envelope.sub_cmd is None:
            return None

        profile = session.profile
        main_cmd = envelope.main_cmd
        sub_cmd = envelope.sub_cmd
        if main_cmd == profile.session_main_cmd:
            label = self.SESSION_COMMAND_LABELS.get(sub_cmd)
            if label:
                return "session", self._format_business_line(label, self._format_generic_business_payload(envelope.payload))
            return None

        if main_cmd == profile.player_main_cmd:
            label = self.PLAYER_COMMAND_LABELS.get(sub_cmd)
            if not label:
                return None
            if sub_cmd == 9:
                return "player", self._format_business_line(label, self._format_scene_pose_payload(envelope.payload))
            return "player", self._format_business_line(label, self._format_generic_business_payload(envelope.payload))

        if main_cmd == profile.feeding_main_cmd:
            label = self.FEEDING_COMMAND_LABELS.get(sub_cmd)
            if label:
                return "feed", self._format_business_line(label, self._format_generic_business_payload(envelope.payload))
            return None

        if main_cmd != profile.fishing_main_cmd:
            return None

        label = self.FISHING_COMMAND_LABELS.get(sub_cmd)
        if not label:
            return None
        if sub_cmd == profile.fight_step_sub_cmd:
            details = self._format_fish_move_payload(envelope.payload)
        elif sub_cmd == profile.fight_load_sub_cmd:
            details = self._format_fight_load_payload(envelope.payload)
        elif sub_cmd == profile.fight_stage_sub_cmd:
            details = self._format_fight_stage_payload(envelope.payload)
        elif sub_cmd == profile.contact_left_sub_cmd:
            details = self._format_contact_left_payload(envelope.payload)
        else:
            details = self._format_generic_business_payload(envelope.payload)
        return "fish", self._format_business_line(label, details)


    def _describe_known_server_business_telemetry(
        self,
        session: FlowSession,
        prefix: str,
        envelope: RpcEnvelope,
    ) -> Optional[tuple[str, str]]:
        if envelope.marker != -1 or envelope.main_cmd is None or envelope.sub_cmd is None:
            return None

        profile = session.profile
        if envelope.main_cmd == profile.server_player_main_cmd:
            if not self._low_level_telemetry_enabled():
                return None
            label = self.SERVER_PLAYER_COMMAND_LABELS.get(envelope.sub_cmd)
            if label:
                return "player", self._format_business_line(label, self._format_generic_business_payload(envelope.payload))
            return None

        if envelope.main_cmd == profile.fishing_main_cmd:
            label = self.FISHING_COMMAND_LABELS.get(envelope.sub_cmd)
            if label:
                return "fish", self._format_business_line(label, self._format_generic_business_payload(envelope.payload))
        return None


    @staticmethod
    def _format_business_line(label: str, details: str) -> str:
        if not details:
            return label
        if details.startswith("="):
            return f"{label} {details}"
        return f"{label} | {details}"


    def _format_scene_pose_payload(self, payload: bytes) -> str:
        summary = self._summarize_business_payload(payload)
        group = self._first_float_group(summary, minimum=4) or self._first_float_group(summary, minimum=3)
        if group and len(group) >= 3:
            return f"={self._format_float_tuple(group[:3])}"
        parts = self._format_summary_tail(summary, include_u32=False, include_float_groups=False)
        return self._join_business_parts(parts, payload)


    def _format_fish_move_payload(self, payload: bytes) -> str:
        summary = self._summarize_business_payload(payload)
        parts: List[str] = []
        gear = self._first_guid(summary)
        if gear:
            parts.append(f"钓组={self._short_id(gear)}")
        group = self._first_float_group(summary, minimum=3)
        if group and len(group) >= 3:
            parts.append(f"钓组坐标={self._format_float_tuple(group[:3])}")
        parts.extend(self._format_summary_tail(summary, include_guids=False, include_u32=False, include_float_groups=False))
        return self._join_business_parts(parts, payload)


    def _format_fight_load_payload(self, payload: bytes) -> str:
        summary = self._summarize_business_payload(payload)
        parts: List[str] = []
        gear = self._first_guid(summary)
        if gear:
            parts.append(f"钓组={self._short_id(gear)}")
        group = self._first_float_group(summary, minimum=4)
        if group and len(group) >= 4:
            parts.append(f"拉力方向={self._format_float_tuple((group[0], group[1], group[3]))}")
            parts.append(f"负载={self._format_float(group[2])}")
        elif group and len(group) >= 3:
            parts.append(f"向量={self._format_float_tuple(group[:3])}")
        tick = self._last_u32(summary)
        if tick is not None:
            parts.append(f"序号={tick}")
        parts.extend(self._format_summary_tail(summary, include_guids=False, include_u32=False, include_float_groups=False))
        return self._join_business_parts(parts, payload)


    def _format_fight_stage_payload(self, payload: bytes) -> str:
        summary = self._summarize_business_payload(payload)
        parts: List[str] = []
        if len(summary.guids) >= 1:
            parts.append(f"钓组={self._short_id(summary.guids[0])}")
        if len(summary.guids) >= 2:
            parts.append(f"鱼编号={self._short_id(summary.guids[1])}")
        group = self._first_float_group(summary, minimum=3)
        if group and len(group) >= 3:
            parts.append(f"状态值={self._format_float_tuple(group[:4])}")
        tick = self._last_u32(summary)
        if tick is not None:
            parts.append(f"序号={tick}")
        parts.extend(self._format_summary_tail(summary, include_guids=False, include_u32=False, include_float_groups=False))
        return self._join_business_parts(parts, payload)


    def _format_contact_left_payload(self, payload: bytes) -> str:
        summary = self._summarize_business_payload(payload)
        parts: List[str] = []
        if len(summary.guids) >= 1:
            parts.append(f"钓组={self._short_id(summary.guids[0])}")
        if len(summary.guids) >= 2:
            parts.append(f"鱼编号={self._short_id(summary.guids[1])}")
        if summary.u32_values:
            parts.append(f"原因/序号={summary.u32_values[0]}")
        group = self._first_float_group(summary, minimum=3)
        if group and len(group) >= 3:
            parts.append(f"状态值={self._format_float_tuple(group[:4])}")
        parts.extend(self._format_summary_tail(summary, include_guids=False, include_u32=False, include_float_groups=False))
        return self._join_business_parts(parts, payload)


    def _format_generic_business_payload(self, payload: bytes) -> str:
        summary = self._summarize_business_payload(payload)
        parts = self._format_arg_prefix(summary)
        parts.extend(self._format_summary_tail(summary))
        return self._join_business_parts(parts, payload)


    def _summarize_business_payload(self, payload: bytes) -> BusinessPayloadSummary:
        arg_count = None
        try:
            arg_count, _ = read_arg_header(payload, 0)
        except (ValueError, IndexError):
            arg_count = None
        strings = self._scan_payload_strings(payload, limit=6)
        guids = self._scan_guid_markers(payload, limit=4)
        u32_values = self._scan_marked_u32_values(payload, limit=6)
        float_groups = self._scan_float_groups(payload, limit=4)
        return BusinessPayloadSummary(
            arg_count=arg_count,
            strings=strings,
            guids=guids,
            u32_values=u32_values,
            float_groups=float_groups,
        )


    def _scan_payload_strings(self, data: bytes, limit: int) -> Tuple[str, ...]:
        values: List[str] = []
        pos = 0
        while len(values) < limit and pos < len(data):
            idx = data.find(b"\x14", pos)
            if idx < 0:
                break
            try:
                value, next_pos = read_marked_string(data, idx)
            except (ValueError, IndexError, UnicodeDecodeError):
                pos = idx + 1
                continue
            if value and self._payload_string_is_interesting(value):
                values.append(self._clean_text(value))
            pos = max(next_pos, idx + 1)

        for value in ascii_strings(data, min_len=8):
            if len(values) >= limit:
                break
            if self._payload_string_is_interesting(value):
                values.append(self._clean_text(value))

        return tuple(self._unique_limited(values, limit))


    @staticmethod
    def _payload_string_is_interesting(value: str) -> bool:
        text = value.strip()
        if not text or text in {"507", "135"}:
            return False
        if "\ufffd" in text:
            return False
        if len(text) <= 2 and text.isascii():
            return False
        if text.isascii() and len(text) < 6 and not any(ch in text for ch in "._[]"):
            return False
        if all(ch.isdigit() or ch in ".-_:/" for ch in text):
            return False
        return True


    @staticmethod
    def _scan_guid_markers(data: bytes, limit: int) -> Tuple[str, ...]:
        values: List[str] = []
        pos = 0
        while len(values) < limit and pos + 17 <= len(data):
            idx = data.find(b"\x0c", pos)
            if idx < 0 or idx + 17 > len(data):
                break
            raw = data[idx + 1:idx + 17]
            if raw != b"\x00" * 16:
                try:
                    value = guid_le(raw)
                except (ValueError, AttributeError):
                    pos = idx + 1
                    continue
                if value not in values:
                    values.append(value)
            pos = idx + 17
        return tuple(values)


    @staticmethod
    def _scan_marked_u32_values(data: bytes, limit: int) -> Tuple[int, ...]:
        values: List[int] = []
        pos = 0
        while len(values) < limit and pos + 5 <= len(data):
            idx = data.find(b"\x10", pos)
            if idx < 0 or idx + 5 > len(data):
                break
            value = u32(data, idx + 1)
            if 0 <= value <= 0x7FFFFFFF and value not in values:
                values.append(value)
            pos = idx + 5
        return tuple(values)


    def _scan_float_groups(self, data: bytes, limit: int) -> Tuple[Tuple[float, ...], ...]:
        groups: List[Tuple[float, ...]] = []
        pos = 0
        while len(groups) < limit and pos + 12 <= len(data):
            group = self._read_float_group_at(data, pos, 4)
            if group is None:
                group = self._read_float_group_at(data, pos, 3)
            if group is None:
                pos += 1
                continue
            if not groups or not self._same_float_group(groups[-1], group):
                groups.append(group)
            pos += len(group) * 4
        return tuple(groups)


    def _read_float_group_at(self, data: bytes, pos: int, count: int) -> Optional[Tuple[float, ...]]:
        if pos + count * 4 > len(data):
            return None
        values = struct.unpack_from("<" + "f" * count, data, pos)
        if not self._usable_float_group(values):
            return None
        return tuple(values)


    @staticmethod
    def _usable_float_group(values: Tuple[float, ...]) -> bool:
        if not values:
            return False
        usable = []
        for value in values:
            if not math.isfinite(value):
                return False
            if abs(value) > 100000.0:
                return False
            if value != 0.0 and abs(value) < 0.000001:
                return False
            usable.append(value)
        if not any(abs(value) >= 0.01 for value in usable):
            return False
        return True


    @staticmethod
    def _same_float_group(left: Tuple[float, ...], right: Tuple[float, ...]) -> bool:
        if len(left) != len(right):
            return False
        return all(abs(a - b) < 0.0001 for a, b in zip(left, right))


    @staticmethod
    def _format_arg_prefix(summary: BusinessPayloadSummary) -> List[str]:
        return [f"参数={summary.arg_count}"] if summary.arg_count is not None else []


    def _format_summary_tail(
        self,
        summary: BusinessPayloadSummary,
        include_guids: bool = True,
        include_u32: bool = True,
        include_float_groups: bool = True,
    ) -> List[str]:
        parts: List[str] = []
        if include_guids and summary.guids:
            parts.append("编号=[" + ", ".join(self._short_id(value) for value in summary.guids) + "]")
        if summary.strings:
            parts.append("文本=[" + ", ".join(self._quote_text(value, limit=40) for value in summary.strings) + "]")
        if include_u32 and summary.u32_values:
            parts.append("数值=[" + ", ".join(str(value) for value in summary.u32_values) + "]")
        if include_float_groups and summary.float_groups:
            parts.append("浮点=[" + ", ".join(self._format_float_tuple(group) for group in summary.float_groups[:3]) + "]")
        return parts


    @staticmethod
    def _join_business_parts(parts: List[str], payload: bytes) -> str:
        if parts:
            return " ".join(parts)
        return f"原始长度={len(payload)}字节"


    @staticmethod
    def _first_guid(summary: BusinessPayloadSummary) -> Optional[str]:
        return summary.guids[0] if summary.guids else None


    @staticmethod
    def _last_u32(summary: BusinessPayloadSummary) -> Optional[int]:
        return summary.u32_values[-1] if summary.u32_values else None


    @staticmethod
    def _first_float_group(summary: BusinessPayloadSummary, minimum: int) -> Optional[Tuple[float, ...]]:
        for group in summary.float_groups:
            if len(group) >= minimum:
                return group
        return None


    def _format_float_tuple(self, values: Tuple[float, ...]) -> str:
        return "(" + ",".join(self._format_float(value) for value in values) + ")"


    @staticmethod
    def _format_float(value: float) -> str:
        if math.isnan(value):
            return "nan"
        if math.isinf(value):
            return "+inf" if value > 0 else "-inf"
        if abs(value) > 1000000.0 or (value != 0.0 and abs(value) < 0.000001):
            return f"{value:.3e}"
        text = f"{value:.3f}".rstrip("0").rstrip(".")
        return text if text else "0"


    @staticmethod
    def _unique_limited(values: List[str], limit: int) -> List[str]:
        out: List[str] = []
        for value in values:
            if value in out:
                continue
            out.append(value)
            if len(out) >= limit:
                break
        return out


    @staticmethod
    def _telemetry_prefix(direction: str, kind: str, envelope: RpcEnvelope) -> str:
        kind_text = "请求" if kind == "request" else "响应"
        parts = [EventFormatter._format_direction(direction), f"{kind_text}#{envelope.call_id}"]
        if envelope.main_cmd is not None and envelope.sub_cmd is not None:
            parts.append(f"协议{envelope.main_cmd}/{envelope.sub_cmd}")
        return " ".join(parts)


    @staticmethod
    def _format_direction(direction: str) -> str:
        return "客户端->服务器" if direction == "C->S" else "服务器->客户端"


    def _format_room_push_summary(self, broadcast: RoomBroadcast) -> Optional[str]:
        if not broadcast.fish_key or not broadcast.weight_raw:
            if self._room_protocol_details_enabled():
                return f"房间状态更新 | {self._format_room_telemetry(broadcast)}"
            return None

        fish_name = self._format_fish_name(broadcast.fish_key)
        weight = self._format_chat_weight(broadcast.weight_raw)
        grade = self._format_grade_label(broadcast.line_type)
        if broadcast.line_type in {21, 22}:
            record_class = self._record_class_label(broadcast)
            label = f"频道记录[{record_class}]" if record_class else "频道记录"
            text = f"{label}：有人钓到 {fish_name} {weight}"
        elif grade:
            text = f"频道鱼获：有人钓到 [{grade}] {fish_name} {weight}"
        else:
            text = f"频道鱼获：有人钓到 {fish_name} {weight}"

        extras = []
        if broadcast.location_id:
            extras.append(f"地点={broadcast.location_id}")
        if broadcast.users_count is not None:
            extras.append(f"房间人数={broadcast.users_count}")
        if self._room_protocol_details_enabled():
            extras.append(f"消息ID={broadcast.event_id}")
            extras.append(f"类型={broadcast.line_type}")
        if extras:
            return f"{text}（{'，'.join(extras)}）"
        return text


    def _format_room_telemetry(self, broadcast: RoomBroadcast) -> str:
        parts = [
            f"事件={broadcast.event_id}",
            f"类型={broadcast.line_type}",
        ]
        if broadcast.fish_key:
            parts.append(f"鱼={self._format_fish_name(broadcast.fish_key)}")
            parts.append(f"鱼名key={broadcast.fish_key}")
        if broadcast.weight_raw:
            parts.append(f"重量={self._format_chat_weight(broadcast.weight_raw)}")
        if broadcast.location_id:
            parts.append(f"地点={broadcast.location_id}")
        if broadcast.users_count is not None:
            parts.append(f"人数={broadcast.users_count}")
        details = self._format_room_detail_items(broadcast.details)
        if details:
            parts.append(f"明细={details}")
        return " ".join(parts)


    @staticmethod
    def _format_room_detail_items(details: Tuple[RoomDetailItem, ...]) -> str:
        if not details:
            return ""
        formatted = []
        for item in details[:8]:
            kind = "文本" if item.kind == "string" else "数值" if item.kind == "u32" else item.kind
            formatted.append(f"{item.slot}:{kind}={item.value}")
        if len(details) > 8:
            formatted.append("...")
        return "[" + ", ".join(formatted) + "]"


    @staticmethod
    def _short_id(value: Optional[str]) -> str:
        if not value:
            return "unknown"
        if len(value) <= 12:
            return value
        return value[:8] + "..."


    def _format_room_chat_line(self, sender_name: Optional[str], broadcast: Optional[RoomBroadcast]) -> Optional[str]:
        if not broadcast:
            return None
        if broadcast.weight_raw and broadcast.fish_key:
            if broadcast.line_type in {21, 22}:
                return self._format_record_chat_line(sender_name or "unknown", broadcast)
            return self._format_catch_chat_line(
                sender_name or "unknown",
                broadcast.fish_key,
                broadcast.weight_raw,
                line_type=broadcast.line_type,
            )
        if broadcast.fish_key:
            text = self._clean_text(broadcast.fish_key)
            if sender_name:
                return f"{sender_name}: {text}"
            return text
        return None


    def _format_catch_chat_line(
        self,
        sender_name: str,
        fish_key: str,
        weight_raw: int,
        line_type: Optional[int] = None,
    ) -> str:
        fish_name = self._format_fish_name(fish_key)
        grade = self._format_grade_label(line_type)
        if grade:
            return f"{sender_name} 钓到了 [{grade}] {self._format_chat_weight(weight_raw)} {fish_name}"
        return f"{sender_name} 钓到了 {self._format_chat_weight(weight_raw)} {fish_name}"


    def _format_record_chat_line(self, sender_name: str, broadcast: RoomBroadcast) -> str:
        fish_name = self._format_fish_name(broadcast.fish_key or "")
        record_class = self._record_class_label(broadcast)
        if record_class:
            return f"{sender_name} 记录[{record_class}] 钓到了 {self._format_chat_weight(broadcast.weight_raw or 0)} {fish_name}"
        return f"{sender_name} 记录 钓到了 {self._format_chat_weight(broadcast.weight_raw or 0)} {fish_name}"


    def _format_fish_name(self, fish_key: str) -> str:
        return self._fish_labels_zh.get(fish_key, fish_key)


    def _format_grade_label(self, line_type: Optional[int]) -> Optional[str]:
        if line_type is None:
            return None
        return self.GRADE_LABELS_BY_LINE_TYPE.get(line_type)


    def _record_class_label(self, broadcast: RoomBroadcast) -> Optional[str]:
        for item in broadcast.details:
            if item.slot == 6 and item.kind == "string" and item.value:
                return self.RECORD_CLASS_LABELS.get(str(item.value), str(item.value))
        return None


    @staticmethod
    def _format_chat_weight(weight_raw: int) -> str:
        if weight_raw < 1000:
            return f"{weight_raw} 克"
        return f"{weight_raw / 1000:.3f} 公斤"


    @staticmethod
    def _clean_text(text: str) -> str:
        return " ".join(text.replace("\r", " ").replace("\n", " ").split())


    @staticmethod
    def _format_ascii_strings(data: bytes, limit: int = 8) -> str:
        values = []
        for value in ascii_strings(data, min_len=4):
            if value in values:
                continue
            values.append(value)
            if len(values) >= limit:
                break
        if not values:
            return "<none>"
        compact = [EventFormatter._quote_text(value, limit=80) for value in values]
        joined = ", ".join(compact)
        if len(values) >= limit and len(ascii_strings(data, min_len=4)) > limit:
            joined += ", ..."
        return joined


    @staticmethod
    def _quote_text(text: str, limit: int = 120) -> str:
        compact = text.replace("\\", "\\\\").replace('"', '\\"').replace("\r", "\\r").replace("\n", "\\n")
        if len(compact) > limit:
            compact = compact[:limit - 3] + "..."
        return f'"{compact}"'
