#!/usr/bin/env python3
# Copyright (C) 2026 花吹雪又一年
#
# This file is part of Roco-Kingdom-Protocol-Parser-Move-Lite-Server (RMLS).
# Licensed under the GNU Affero General Public License v3.0 only (AGPL-3.0-only).

from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import logging
import queue
import struct
import sys
import threading
import time
import bz2
from collections import deque
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator
from urllib.parse import parse_qs, urlparse

try:
    from Crypto.Cipher import AES
except ImportError as exc:
    raise SystemExit("缺少 pycryptodome。先执行: python -m pip install --user pycryptodome") from exc

from scapy.all import AsyncSniffer, PcapReader, conf, get_if_list  # type: ignore
from scapy.layers.inet import IP, TCP  # type: ignore
from scapy.layers.inet6 import IPv6  # type: ignore

SCRIPT_DIR = Path(__file__).resolve().parent
logger = logging.getLogger(__name__)

MAGIC = b"\x33\x66"
FIXED_HDR_LEN = 21
_KNOWN_CMD_RANGE = range(0x0001, 0x8000)

_MAX_BUFFER_SIZE = 16 * 1024 * 1024
_MAX_PENDING_BYTES = 8 * 1024 * 1024
FLOW_TTL_SECONDS = 10 * 60
FLOW_CLEANUP_INTERVAL_PACKETS = 256

CMD_AUTH_RSP = 0x1002
CMD_DATA = 0x4013
RKPP_IVDECODER_MODE = "Ivdecoder"
RKPP_IVDECODER_AES_IV = bytes(range(16))

_RELAY_PORT_FALLBACK_ERRNOS = frozenset({10013, 10048, 13, 48, 98})
_EVENT_FLUSH_BATCH_SIZE = 8
_EVENT_FLUSH_INTERVAL_SECONDS = 0.05

DEFAULT_PORT = 8195
KEY_FILE = SCRIPT_DIR / "key.txt"
_KEY_STALE_WARNING_SECONDS = 30 * 60

def _remember_iface(
    rows: list[tuple[str, str]],
    seen: set[str],
    name: str,
    detail: str = "",
    aliases: Iterable[str] = (),
) -> None:
    name = name.strip()
    if not name or name in seen:
        return
    rows.append((name, detail.strip()))
    seen.add(name)
    for alias in aliases:
        alias = alias.strip()
        if alias:
            seen.add(alias)

def available_capture_interfaces() -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    seen: set[str] = set()

    try:
        for iface in conf.ifaces.values():
            name = str(getattr(iface, "name", "") or "").strip()
            description = str(getattr(iface, "description", "") or "").strip()
            network_name = str(getattr(iface, "network_name", "") or "").strip()
            display_name = name or network_name or description
            detail_parts = [
                part for part in (description, network_name)
                if part and part != display_name
            ]
            detail = " | ".join(dict.fromkeys(detail_parts))
            _remember_iface(rows, seen, display_name, detail, (description, network_name))
    except Exception:  # pylint: disable=broad-exception-caught
        pass

    try:
        for name in get_if_list():
            _remember_iface(rows, seen, str(name))
    except Exception:  # pylint: disable=broad-exception-caught
        pass

    return rows

def format_capture_interfaces(rows: list[tuple[str, str]] | None = None) -> str:
    if rows is None:
        rows = available_capture_interfaces()
    if not rows:
        return "未能读取本机抓包接口；可手动输入 --iface 使用的接口名。"

    lines = ["可用抓包接口（用于 --iface）："]
    for index, (name, detail) in enumerate(rows, start=1):
        suffix = f"  {detail}" if detail else ""
        lines.append(f"  {index}. {name}{suffix}")
    return "\n".join(lines)

def prompt_iface() -> str:
    rows = available_capture_interfaces()
    if rows:
        print(format_capture_interfaces(rows))
    else:
        print("未能读取本机抓包接口；可手动输入 --iface 使用的接口名。")

    default_iface = next((name for name, _ in rows if name == "以太网"), None)
    if default_iface is None:
        default_iface = rows[0][0] if rows else "以太网"

    while True:
        raw = input(f"接口名/序号 [{default_iface}]: ").strip()
        if not raw:
            return default_iface
        if raw.isdecimal():
            index = int(raw)
            if 1 <= index <= len(rows):
                return rows[index - 1][0]
            print("接口序号超出范围，请重新输入。")
            continue
        return raw

def now_text() -> str:
    return dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

class SessionLogger:
    """同时输出到屏幕和可选文件。"""

    def __init__(self, log_path: Path | None = None) -> None:
        self.log_path = log_path
        self._fp = None if log_path is None else log_path.open("a", encoding="utf-8")

    def log(self, message: str) -> None:
        line = f"[{now_text()}] {message}"
        print(line, flush=True)
        if self._fp is not None:
            self._fp.write(line + "\n")
            self._fp.flush()

    def close(self) -> None:
        if self._fp is not None and not self._fp.closed:
            self._fp.close()

def read_varint(data: bytes, off: int) -> tuple[int, int]:
    value = shift = 0
    cur = off
    while cur < len(data):
        byte = data[cur]
        cur += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, cur
        shift += 7
        if shift > 63:
            raise ValueError(f"varint too large at offset 0x{off:X}")
    raise ValueError(f"unterminated varint at offset 0x{off:X}")

def iter_fields(data: bytes) -> Iterator[tuple[int, int, Any]]:
    off = 0
    n = len(data)
    try:
        while off < n:
            tag, off = read_varint(data, off)
            wire = tag & 7
            fn = tag >> 3
            if wire == 0:
                value, off = read_varint(data, off)
                yield fn, wire, value
            elif wire == 2:
                length, off = read_varint(data, off)
                if off + length > n:
                    return
                yield fn, wire, data[off:off + length]
                off += length
            elif wire == 1:
                if off + 8 > n:
                    return
                yield fn, wire, data[off:off + 8]
                off += 8
            elif wire == 5:
                if off + 4 > n:
                    return
                yield fn, wire, data[off:off + 4]
                off += 4
            else:
                return
    except ValueError:
        return

def _sint32(v: int) -> int:
    """把 varint 解出来的无符号 int 当作 int32 做符号扩展。"""
    v &= 0xFFFFFFFF
    return v - 0x100000000 if v & 0x80000000 else v

_TSF4G_MARKER = b"tsf4g"
_TSF4G_MIN_LEN = 6
_TSF4G_MAX_LEN = 22  # 协议保证 trailer 总长 N ∈ [6,22]（见 TSF4G.md §6）

def _has_tsf4g_trailer(data: bytes) -> bool:
    """plaintext 末尾是否为合法 tsf4g trailer: random(N-6) + "tsf4g" + uint8(N)。"""
    if len(data) < _TSF4G_MIN_LEN:
        return False
    n = data[-1]
    return (
        _TSF4G_MIN_LEN <= n <= _TSF4G_MAX_LEN
        and len(data) >= n
        and data[-6:-1] == _TSF4G_MARKER
    )

def _tsf4g_padding_len(data: bytes) -> int:
    """合法 tsf4g trailer → 返回其总长 N，否则 0。真实流量 N 恒为 [6,21]。"""
    return data[-1] if _has_tsf4g_trailer(data) else 0

MOVE_NOTIFY_OPCODE = 0x0414
MOVE_BATCH_OPCODE = 0x0413
MOVE_REQ_OPCODE = 0x0133
SYNC_PLAYER_STATUS_REQ_OPCODE = 0x0159
CHANGE_MOVE_MODE_REQ_OPCODE = 0x0360
INTERACT_MOVE_REQ_OPCODE = 0x03E8
TRAVEL_TOGETHER_SYNC_REQ_OPCODE = 0x15E5

MOVE_OPCODES = frozenset(
    {
        MOVE_NOTIFY_OPCODE,
        MOVE_BATCH_OPCODE,
        MOVE_REQ_OPCODE,
        SYNC_PLAYER_STATUS_REQ_OPCODE,
        CHANGE_MOVE_MODE_REQ_OPCODE,
        INTERACT_MOVE_REQ_OPCODE,
        TRAVEL_TOGETHER_SYNC_REQ_OPCODE,
    }
)

_ASSET_DATA: dict[str, Any] | None = None
_ASSET_LABEL = "embedded move_proto assets"
_EMBEDDED_ASSET_B85 = (
    'LRx4!F+o`-Q(24eP)h(7x1WFz6o2qPH{Y7S|Nr`64qFGH?_hn3J!uAt<4;`WRI^NV(52`wgKej$PzH&l#Wta%Ajkj!0001Kh'
    ')p38l4?&VX`nO>13+j!Kxj#!14BlDXlbAUpdOP5270K8s%;PeXwWnb00004N)QCnX_HKfdTHvIgnEpgngI;ZDkOqTLTYGeC#'
    '2EnX{hvo009VqXMrdNgNl&M!jY7NB`kX~MXR4C0Z@RH!+&WSFbS0}?Vl3-$gYXZZra%&clGZ7!uy|LcjkG~@Rxq8$9O<=c(f'
    'Wr`-$a?(%p5F-!tb_9umLV?0TSqqJC_4a>pBfDH@MLiKHbjHl|GJcB?pj8mF+P4p1{L6taRo9D@Xa2@n|s*?>%X^DZQs!dgf'
    'u1emliv!e?1{$=rA?l|6mN{>_|1XtPV+t$9<wbl1}g8IpVMly751}@F2YzlNT!N-y)=-=j)OWf5&=~E`A$-UN^Lt@@r$&ok}'
    'R;sGbRJBzpDKr)4Zf|;-%}(-0izut6rM=O+)@JK*yx#RK8P>E-YGmn_r!y`x{-v$%?t)wmi#w{y8B{8k0}k5{w>L6~D>8U8c'
    '-rALxZs>;07QhPih!!R)>suSSz2PWHXSqAYD6bIIYUbMTejrWf@|L0oi2E@H1Kj;WbUPsUmyY__qYAzAAf-3yy^q;$Ifu~PD'
    'HP7&g!~C$(QY%R#j%K+xPd~b3z8pNr{3Pgkh0pB*^&iy7kG|YFG@3`tpFJ0$r0VlSrq=$6S1?WN+em=%GB6M?ou=d?ZF)gd`'
    '@W<pxbuxlM)9w_vnNw`QHxvlX>OB6#P!2pS!Z3GMQ?^6R2HK*>d(J)YMMmdB%kWN1F0E?w(Sp0ay${+`NOwgs_iEu>j3N~l_'
    'r7M4L`%Cg#oETxcvO9?pETrrGE3P>zMQrM9pWGyX3kfb3<N?1rmk!ethTFQ*I3i&@2hx<!ylGz|zB_y^N{V+hF090En00000'
    '00031g{y7hNi3LIoZ`$WS~Y}-3lJiFJ9dPUG=cAj*E!yRd=h37AuZEvNtKr0?(9xxiwg@#sdvegp89EHFBy>9tt~G&jJ#W-?'
    'n}X(T~L-3H>Jk7&Kot-VKqtwx-k&3t|XXUF^&A%X{3eSoMlK&EMlsen7me1h>|+JrH`-*YvWQ?jA*C2KSP5<XQ_=UY4$OUW9'
    'e>f?O$tSmkt$=%0@Gfc4j&~?V>hr{13IX)VIxyY56#lO`a;|Hk!A;zT3l29*@U$nsXexJd~^JRAS|lEs12pT9heyxX`k`v?P'
    '*4SV&aGQOYf@ohfZAW=1;jx^<dv)4}rk?W)6eGZ*AyI-|8d5$>oh3uKnsNVF|2iENV8iSDLY%88Z*jDbiLjD&+#MSBuNaUv_'
    'J(BT%+QB%!Pg;L2TwVt(IWt?A7e$Nf4QShv-AC1J%wGEx{xzQl(4t~Bq8bEc{;cwiI^Q(@v$R=&<SL)CG`hL${am1iU5axsX'
    '<Oqx*8X+AWh3nxcagA*U7hrdV-p8oHIh~g?87H7wGoKjJGE!(>WK^W4I@BaICn<r1-|vzi(gyXoT?(n+znRF`2EKvJF|j_)v'
    'tE=q%W1r-Maa-%a#*Vfb<so;3=!6~=Qt8229d<V6WJ61I3vsrNTCfXXegNnhtiA%P(>LqN1??IdF~%2o3#LXxG%6HL6mTz=g'
    'd!oJnT1Ju)?ZSA3@R})Hd|9?3<;vWJ?ug9rdpLu5U{hm9JCNZen)-F9!UJheMsdLlDc5hOICU4TtqNrmqBlf$LB<hFjm5!^&'
    'hClbUL4H=FRMiTMl-olUW^O^Qj{&gr&#aWvspn5&MnyT7x5pV`ZEf@tCcrNXuZ`Hl2Q+K-XuTwQ3!ck055uOww#a#w9lKCRq'
    'Cp}mkduId1FZoKnX5ViJ97r4ZvB}Wjh;msw~ax-nt`HOC!ib*etj4VQtH5HMP8g#d(U1W=8qAI1*-1Qokxx$exMUxT98}k*4'
    '8B>lFzSvTbWFeQ_WHBmM_B|uGUqbw93TeRaDM@z7J_;bU9;6G8f`b&2FcFB!WFvc?kdVt%=`^YA4T|OH-NPKojE6c}$tPx*t'
    'mp$*m4bxoN+UPR8nhw^9779a4kjy1B1o81a1d5FBLr*QTVVJAaxhYoz>vPKJE5i<c%H}78`E$@xPVZf^u*qO;?8}FKJVnnF!'
    '9OLsZgA<Q0LJLu8=AiTyGO>&wh}jCZf?E0Yo_!qiQxe)zRkNC|_mv3z#^4kB&8z!J%aG1{@5QjR*-FB!`G7jKvdKNJ0d%rkq'
    '3=cRP;>XB3B~iIqe#wg7sMY(|RqbaOMFo!z_Vof=Zp>s2jT(bBj~-qkM~k$y2r1SE0?Zu^18JFx>g!6ZO>`52&P+umk!ZeJ?'
    '7r+Dmh6N^b@9Xq$3O_4A2>HHItCD|ruE_0Mk;8+a9yi3szz5XMHCcTXH2xPmAQZPyf)g)=J&0$KZUoLRdHH<!XmSLrzTf5%&'
    'oekR6!PvbkSkYJ&%pK;u3%GB%vxf3!u%3qtSPZx?Cju0tA)Bo)gQtfJ1ai)taPcW`1G@KQcRdqXE^ISRI}WzVt@jEfoOs5F#'
    'x;`6@Z!{55R{56$2v_?mbcxc-OQX{(@35I%3IB~#nm$!ZsGMIydDMF{uT~ol{oNpPrMcmP~M$%cy@HLo)d!2<jWGdW*9oJgK'
    'Dvx{9~kW*z-?hU%aft0g|dLl|497^&cSiN-cZ~WzL5$v`iD%qWS?CPT}T#MtLDPp|V6r=&W|$U9q!Hfs+Cv93msziG73U9$;'
    'C0hr~UgW#EI%jqFMy8@vYM0rnI5PBixrpgfQw4|Pr#aV{6y`3G;8<6yex85H|O4{Yv}+2&Z^v;QqA_zq#S%cWawETyxy-yI`'
    'wx+@|qv1_5LDm4}5e$u8}Sz+K+i787FY^L`Vwj{K-R%Ehj;$bh&#ieBDi47ZRw0*|UhR|}~o^`R|^!0P~?A==F4K?Xx>m<+m'
    'Z<C)Y$#|qlh$|ZFC>6h#psu1|nv+GSjLGYEmx~E6fN_OdQ#n%JQ%!EoopE)xnKLDLF)XO_X)6y~Ow8Rj%-3nrR}GV7#!v(az'
    'V4GroN!b%Ch@ZGO-7Rv<E7wnn{OMgS!K0qS!KLVnrifgn5C99Hjg=a9Xt99rNFznuj0}n7!*brk0S#JL_{|OEryMBW~;}JIc'
    '=8<&FgTUP{&roY2J9O(`g<|l6?|Y3OFS3PFbxjwnk1F4YI%}873+gNhSv9mXw<TBS?ueBN*|lmiX};a)*wd1mK9}V|UDNLE6'
    'b7x+b_h0tN06paW&9)KUB3go_|%I<ql4pYT3`48sEqnlqB_7jb%U>Jbg`6vzAq3DCpWxO}j-gxOgc6w)F{+Ei$5HW9TgXn|9'
    'd{4GZ2kvt+ujK3T|(F^_t$4t1^#F-^V6(XkohnkTt11x_e7yrZa6l+$8_Aca#aG@a=-k_E'
)

def _load_assets() -> dict[str, Any]:
    global _ASSET_DATA
    if _ASSET_DATA is None:
        try:
            compressed = base64.b85decode(_EMBEDDED_ASSET_B85)
            _ASSET_DATA = json.loads(bz2.decompress(compressed).decode("utf-8"))
        except Exception as exc:  # pylint: disable=broad-exception-caught
            raise SystemExit(f"内嵌资源包解析失败: {_ASSET_LABEL}") from exc
    return _ASSET_DATA

def _load_move_proto_spec() -> dict[str, Any]:
    spec = _load_assets().get("move_proto")
    if not isinstance(spec, dict):
        raise SystemExit(f"内嵌资源包缺少 move_proto: {_ASSET_LABEL}")
    return spec

def _row_cfg(name: str) -> Any:
    cfg = _load_assets().get("row_cfg")
    if not isinstance(cfg, dict):
        raise SystemExit(f"内嵌资源包缺少 row_cfg: {_ASSET_LABEL}")
    return cfg[name]

def _schema_messages() -> dict[str, dict[str, list[str]]]:
    return _load_move_proto_spec()['messages']

def _schema_opcodes() -> dict[str, str]:
    return _load_move_proto_spec()['opcodes']

def _decode_float32(blob: Any) -> float | None:
    if not isinstance(blob, (bytes, bytearray)) or len(blob) != 4:
        return None
    return struct.unpack('<f', bytes(blob))[0]

def _decode_text(blob: Any) -> str:
    if not isinstance(blob, (bytes, bytearray)):
        return ''
    return bytes(blob).decode('utf-8', errors='ignore')

def _signed64(value: int) -> int:
    value &= 0xFFFFFFFFFFFFFFFF
    return value - 0x10000000000000000 if value & 0x8000000000000000 else value

def _assign_schema_value(result: dict[str, Any], name: str, value: Any, repeated: bool) -> None:
    if repeated:
        result.setdefault(name, []).append(value)
        return
    if name not in result:
        result[name] = value
        return
    existing = result[name]
    if isinstance(existing, list):
        existing.append(value)
    elif existing != value:
        result[name] = [existing, value]

def _decode_schema_value(kind: str, wire: int, value: Any) -> Any:
    messages = _schema_messages()
    if kind == 'u':
        return value
    if kind == 'i':
        return _sint32(int(value))
    if kind == 'q':
        return _signed64(int(value))
    if kind == 'b':
        return bool(value)
    if kind == 'f':
        return _decode_float32(value) if wire == 5 else None
    if kind == 'x':
        return bytes(value).hex() if isinstance(value, (bytes, bytearray)) else value
    if kind == 's':
        if isinstance(value, (bytes, bytearray)):
            return _decode_text(value)
        return str(value)
    if kind in messages and isinstance(value, (bytes, bytearray)):
        return _decode_message(kind, bytes(value))
    return None

def _decode_message(message_name: str, blob: bytes) -> dict[str, Any]:
    schema = _schema_messages().get(message_name)
    if not isinstance(schema, dict):
        return {}
    result: dict[str, Any] = {}
    for fn, wire, value in iter_fields(blob):
        entry = schema.get(str(fn))
        if not entry:
            continue
        field_name, type_token = entry
        repeated = type_token.startswith('*')
        kind = type_token[1:] if repeated else type_token
        decoded = _decode_schema_value(kind, wire, value)
        if decoded is None:
            continue
        _assign_schema_value(result, field_name, decoded, repeated)
    return result

def opcode_name(opcode: int) -> str:
    return _schema_opcodes().get(str(int(opcode)), '')

def decode_payload(opcode: int, blob: bytes) -> dict[str, Any] | None:
    message_name = opcode_name(opcode)
    if not message_name:
        return None
    trailer = _tsf4g_padding_len(blob)
    body = blob[:-trailer] if trailer else blob
    return _decode_message(message_name, body)

def safe_decode_payload(opcode: int, blob: bytes) -> tuple[dict[str, Any] | None, str]:
    try:
        return decode_payload(opcode, blob), ""
    except Exception as exc:  # pylint: disable=broad-exception-caught
        return None, str(exc)

# ---- 内嵌资源访问（vec/passthrough 缓存一次） ----
_VEC_PREFIXES: tuple[str, ...] = ()
_PASSTHROUGH: tuple[str, ...] = ()
_PASSTHROUGH_FROM_BASE = frozenset({"space_time_ms", "operator_obj_id"})

def _row_cfg_cached() -> None:
    global _VEC_PREFIXES, _PASSTHROUGH
    if not _VEC_PREFIXES:
        _VEC_PREFIXES = tuple(_row_cfg("vec_prefixes"))
        _PASSTHROUGH = tuple(_row_cfg("relay_passthrough"))

def _vec(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {"x": None, "y": None, "z": None}
    return {axis: value.get(axis) for axis in "xyz"}

def _emit_event(
    out: list[dict[str, Any]],
    row_index: int,
    row: dict[str, Any],
    action_name: str,
    event_class: str,
    content: dict[str, Any],
    *,
    base: dict[str, Any] | None = None,
    batch_index: int | None = None,
    batch_timestamp: Any = None,
    act_index: int | None = None,
    segment_index: int | None = None,
    summary_text: str = "",
) -> None:
    """直接构造对外的移动事件（取代旧的扁平 row + _build_move_events 重打包两层）。"""
    content = content if isinstance(content, dict) else {}
    base = base if isinstance(base, dict) else {}
    event: dict[str, Any] = {
        "row_index": int(row_index),
        "captured_at": row.get("captured_at"),
        "flow_id": row.get("flow_id"),
        "direction": row.get("direction"),
        "seq": row.get("seq"),
        "opcode": row.get("opcode"),
        "opcode_name": str(row.get("opcode_name") or "").strip(),
        "event_class": event_class or "move",
        "action_name": action_name,
    }
    for prefix in _VEC_PREFIXES:
        event[prefix] = _vec(content.get(prefix))
    event["batch_index"] = batch_index
    event["batch_timestamp"] = batch_timestamp
    event["act_index"] = act_index
    event["segment_index"] = segment_index
    event["opencode"] = row.get("opcode_hex") or row.get("opcode")
    event["summary_kind"] = action_name or "move"
    event["summary_text"] = summary_text
    for key in _PASSTHROUGH:
        src = base if key in _PASSTHROUGH_FROM_BASE else content
        event[key] = src.get(key)
    event["content"] = content or {}
    out.append(event)

def _point_pos(value: Any) -> dict[str, Any]:
    if isinstance(value, dict) and isinstance(value.get("pos"), dict):
        return value["pos"]
    return {}

def _point_dir(value: Any) -> dict[str, Any]:
    if isinstance(value, dict) and isinstance(value.get("dir"), dict):
        return value["dir"]
    return {}

def _actor_base(actor: dict[str, Any]) -> dict[str, Any]:
    for key in ("avatar", "npc", "monster"):
        branch = actor.get(key)
        if isinstance(branch, dict) and isinstance(branch.get("base"), dict):
            return branch["base"]
    return {}

def _xyz(d: Any) -> str:
    d = d if isinstance(d, dict) else {}
    return f"({d.get('x')},{d.get('y')},{d.get('z')})"

def _iter_client_move_sources(
    record: dict[str, Any],
) -> Iterable[tuple[int | None, Any, dict[str, Any]]]:
    """按 opcode 把 record 展成 (batch_index, batch_timestamp, notify_dict) 序列。"""
    opcode = int(record.get("opcode", 0) or 0)
    decoded = record.get("_decoded")
    if not isinstance(decoded, dict):
        return
    if opcode == MOVE_NOTIFY_OPCODE:
        yield None, None, decoded
    elif opcode == MOVE_BATCH_OPCODE:
        batch_timestamp = decoded.get("timestamp")
        for batch_index, notify in enumerate(decoded.get("acts") or []):
            if isinstance(notify, dict):
                yield batch_index, batch_timestamp, notify

def _decoded_record(record: dict[str, Any]) -> dict[str, Any]:
    decoded = record.get("_decoded")
    return decoded if isinstance(decoded, dict) else {}

# ---- 直接 opcode（c2s 请求/状态）抽取器 ----
def _extract_zone_scene_move_req(row_index, row, record, out):
    move = _decoded_record(record)
    pos = move.get("to_pos") if isinstance(move.get("to_pos"), dict) else {}
    _emit_event(
        out, row_index, row, "zone_scene_move_req", "request", move,
        summary_text=f"zone_scene_move_req pos={_xyz(pos)} mode={move.get('move_mode')}",
    )

def _extract_zone_scene_interact_move_req(row_index, row, record, out):
    move = _decoded_record(record)
    point = move.get("to_point") if isinstance(move.get("to_point"), dict) else {}
    content = {"to_pos": _point_pos(point), "to_rot": _point_dir(point), **move}
    _emit_event(
        out, row_index, row, "zone_scene_interact_move_req", "request", content,
        summary_text=f"zone_scene_interact_move_req pos={_xyz(content.get('to_pos'))}",
    )

def _extract_zone_scene_sync_player_status_req(row_index, row, record, out):
    s = _decoded_record(record)
    _emit_event(
        out, row_index, row, "zone_scene_sync_player_status_req", "status", s,
        summary_text=f"sync_player_status_req status={s.get('status')} op={s.get('op_code')} sub={s.get('sub_status')}",
    )

def _extract_zone_scene_change_move_mode_req(row_index, row, record, out):
    s = _decoded_record(record)
    _emit_event(
        out, row_index, row, "zone_scene_change_move_mode_req", "status", s,
        summary_text=f"change_move_mode_req move_id={s.get('move_id')} stamina={s.get('stamina')}",
    )

def _extract_travel_together_sync_req(row_index, row, record, out):
    sync = _decoded_record(record)
    content = {"to_pos": sync.get("report_pos"), "speed": sync.get("pos_diff"), **sync}
    _emit_event(
        out, row_index, row, "zone_scene_relation_travel_together_sync_req", "request", content,
        summary_text=f"travel_together_sync_req pos={_xyz(content.get('to_pos'))}",
    )

DIRECT_OPCODE_EXTRACTORS = {
    MOVE_REQ_OPCODE: _extract_zone_scene_move_req,
    INTERACT_MOVE_REQ_OPCODE: _extract_zone_scene_interact_move_req,
    SYNC_PLAYER_STATUS_REQ_OPCODE: _extract_zone_scene_sync_player_status_req,
    CHANGE_MOVE_MODE_REQ_OPCODE: _extract_zone_scene_change_move_mode_req,
    TRAVEL_TOGETHER_SYNC_REQ_OPCODE: _extract_travel_together_sync_req,
}

# ---- 场景 act 抽取器（共享签名: out,row_index,row,batch_index,batch_timestamp,act_index,act,base） ----
def _ex_client_move(out, ri, row, bi, bt, ai, act, base):
    move = act.get("client_move")
    if not isinstance(move, dict):
        return
    _emit_event(
        out, ri, row, "client_move", "client_move", move, base=base,
        batch_index=bi, batch_timestamp=bt, act_index=ai,
        summary_text=f"client_move actor={move.get('actor_id')} pos={_xyz(move.get('to_pos'))} mode={move.get('move_mode')}",
    )

def _ex_server_move(out, ri, row, bi, bt, ai, act, base):
    sm = act.get("server_move")
    if not isinstance(sm, dict):
        return
    positions = sm.get("to_pos_list") or []
    times = sm.get("to_time_list") or []
    dirs = sm.get("to_dir_list") or []
    if isinstance(positions, list) and positions:
        for si, pos in enumerate(positions):
            content = dict(sm)
            content["to_pos"] = pos if isinstance(pos, dict) else {}
            if si < len(times):
                content["time_stamp"] = times[si]
            if si < len(dirs):
                content["custom_mode"] = dirs[si]
            _emit_event(
                out, ri, row, "server_move", "server_move", content, base=base,
                batch_index=bi, batch_timestamp=bt, act_index=ai, segment_index=si,
                summary_text=f"server_move actor={sm.get('actor_id')} segment={si} mode={sm.get('move_mode')}",
            )
        return
    _emit_event(
        out, ri, row, "server_move", "server_move", sm, base=base,
        batch_index=bi, batch_timestamp=bt, act_index=ai,
        summary_text=f"server_move actor={sm.get('actor_id')}",
    )

def _ex_simple_actions(out, ri, row, bi, bt, ai, act, base):
    for key, pos_key, rot_key in _row_cfg("simple_actions"):
        content = act.get(key)
        if not isinstance(content, dict):
            continue
        payload = dict(content)
        if pos_key:
            payload["to_pos"] = content.get(pos_key)
        if rot_key:
            payload["to_rot"] = content.get(rot_key)
        _emit_event(
            out, ri, row, key, "scene_action", payload, base=base,
            batch_index=bi, batch_timestamp=bt, act_index=ai,
            summary_text=f"{key} actor={content.get('actor_id')}",
        )

def _ex_point_actions(out, ri, row, bi, bt, ai, act, base):
    for key, point_key in _row_cfg("point_actions"):
        content = act.get(key)
        if not isinstance(content, dict):
            continue
        point = content.get(point_key) if isinstance(content.get(point_key), dict) else {}
        payload = {"to_pos": _point_pos(point), "to_rot": _point_dir(point), **content}
        _emit_event(
            out, ri, row, key, "scene_action", payload, base=base,
            batch_index=bi, batch_timestamp=bt, act_index=ai,
            summary_text=f"{key} actor={content.get('actor_id')}",
        )

def _ex_actor_enter(out, ri, row, bi, bt, ai, act, base):
    actor_enter = act.get("actor_enter")
    if not isinstance(actor_enter, dict):
        return
    for si, actor in enumerate(actor_enter.get("actors") or []):
        if not isinstance(actor, dict):
            continue
        info = _actor_base(actor)
        pt = info.get("pt") if isinstance(info.get("pt"), dict) else {}
        payload = {
            "actor_id": info.get("actor_id"),
            "target_actor_id": info.get("logic_id"),
            "platform_actor_id": info.get("platform_actor_id"),
            "to_pos": _point_pos(pt),
            "to_rot": _point_dir(pt),
            **info,
        }
        _emit_event(
            out, ri, row, "actor_enter", "scene_actor", payload, base=base,
            batch_index=bi, batch_timestamp=bt, act_index=ai, segment_index=si,
            summary_text=f"actor_enter actor={info.get('actor_id')}",
        )

def _ex_actor_leave(out, ri, row, bi, bt, ai, act, base):
    actor_leave = act.get("actor_leave")
    if not isinstance(actor_leave, dict):
        return
    for si, actor_id in enumerate(actor_leave.get("actor_ids") or []):
        _emit_event(
            out, ri, row, "actor_leave", "scene_actor", {"actor_id": actor_id}, base=base,
            batch_index=bi, batch_timestamp=bt, act_index=ai, segment_index=si,
            summary_text=f"actor_leave actor={actor_id}",
        )

def _ex_actor_num(out, ri, row, bi, bt, ai, act, base):
    actor_num = act.get("actor_num")
    if not isinstance(actor_num, dict):
        return
    payload = {"to_pos": actor_num.get("pos"), **actor_num}
    _emit_event(
        out, ri, row, "actor_num", "scene_actor", payload, base=base,
        batch_index=bi, batch_timestamp=bt, act_index=ai,
        summary_text=f"actor_num total={actor_num.get('total_num')} view={actor_num.get('view_num')}",
    )

def _ex_status_actions(out, ri, row, bi, bt, ai, act, base):
    for key, action_name in _row_cfg("status_actions"):
        content = act.get(key)
        if not isinstance(content, dict):
            continue
        _emit_event(
            out, ri, row, action_name, "status", content, base=base,
            batch_index=bi, batch_timestamp=bt, act_index=ai,
            summary_text=f"{action_name} actor={content.get('actor_id')}",
        )

SCENE_ACT_EXTRACTORS = (
    _ex_client_move, _ex_server_move, _ex_simple_actions, _ex_point_actions,
    _ex_actor_enter, _ex_actor_leave, _ex_actor_num, _ex_status_actions,
)

def build_move_events(
    row_index: int, row: dict[str, Any], parsed_info: dict[str, Any],
) -> list[dict[str, Any]]:
    """把一条解码后的 record 展开成多条对外移动事件。"""
    record = parsed_info.get("record") if isinstance(parsed_info, dict) else None
    if not isinstance(record, dict):
        return []
    opcode = int(record.get("opcode", 0) or 0)
    if opcode not in MOVE_OPCODES:
        return []
    _row_cfg_cached()
    out: list[dict[str, Any]] = []

    direct = DIRECT_OPCODE_EXTRACTORS.get(opcode)
    if direct is not None:
        direct(row_index, row, record, out)
        return out

    for batch_index, batch_timestamp, decoded in _iter_client_move_sources(record):
        acts = decoded.get("acts")
        if not isinstance(acts, list):
            continue
        base = decoded.get("space_base_data") if isinstance(decoded.get("space_base_data"), dict) else {}
        for act_index, act in enumerate(acts):
            if not isinstance(act, dict):
                continue
            for extractor in SCENE_ACT_EXTRACTORS:
                extractor(out, row_index, row, batch_index, batch_timestamp, act_index, act, base)
    return out

def parse_key_text(text: str) -> bytes:
    raw = text.strip()
    msg = "key 必须是 16 字节 ASCII 或 32 位 hex"
    if len(raw) == 16:
        try:
            return raw.encode("ascii")
        except UnicodeEncodeError as exc:
            raise ValueError(msg) from exc
    hex_cand = "".join(c for c in raw if c in "0123456789abcdefABCDEF")
    if len(hex_cand) == 32:
        return bytes.fromhex(hex_cand)
    raise ValueError(msg)

def load_key_from_file(path: str | Path) -> bytes | None:
    path = Path(path)
    if not path.is_file():
        return None
    text = path.read_text(encoding="utf-8", errors="ignore").strip()
    if not text:
        return None

    def _try(value: str) -> bytes | None:
        try:
            return parse_key_text(value)
        except ValueError:
            return None

    lines = text.splitlines()
    if "=" not in lines[0]:
        return _try(lines[0].strip())
    for line in lines:
        prefix, sep, value = line.partition("=")
        value = value.strip()
        if not sep or not value:
            continue
        if prefix == "key_hex" or (prefix == "key_ascii" and value != "<non-ascii>"):
            key = _try(value)
            if key is not None:
                return key
    return None

def load_key_info(path: str | Path) -> dict[str, Any]:
    path = Path(path)
    key = load_key_from_file(path)
    captured_at: dt.datetime | None = None
    if path.is_file():
        text = path.read_text(encoding="utf-8", errors="ignore")
        for line in text.splitlines():
            if not line.startswith("captured_at="):
                continue
            try:
                captured_at = dt.datetime.strptime(line.split("=", 1)[1].strip(), "%Y-%m-%d %H:%M:%S")
            except ValueError:
                captured_at = None
            break
        if captured_at is None:
            captured_at = dt.datetime.fromtimestamp(path.stat().st_mtime)
    age_seconds: int | None = None
    if captured_at is not None:
        age_seconds = max(0, int((dt.datetime.now() - captured_at).total_seconds()))
    return {"path": path, "key": key, "captured_at": captured_at, "age_seconds": age_seconds}

def _format_age(age_seconds: int | None) -> str:
    if age_seconds is None:
        return "unknown"
    hours, remain = divmod(age_seconds, 3600)
    minutes, seconds = divmod(remain, 60)
    if hours:
        return f"{hours}h{minutes:02d}m"
    if minutes:
        return f"{minutes}m{seconds:02d}s"
    return f"{seconds}s"

def decrypt_4013_body(key: bytes, body: bytes) -> tuple[bytes, bytes]:
    if len(body) < 16:
        raise ValueError("0x4013 body 长度不足，无法解密")
    if len(body) % 16 != 0:
        raise ValueError("0x4013 body 不是 16 字节对齐")
    return RKPP_IVDECODER_AES_IV, AES.new(key, AES.MODE_CBC, RKPP_IVDECODER_AES_IV).decrypt(body)

def unwrap_ivdecoder_record(plain: bytes) -> bytes:
    if len(plain) < 16:
        raise ValueError("Ivdecoder 明文长度不足，无法拆出业务 record")
    return plain[16:]

def packet_has_target_port(packet, port: int) -> bool:
    return (
        packet.haslayer(TCP)
        and (int(packet[TCP].sport) == port or int(packet[TCP].dport) == port)
    )

def packet_ip_tuple(packet) -> tuple[str, str] | None:
    for layer in (IP, IPv6):
        if packet.haslayer(layer):
            ip = packet[layer]
            return ip.src, ip.dst
    return None

def flow_key_from_packet(packet, port: int) -> tuple[str, str, int, str, int, str] | None:
    """识别同一会话上的 s2c/c2s，统一返回 (client_ip, direction, client_port, server_ip, server_port, flow_text)。"""
    ip_pair = packet_ip_tuple(packet)
    if ip_pair is None or not packet.haslayer(TCP):
        return None
    src_ip, dst_ip = ip_pair
    tcp = packet[TCP]
    sp, dp = int(tcp.sport), int(tcp.dport)
    if sp == port:
        return dst_ip, "s2c", dp, src_ip, sp, f"{src_ip}:{sp}->{dst_ip}:{dp}"
    if dp == port:
        return src_ip, "c2s", sp, dst_ip, dp, f"{dst_ip}:{dp}->{src_ip}:{sp}"
    return None

@dataclass
class Be21Packet:
    direction: str
    cmd: int
    seq: int
    header_extra: bytes
    body: bytes

def _read_be21_header(data: bytearray, off: int) -> tuple[int, int, int, int] | None:
    if off + FIXED_HDR_LEN > len(data):
        return None
    cmd = int.from_bytes(data[off + 6:off + 8], "big")
    hdr_len = int.from_bytes(data[off + 13:off + 17], "big")
    body_len = int.from_bytes(data[off + 17:off + 21], "big")
    if cmd not in _KNOWN_CMD_RANGE or hdr_len < FIXED_HDR_LEN or (hdr_len + body_len) > 4 * 1024 * 1024:
        return None
    seq = int.from_bytes(data[off + 9:off + 13], "big")
    return cmd, seq, hdr_len, body_len

def parse_be21_from_buffer(
    data: bytearray,
    direction: str,
    start: int,
) -> tuple[list[Be21Packet], int]:
    packets: list[Be21Packet] = []
    off = start
    size = len(data)
    while off + FIXED_HDR_LEN <= size:
        if data[off:off + 2] != MAGIC:
            nxt = data.find(MAGIC, off + 1)
            if nxt < 0:
                break
            off = nxt
            continue
        header = _read_be21_header(data, off)
        if header is None:
            off += 2
            continue
        cmd, seq, hdr_len, body_len = header
        pkt_len = hdr_len + body_len
        if off + pkt_len > size:
            break
        packets.append(
            Be21Packet(
                direction=direction,
                cmd=cmd,
                seq=seq,
                header_extra=bytes(data[off + FIXED_HDR_LEN:off + hdr_len]),
                body=bytes(data[off + hdr_len:off + pkt_len]),
            )
        )
        off += pkt_len
    return packets, off

@dataclass
class DirectionState:
    """把 TCP 段按 seq 重组为连续字节流，再跑 BE21 解析。"""
    direction: str
    buffer: bytearray = field(default_factory=bytearray)
    parse_offset: int = 0
    _base_seq: int | None = None
    _next_contig_seq: int | None = None
    _pending: dict[int, bytes] = field(default_factory=dict)
    _pending_bytes: int = 0

    def feed(self, seq: int, payload: bytes) -> list[Be21Packet]:
        if not payload:
            return []

        if self._base_seq is None:
            self._base_seq = seq
            self.buffer.extend(payload)
            self._next_contig_seq = seq + len(payload)
        else:
            self._ingest_segment(seq, payload)

        if len(self.buffer) > _MAX_BUFFER_SIZE:
            self._trim_buffer()

        packets, new_off = parse_be21_from_buffer(self.buffer, self.direction, self.parse_offset)
        self.parse_offset = new_off

        if self.parse_offset >= 0x10000 and self.parse_offset > len(self.buffer) // 2:
            trim = self.parse_offset
            del self.buffer[:trim]
            if self._base_seq is not None:
                self._base_seq += trim
            self.parse_offset = 0

        return packets

    def _ingest_segment(self, seq: int, payload: bytes) -> None:
        assert self._base_seq is not None
        assert self._next_contig_seq is not None

        end = seq + len(payload)
        if seq < self._base_seq:
            if end < self._base_seq:
                logger.debug(
                    "DirectionState[%s] dropping old segment seq=%d end=%d base=%d",
                    self.direction, seq, end, self._base_seq,
                )
                return
            prepend_len = self._base_seq - seq
            if prepend_len > 0:
                self.buffer = bytearray(payload[:prepend_len]) + self.buffer
                self._base_seq = seq
                self.parse_offset += prepend_len
            if end <= self._next_contig_seq:
                return
            payload = payload[self._next_contig_seq - seq:]
            seq = self._next_contig_seq
            if not payload:
                return

        if seq <= self._next_contig_seq:
            start = seq - self._base_seq
            overlap = self._next_contig_seq - seq
            if overlap > 0 and start >= 0:
                overlap = min(overlap, len(payload))
                existing = bytes(self.buffer[start:start + overlap])
                incoming = payload[:overlap]
                if existing != incoming:
                    if start < self.parse_offset:
                        logger.debug(
                            "DirectionState[%s] ignoring conflicting retransmit seq=%d",
                            self.direction, seq,
                        )
                        return
                    log_func = (
                        logger.debug if existing and all(b == 0 for b in existing)
                        else logger.warning
                    )
                    log_func(
                        "DirectionState[%s] replacing conflicting overlap seq=%d "
                        "(existing=%s incoming=%s)",
                        self.direction, seq, existing[:8].hex(), incoming[:8].hex(),
                    )
                    del self.buffer[start:]
                    self.buffer.extend(payload)
                    self._next_contig_seq = seq + len(payload)
                    self.parse_offset = min(self.parse_offset, start)
                    self._drain_pending()
                    return
            if overlap >= len(payload):
                return
            self.buffer.extend(payload[overlap:])
            self._next_contig_seq += len(payload) - overlap
            self._drain_pending()
            return

        self._store_pending(seq, payload)

    def _store_pending(self, seq: int, payload: bytes) -> None:
        end = seq + len(payload)
        for old_seq, old_payload in list(self._pending.items()):
            old_end = old_seq + len(old_payload)
            if old_seq <= seq and old_end >= end:
                return
            if seq <= old_seq and end >= old_end:
                self._pending_bytes -= len(old_payload)
                del self._pending[old_seq]

        existing = self._pending.get(seq)
        if existing is not None:
            if len(existing) >= len(payload):
                return
            self._pending_bytes -= len(existing)

        self._pending[seq] = payload
        self._pending_bytes += len(payload)

        while self._pending_bytes > _MAX_PENDING_BYTES and self._pending:
            farthest_seq = max(self._pending)
            dropped = self._pending.pop(farthest_seq)
            self._pending_bytes -= len(dropped)
            logger.warning(
                "DirectionState[%s] pending cache exceeded %d bytes, dropping seq=%d",
                self.direction, _MAX_PENDING_BYTES, farthest_seq,
            )

    def _drain_pending(self) -> None:
        assert self._next_contig_seq is not None
        while True:
            ready = [s for s in self._pending if s <= self._next_contig_seq]
            if not ready:
                return
            seq = min(ready)
            payload = self._pending.pop(seq)
            self._pending_bytes -= len(payload)
            overlap = self._next_contig_seq - seq
            if overlap >= len(payload):
                continue
            self.buffer.extend(payload[overlap:])
            self._next_contig_seq += len(payload) - overlap

    def _trim_buffer(self) -> None:
        if not self.buffer:
            return
        logger.warning(
            "DirectionState[%s] buffer exceeded %d bytes, trimming",
            self.direction, _MAX_BUFFER_SIZE,
        )
        desired = _MAX_BUFFER_SIZE // 2
        if self.parse_offset > 0:
            trim = min(self.parse_offset, max(0, len(self.buffer) - desired))
        else:
            trim = max(0, len(self.buffer) - desired)
        if trim <= 0:
            return
        del self.buffer[:trim]
        self.parse_offset = max(0, self.parse_offset - trim)
        if self._base_seq is not None:
            self._base_seq += trim

@dataclass
class FlowState:
    flow_id: str
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    last_seen: float = 0.0
    c2s: DirectionState = field(default_factory=lambda: DirectionState("c2s"))
    s2c: DirectionState = field(default_factory=lambda: DirectionState("s2c"))
    key: bytes | None = None

def parse_live_s2c_record(plain: bytes, seq: int) -> dict[str, Any] | None:
    if len(plain) < 10 or plain[4:6] != b"\x55\xaa":
        return None
    opcode = int.from_bytes(plain[0:4], "big")
    if opcode <= 0 or opcode > 0xFFFF:
        return None
    subtype = int.from_bytes(plain[6:10], "big")
    return {
        "seq": seq,
        "direction": "s2c",
        "opcode": opcode,
        "opcode_hex": f"0x{opcode:04X}",
        "opcode_name": opcode_name(opcode),
        "subtype": subtype,
        "raw_payload": plain[10:],
    }

def normalize_c2s_opcode(raw_opcode: int) -> tuple[int, bool]:
    low16 = raw_opcode & 0xFFFF
    if raw_opcode > 0xFFFF and (raw_opcode >> 16) == 0x0001 and low16:
        return low16, True
    return raw_opcode, False

def parse_live_c2s_record(plain: bytes, seq: int) -> dict[str, Any] | None:
    # 旧版用固定魔数 plain[8:10]==0x3963 作硬闸，但真实抓包该位置随会话变化
    # (实测 7ca2/0000/fae2…)，导致 100% c2s 记录被丢。改用 tsf4g trailer + opcode
    # 结构双重校验：既能容纳变化的 stream 标记，又能拒绝垃圾。
    if len(plain) < 14 or not _has_tsf4g_trailer(plain):
        return None
    prefix_u32 = int.from_bytes(plain[0:4], "big")
    raw_opcode = int.from_bytes(plain[4:8], "big")
    if raw_opcode <= 0 or (raw_opcode >> 16) not in {0x0000, 0x0001} or (raw_opcode & 0xFFFF) == 0:
        return None
    opcode, normalized = normalize_c2s_opcode(raw_opcode)
    req_seq = int.from_bytes(plain[10:14], "big")
    return {
        "seq": seq,
        "direction": "c2s",
        "opcode": opcode,
        "opcode_hex": f"0x{opcode:04X}",
        "opcode_name": opcode_name(opcode),
        "raw_opcode": raw_opcode,
        "raw_opcode_hex": f"0x{raw_opcode:08X}",
        "opcode_normalized": normalized,
        "prefix_u32": prefix_u32,
        "stream_tag": plain[8:10].hex(),  # 旧 0x3963 位置；随会话变化，仅作调试线索
        "req_seq": req_seq,
        "raw_payload": plain[14:],
    }

class OpcodeRelayServer:
    def __init__(
        self,
        *,
        host: str,
        port: int,
        session_logger: SessionLogger,
        history_size: int = 500,
    ) -> None:
        self.host = host
        self.port = port
        self.logger = session_logger
        self._history: deque[tuple[int, dict[str, Any]]] = deque(maxlen=max(1, history_size))
        self._clients: set[queue.Queue[tuple[int, dict[str, Any]] | None]] = set()
        self._lock = threading.Lock()
        self._event_count = 0
        self._next_seq = 0
        self._dropped_client_events = 0
        self._runtime_stats_provider: Callable[[], dict[str, Any]] | None = None
        self._requested_port = port
        self._httpd = self._make_server_with_fallback()
        self._thread = threading.Thread(
            target=self._httpd.serve_forever, name="rkpp-opcode-relay", daemon=True,
        )

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def start(self) -> None:
        if self.port != self._requested_port:
            self.logger.log(
                f"[relay] requested port {self._requested_port} unavailable, "
                f"fallback port={self.port}"
            )
        self._thread.start()
        self.logger.log(f"[relay] listening url={self.url} endpoints=/health,/latest,/events")

    def set_runtime_stats_provider(self, provider: Callable[[], dict[str, Any]]) -> None:
        self._runtime_stats_provider = provider

    def close(self) -> None:
        with self._lock:
            clients = list(self._clients)
        for client in clients:
            self._push_client(client, None)
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join(timeout=2.0)

    def handle(self, row_index: int, row: dict[str, Any], parsed_info: dict[str, Any]) -> None:
        events = self._build_move_events(row_index, row, parsed_info)
        if not events:
            return
        with self._lock:
            self._event_count += len(events)
            seq_items: list[tuple[int, dict[str, Any]]] = []
            for event in events:
                self._next_seq += 1
                pair = (self._next_seq, event)
                self._history.append(pair)
                seq_items.append(pair)
            clients = list(self._clients)
        for pair in seq_items:
            for client in clients:
                self._push_client(client, pair)

    def stats(self) -> dict[str, Any]:
        with self._lock:
            stats = {
                "status": "ok",
                "mode": "move",
                "time": now_text(),
                "events": self._event_count,
                "history": len(self._history),
                "clients": len(self._clients),
                "dropped_client_events": self._dropped_client_events,
            }
        if self._runtime_stats_provider is not None:
            stats.update(self._runtime_stats_provider())
        return stats

    def latest(self, limit: int = 50) -> list[dict[str, Any]]:
        if limit <= 0:
            return []
        with self._lock:
            items = list(self._history)
        return [event for _seq, event in items[-limit:]]

    def _snapshot(self, limit: int = 50) -> list[tuple[int, dict[str, Any]]]:
        if limit <= 0:
            return []
        with self._lock:
            items = list(self._history)
        return items[-limit:]

    def subscribe(self) -> queue.Queue[tuple[int, dict[str, Any]] | None]:
        client: queue.Queue[tuple[int, dict[str, Any]] | None] = queue.Queue(maxsize=1000)
        with self._lock:
            self._clients.add(client)
        return client

    def unsubscribe(self, client: queue.Queue[tuple[int, dict[str, Any]] | None]) -> None:
        with self._lock:
            self._clients.discard(client)

    def _push_client(
        self,
        client: queue.Queue[tuple[int, dict[str, Any]] | None],
        item: tuple[int, dict[str, Any]] | None,
    ) -> None:
        try:
            client.put_nowait(item)
        except queue.Full:
            if item is None:
                try:
                    client.get_nowait()
                    client.put_nowait(None)
                except (queue.Empty, queue.Full):
                    pass
                return
            with self._lock:
                self._dropped_client_events += 1
            try:
                client.get_nowait()
                client.put_nowait(item)
            except (queue.Empty, queue.Full):
                pass

    def _build_move_events(
        self,
        row_index: int,
        row: dict[str, Any],
        parsed_info: dict[str, Any],
    ) -> list[dict[str, Any]]:
        return build_move_events(row_index, row, parsed_info)

    def _make_server_with_fallback(self) -> ThreadingHTTPServer:
        last_exc: OSError | None = None
        for candidate in range(self.port, self.port + 11):
            self.port = candidate
            try:
                return self._make_server()
            except OSError as exc:
                last_exc = exc
                code = getattr(exc, "winerror", None) or getattr(exc, "errno", None)
                if code not in _RELAY_PORT_FALLBACK_ERRNOS:
                    raise
        assert last_exc is not None
        raise last_exc

    def _make_server(self) -> ThreadingHTTPServer:
        relay = self

        class Handler(BaseHTTPRequestHandler):  # pylint: disable=missing-class-docstring
            protocol_version = "HTTP/1.1"

            def log_message(self, _format: str, *args: Any) -> None:  # pylint: disable=arguments-differ
                return

            def do_GET(self) -> None:  # noqa: N802  # pylint: disable=invalid-name
                parsed = urlparse(self.path)
                if parsed.path == "/health":
                    self._send_json(relay.stats())
                    return
                if parsed.path == "/latest":
                    try:
                        limit = int(parse_qs(parsed.query).get("limit", ["50"])[0])
                    except ValueError:
                        self.send_error(400, "invalid limit")
                        return
                    self._send_json(relay.latest(limit))
                    return
                if parsed.path == "/events":
                    self._stream_events()
                    return
                self.send_error(404, "not found")

            def _send_json(self, value: Any) -> None:
                body = json.dumps(value, ensure_ascii=False).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _stream_events(self) -> None:
                client = relay.subscribe()
                self.send_response(200)
                self.send_header("Content-Type", "application/x-ndjson; charset=utf-8")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Connection", "close")
                self.end_headers()
                pending_flush = 0
                last_flush = time.monotonic()
                replayed_seq = 0
                try:
                    for seq, event in relay._snapshot(50):
                        replayed_seq = seq
                        self._write_event(event)
                        pending_flush += 1
                        if pending_flush >= _EVENT_FLUSH_BATCH_SIZE:
                            self.wfile.flush()
                            pending_flush = 0
                            last_flush = time.monotonic()
                    if pending_flush:
                        self.wfile.flush()
                        pending_flush = 0
                        last_flush = time.monotonic()
                    while True:
                        item = client.get()
                        if item is None:
                            break
                        seq, event = item
                        if seq <= replayed_seq:
                            continue  # 已在历史回放阶段发送，避免重复推送
                        self._write_event(event)
                        pending_flush += 1
                        now = time.monotonic()
                        if (
                            pending_flush >= _EVENT_FLUSH_BATCH_SIZE
                            or now - last_flush >= _EVENT_FLUSH_INTERVAL_SECONDS
                        ):
                            self.wfile.flush()
                            pending_flush = 0
                            last_flush = now
                except (BrokenPipeError, ConnectionResetError, OSError):
                    pass
                finally:
                    if pending_flush:
                        try:
                            self.wfile.flush()
                        except (BrokenPipeError, ConnectionResetError, OSError):
                            pass
                    relay.unsubscribe(client)

            def _write_event(self, item: dict[str, Any]) -> None:
                line = json.dumps(item, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"
                self.wfile.write(line)

        return ThreadingHTTPServer((self.host, self.port), Handler)

class RkppAnalyzer:
    def __init__(
        self,
        *,
        port: int,
        session_logger: SessionLogger,
        key_file: Path,
        preset_key: bytes | None,
        preset_key_source: str = "",
        analysis_listeners: tuple[Any, ...] = (),
    ) -> None:
        self.port = port
        self.session_logger = session_logger
        self.key_file = key_file
        self.preset_key = preset_key
        self.current_key = preset_key
        self.preset_key_source = preset_key_source
        self.analysis_listeners = analysis_listeners
        self.should_stop = False
        self.packet_count = 0
        self.key_hits = 0
        self.decoded_rows = 0
        self.business_frames_seen = 0
        self.parsed_business_records = 0
        self.failed_business_records = 0
        self.decode_errors = 0
        self.listener_errors = 0
        self.flow_expirations = 0
        self.flows: dict[tuple[str, int, str, int], FlowState] = {}
        self._warned_stale_key = False

    def stats(self) -> dict[str, Any]:
        return {
            "packets": self.packet_count,
            "key_hits": self.key_hits,
            "rows": self.decoded_rows,
            "parsed": self.parsed_business_records,
            "failed": self.failed_business_records,
            "decode_errors": self.decode_errors,
            "listener_errors": self.listener_errors,
            "has_key": self.current_key is not None,
            "flows": len(self.flows),
            "flow_expirations": self.flow_expirations,
            "flow_ttl_seconds": FLOW_TTL_SECONDS,
        }

    def _cleanup_flows(self, now: float) -> None:
        stale = [
            flow_key for flow_key, flow in self.flows.items()
            if flow.last_seen and now - flow.last_seen > FLOW_TTL_SECONDS
        ]
        for flow_key in stale:
            del self.flows[flow_key]
        if stale:
            self.flow_expirations += len(stale)

    def process_packet(self, packet, frame_no: int | None = None) -> None:
        if not packet_has_target_port(packet, self.port):
            return
        self.packet_count += 1
        now = time.time()
        if self.packet_count % FLOW_CLEANUP_INTERVAL_PACKETS == 0:
            self._cleanup_flows(now)
        payload = bytes(packet[TCP].payload)
        if not payload:
            return
        flow_info = flow_key_from_packet(packet, self.port)
        if flow_info is None:
            return  # 无可识别 IP 层（非 s2c/c2s 端口对），跳过
        client_ip, direction, client_port, server_ip, server_port, flow_text = flow_info
        flow_key = (client_ip, client_port, server_ip, server_port)
        flow = self.flows.get(flow_key)
        if flow is None:
            flow = FlowState(
                flow_id=flow_text,
                client_ip=client_ip, client_port=client_port,
                server_ip=server_ip, server_port=server_port,
                last_seen=now,
                key=self.preset_key,  # 仅继承不可变预置 Key；不继承其它 flow 学到的 current_key
            )
            self.flows[flow_key] = flow
            self.session_logger.log(f"[flow] new flow={flow.flow_id}")
            if self.preset_key:
                self.session_logger.log(
                    f"[key] preset key active flow={flow.flow_id} "
                    f"mode={RKPP_IVDECODER_MODE}"
                )
        else:
            flow.last_seen = now
        direction_state = flow.s2c if direction == "s2c" else flow.c2s
        for be21 in direction_state.feed(int(packet[TCP].seq), payload):
            self._handle_be21(flow, be21, packet, frame_no)

    def _handle_be21(
        self, flow: FlowState, be21: Be21Packet, packet, frame_no: int | None,
    ) -> None:
        if be21.cmd == CMD_AUTH_RSP and len(be21.header_extra) >= 18:
            key = be21.header_extra[2:18]
            if flow.key != key:
                flow.key = key
                self.current_key = key
                self.key_hits += 1
                previous = " refreshed" if self.preset_key is not None else ""
                self.session_logger.log(
                    f"[ack_0x1002{previous}] flow={flow.flow_id} seq={be21.seq} "
                    f"key=latest mode={RKPP_IVDECODER_MODE}"
                )

        if be21.cmd != CMD_DATA or not self.analysis_listeners:
            return
        self.business_frames_seen += 1
        if flow.key is None:
            return

        try:
            _iv, plain = decrypt_4013_body(flow.key, be21.body)
            record_plain = unwrap_ivdecoder_record(plain)
        except ValueError as exc:
            self.failed_business_records += 1
            logger.warning("decrypt failed seq=%s: %s", be21.seq, exc)
            if self.preset_key is not None and not self._warned_stale_key:
                self._warned_stale_key = True
                source = self.preset_key_source or "preset key"
                self.session_logger.log(
                    f"[key_warning] {source} 解密失败，Key 可能已过期，请等待 0x1002 刷新或重新指定 --key"
                )
            return

        if be21.direction == "s2c":
            record = parse_live_s2c_record(record_plain, be21.seq)
        else:
            record = parse_live_c2s_record(record_plain, be21.seq)
        if record is None:
            self.failed_business_records += 1
            return
        self.parsed_business_records += 1

        decoded, decode_error = safe_decode_payload(record["opcode"], record["raw_payload"])
        if decode_error:
            self.decode_errors += 1
            self.failed_business_records += 1
            logger.debug("decode failed seq=%s opcode=%s: %s", be21.seq, record["opcode_hex"], decode_error)
            return
        if decoded is None:
            return  # 已注册 opcode 之外的帧我们不关心
        record["_decoded"] = decoded

        row = {
            "captured_at": now_text(),
            "flow_id": flow.flow_id,
            "direction": be21.direction,
            "seq": be21.seq,
            "opcode": record["opcode"],
            "opcode_hex": record["opcode_hex"],
            "opcode_name": record["opcode_name"],
        }

        row_index = self.decoded_rows
        self.decoded_rows += 1
        parsed_info = {"record": record}
        for listener in self.analysis_listeners:
            try:
                listener.handle(row_index, row, parsed_info)
            except Exception as exc:  # pylint: disable=broad-exception-caught
                self.listener_errors += 1
                self.session_logger.log(
                    f"[listener_error] flow={flow.flow_id} seq={be21.seq} error={exc}"
                )
                logger.exception("analysis listener failed for seq=%s", be21.seq)

def _run_session(analyzer: RkppAnalyzer, args: argparse.Namespace) -> None:
    if args.read_pcap:
        with PcapReader(str(args.read_pcap)) as reader:
            for frame_no, pkt in enumerate(reader, 1):
                analyzer.process_packet(pkt, frame_no)
                if analyzer.should_stop:
                    break
        return
    bpf = None if args.no_bpf else f"tcp port {args.port}"
    sniffer = AsyncSniffer(
        iface=args.iface,
        store=False,
        prn=analyzer.process_packet,
        lfilter=lambda pkt: packet_has_target_port(pkt, args.port),
        filter=bpf,
    )
    sniffer.start()
    try:
        while not analyzer.should_stop:
            time.sleep(0.25)
    except KeyboardInterrupt:
        pass
    finally:
        try:
            sniffer.stop()
        except Exception:  # pylint: disable=broad-exception-caught
            pass

def _verify_opcode_consistency(session_logger: SessionLogger) -> None:
    """Python 侧 opcode 常量与压缩块 opcodes 是双份事实来源，启动时强制对齐。"""
    asset_ops = {int(k) for k in _schema_opcodes()}
    if asset_ops != set(MOVE_OPCODES):
        session_logger.log(
            "[config_error] MOVE_OPCODES 与内嵌 opcodes 不一致 "
            f"(仅常量={sorted(set(MOVE_OPCODES)-asset_ops)} 仅资源={sorted(asset_ops-set(MOVE_OPCODES))})"
        )

def run_command(args: argparse.Namespace) -> int:
    session_logger = SessionLogger()
    _verify_opcode_consistency(session_logger)
    relay: OpcodeRelayServer | None = None
    key_file = KEY_FILE
    preset_key_source = ""

    try:
        key_text = getattr(args, "key", None)
        preset_key = parse_key_text(key_text) if key_text else None
        if preset_key is not None:
            preset_key_source = "--key"
        else:
            key_info = load_key_info(key_file)
            preset_key = key_info["key"]
            if preset_key is not None:
                preset_key_source = key_file.name
                age_seconds = key_info["age_seconds"]
                captured_at = key_info["captured_at"]
                age_text = _format_age(age_seconds)
                if captured_at is not None:
                    session_logger.log(
                        f"[key] using {key_file.name} captured_at={captured_at:%Y-%m-%d %H:%M:%S} age={age_text}"
                    )
                else:
                    session_logger.log(f"[key] using {key_file.name} age={age_text}")
                if age_seconds is not None and age_seconds >= _KEY_STALE_WARNING_SECONDS:
                    session_logger.log(
                        f"[key_warning] {key_file.name} 已超过 {_format_age(_KEY_STALE_WARNING_SECONDS)}，"
                        "若解密失败请更新 Key"
                    )
        if preset_key is None:
            session_logger.log("[key] no preset key; waiting for 0x1002 session key")

        relay = OpcodeRelayServer(
            host=args.relay_host,
            port=args.relay_port,
            history_size=args.relay_history,
            session_logger=session_logger,
        )
        relay.start()

        analyzer = RkppAnalyzer(
            port=args.port,
            session_logger=session_logger,
            key_file=key_file,
            preset_key=preset_key,
            preset_key_source=preset_key_source,
            analysis_listeners=(relay,),
        )
        relay.set_runtime_stats_provider(analyzer.stats)

        mode = "offline" if args.read_pcap else "live"
        session_logger.log(
            f"[startup] mode={mode} iface={args.iface or '<default>'} "
            f"port={args.port} compat_key_file={key_file}"
        )

        try:
            _run_session(analyzer, args)
        except KeyboardInterrupt:
            session_logger.log("[status] keyboard_interrupt stopping")

        session_logger.log(
            f"[summary] packets={analyzer.packet_count} key_hits={analyzer.key_hits} "
            f"rows={analyzer.decoded_rows} "
            f"parsed={analyzer.parsed_business_records} "
            f"failed={analyzer.failed_business_records} "
            f"decode_errors={analyzer.decode_errors} "
            f"listener_errors={analyzer.listener_errors} "
            f"flows={len(analyzer.flows)}"
        )
        if (
            preset_key is not None
            and analyzer.business_frames_seen > 0
            and analyzer.parsed_business_records == 0
            and analyzer.failed_business_records > 0
        ):
            session_logger.log("[key_warning] 当前 Key 无法解密有效业务包，请等待 0x1002 刷新或重新指定 --key")
            return 2
        return 0

    finally:
        for resource in (relay, session_logger):
            if resource is not None:
                resource.close()

def build_interactive_args() -> argparse.Namespace:
    iface = prompt_iface()

    key: str | None = None
    key_info = load_key_info(KEY_FILE)
    if key_info["key"] is not None:
        key = key_info["key"].hex()
        print(f"已读取 {KEY_FILE.name}（最新 Key）")
        if key_info["age_seconds"] is not None and key_info["age_seconds"] >= _KEY_STALE_WARNING_SECONDS:
            print(f"{KEY_FILE.name} 已超过 {_format_age(_KEY_STALE_WARNING_SECONDS)}，若解密失败请更新 Key。")
    if key is None:
        print("未找到 key.txt；可手动输入，或留空等待 0x1002 自动获取。")
        while True:
            raw = input("秘钥（16位ASCII/32位hex，留空继续）: ").strip()
            if not raw:
                break
            try:
                key = parse_key_text(raw).hex()
                break
            except ValueError as e:
                print(f"秘钥格式错误: {e}")

    return argparse.Namespace(
        iface=iface, port=DEFAULT_PORT,
        read_pcap=None, no_bpf=False,
        key=key,
        relay_host="127.0.0.1", relay_port=8765, relay_history=500,
    )

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="RKPP 移动后端：抓 key + 解密 0x4013 + 推送 0x0413/0x0414 移动事件",
        epilog=format_capture_interfaces(),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--iface", help="抓包网卡名；无参数启动时可直接从接口列表选序号")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--read-pcap", type=Path)
    parser.add_argument("--no-bpf", action="store_true")
    parser.add_argument(
        "--key",
        help="可选已知 key，16字节ASCII或32位hex；不填则等待 0x1002 自动获取",
    )
    parser.add_argument("--relay-host", default="127.0.0.1")
    parser.add_argument("--relay-port", type=int, default=8765)
    parser.add_argument("--relay-history", type=int, default=500)
    parser.add_argument(
        "--interactive", action="store_true",
        help="忽略 CLI 参数，进入交互提示（默认无参数时也是）",
    )
    return parser

def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:  # pylint: disable=broad-exception-caught
        pass

    argv = sys.argv[1:]
    if not argv or "--interactive" in argv:
        args = build_interactive_args()
    else:
        args = build_parser().parse_args(argv)
    return run_command(args)

if __name__ == "__main__":
    raise SystemExit(main())
