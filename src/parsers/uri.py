"""URI 解析器 — 支持 ss/vmess/vless/trojan/hysteria2/hysteria/tuic URI 格式。"""

from __future__ import annotations

import base64
import json
import logging
from typing import Optional
from urllib.parse import parse_qs, unquote, urlparse

from src.models import Node, ProxyType

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# 公共工具
# ---------------------------------------------------------------------------

def safe_b64decode(s: str) -> str:
    """兼容标准/URL-safe base64，自动补齐 padding。"""
    s = s.strip()
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    try:
        return base64.b64decode(s).decode("utf-8", errors="replace")
    except Exception:
        return base64.urlsafe_b64decode(s).decode("utf-8", errors="replace")


def _first(qs: dict, key: str, default: str = "") -> str:
    """从 parse_qs 结果取第一个值。"""
    vals = qs.get(key, [])
    return vals[0] if vals else default


# ---------------------------------------------------------------------------
# 各协议解析
# ---------------------------------------------------------------------------

def parse_ss(uri: str) -> Optional[Node]:
    """解析 ss:// URI (SIP002 + 旧格式)。"""
    body = uri[5:]  # 去掉 "ss://"
    name = ""
    if "#" in body:
        body, name = body.rsplit("#", 1)
        name = unquote(name)

    # SIP002: ss://base64(method:password)@host:port/?plugin=...
    if "@" in body:
        userinfo, hostport = body.split("@", 1)
        # 去掉查询参数
        plugin = None
        plugin_opts = None
        if "?" in hostport:
            hostport, qs_str = hostport.split("?", 1)
            qs = parse_qs(qs_str)
            plugin = _first(qs, "plugin")
            plugin_opts = _first(qs, "plugin-opts")
        host, port_s = hostport.rsplit(":", 1)
        decoded = safe_b64decode(userinfo)
        method, password = decoded.split(":", 1)
    else:
        # 旧格式: ss://base64(method:password@host:port)
        decoded = safe_b64decode(body)
        userinfo, hostport = decoded.rsplit("@", 1)
        method, password = userinfo.split(":", 1)
        host, port_s = hostport.rsplit(":", 1)
        plugin = None
        plugin_opts = None

    return Node(
        name=name or f"SS-{host}",
        proxy_type=ProxyType.SS,
        server=host.strip("[]"),
        port=int(port_s),
        method=method,
        password=password,
        plugin=plugin or None,
        plugin_opts=plugin_opts or None,
    )


def parse_vmess(uri: str) -> Optional[Node]:
    """解析 vmess:// URI (V2RayN JSON base64)。"""
    body = uri[8:]  # 去掉 "vmess://"
    decoded = safe_b64decode(body)
    cfg = json.loads(decoded)

    network = cfg.get("net", "tcp")
    tls_val = cfg.get("tls", "")
    use_tls = tls_val == "tls"

    # allowInsecure 可能为布尔、字符串 "1"/"true" 或整数
    allow_insecure_raw = cfg.get("allowInsecure", "")
    skip_cert = str(allow_insecure_raw).lower() in ("1", "true")

    return Node(
        name=cfg.get("ps", "") or f"VMess-{cfg['add']}",
        proxy_type=ProxyType.VMESS,
        server=cfg["add"],
        port=int(cfg["port"]),
        uuid=cfg["id"],
        alter_id=int(cfg.get("aid", 0)),
        security=cfg.get("scy", "auto"),
        network=network,
        tls=use_tls,
        sni=cfg.get("sni", "") or None,
        skip_cert_verify=skip_cert,
        ws_path=cfg.get("path", "") or None if network == "ws" else None,
        ws_host=cfg.get("host", "") or None if network == "ws" else None,
        grpc_service_name=cfg.get("path", "") or None if network == "grpc" else None,
        h2_path=cfg.get("path", "") or None if network == "h2" else None,
        h2_host=[cfg["host"]] if network == "h2" and cfg.get("host") else None,
        fingerprint=cfg.get("fp", "") or None,
    )


def parse_vless(uri: str) -> Optional[Node]:
    """解析 vless:// URI。"""
    parsed = urlparse(uri)
    qs = parse_qs(parsed.query)

    name = unquote(parsed.fragment) if parsed.fragment else ""
    host = parsed.hostname or ""
    port = parsed.port or 443

    security = _first(qs, "security", "none")
    network = _first(qs, "type", "tcp")
    use_tls = security in ("tls", "reality")

    node = Node(
        name=name or f"VLESS-{host}",
        proxy_type=ProxyType.VLESS,
        server=host,
        port=port,
        uuid=parsed.username or "",
        flow=_first(qs, "flow") or None,
        network=network,
        tls=use_tls,
        sni=_first(qs, "sni") or None,
        fingerprint=_first(qs, "fp") or None,
        alpn=_first(qs, "alpn").split(",") if _first(qs, "alpn") else None,
        skip_cert_verify=_first(qs, "allowInsecure") == "1",
    )

    # Reality
    if security == "reality":
        node.reality_public_key = _first(qs, "pbk") or None
        node.reality_short_id = _first(qs, "sid") or None

    # 传输层
    if network == "ws":
        node.ws_path = _first(qs, "path") or None
        node.ws_host = _first(qs, "host") or None
    elif network == "grpc":
        node.grpc_service_name = _first(qs, "serviceName") or None
    elif network == "h2":
        node.h2_path = _first(qs, "path") or None
        h2host = _first(qs, "host")
        node.h2_host = [h2host] if h2host else None

    return node


def parse_trojan(uri: str) -> Optional[Node]:
    """解析 trojan:// URI。"""
    parsed = urlparse(uri)
    qs = parse_qs(parsed.query)

    name = unquote(parsed.fragment) if parsed.fragment else ""
    host = parsed.hostname or ""
    port = parsed.port or 443
    password = unquote(parsed.username or "")

    security = _first(qs, "security", "tls")
    network = _first(qs, "type", "tcp")

    node = Node(
        name=name or f"Trojan-{host}",
        proxy_type=ProxyType.TROJAN,
        server=host,
        port=port,
        password=password,
        network=network,
        tls=security != "none",
        sni=_first(qs, "sni") or None,
        fingerprint=_first(qs, "fp") or None,
        alpn=_first(qs, "alpn").split(",") if _first(qs, "alpn") else None,
        skip_cert_verify=_first(qs, "allowInsecure") == "1",
    )

    if network == "ws":
        node.ws_path = _first(qs, "path") or None
        node.ws_host = _first(qs, "host") or None
    elif network == "grpc":
        node.grpc_service_name = _first(qs, "serviceName") or None

    return node


def parse_hysteria2(uri: str) -> Optional[Node]:
    """解析 hysteria2:// 或 hy2:// URI。"""
    parsed = urlparse(uri)
    qs = parse_qs(parsed.query)

    name = unquote(parsed.fragment) if parsed.fragment else ""
    host = parsed.hostname or ""
    port = parsed.port or 443
    auth = unquote(parsed.username or "")

    obfs_type = _first(qs, "obfs") or None
    obfs_pw = _first(qs, "obfs-password") or None

    return Node(
        name=name or f"Hy2-{host}",
        proxy_type=ProxyType.HYSTERIA2,
        server=host,
        port=port,
        password=auth,
        tls=True,
        sni=_first(qs, "sni") or None,
        skip_cert_verify=_first(qs, "insecure") == "1",
        obfs=obfs_type,
        obfs_password=obfs_pw,
    )


def parse_hysteria(uri: str) -> Optional[Node]:
    """解析 hysteria:// URI。"""
    parsed = urlparse(uri)
    qs = parse_qs(parsed.query)

    name = unquote(parsed.fragment) if parsed.fragment else ""
    host = parsed.hostname or ""
    port = parsed.port or 443

    return Node(
        name=name or f"Hysteria-{host}",
        proxy_type=ProxyType.HYSTERIA,
        server=host,
        port=port,
        auth=_first(qs, "auth") or None,
        tls=True,
        sni=_first(qs, "peer") or _first(qs, "sni") or None,
        skip_cert_verify=_first(qs, "insecure") == "1",
        alpn=_first(qs, "alpn").split(",") if _first(qs, "alpn") else None,
        obfs=_first(qs, "obfs") or None,
        obfs_password=_first(qs, "obfsParam") or None,
        up_mbps=int(_first(qs, "upmbps", "0")) or None,
        down_mbps=int(_first(qs, "downmbps", "0")) or None,
    )


def parse_tuic(uri: str) -> Optional[Node]:
    """解析 tuic:// URI。"""
    parsed = urlparse(uri)
    qs = parse_qs(parsed.query)

    name = unquote(parsed.fragment) if parsed.fragment else ""
    host = parsed.hostname or ""
    port = parsed.port or 443

    uuid = parsed.username or ""
    password = unquote(parsed.password or "") if parsed.password else ""

    return Node(
        name=name or f"TUIC-{host}",
        proxy_type=ProxyType.TUIC,
        server=host,
        port=port,
        uuid=uuid,
        password=password,
        tls=True,
        sni=_first(qs, "sni") or None,
        alpn=_first(qs, "alpn").split(",") if _first(qs, "alpn") else None,
        skip_cert_verify=_first(qs, "allow_insecure") == "1",
        congestion_control=_first(qs, "congestion_control", "bbr"),
        udp_relay_mode=_first(qs, "udp_relay_mode", "native"),
    )


# ---------------------------------------------------------------------------
# 分发
# ---------------------------------------------------------------------------

_SCHEME_MAP: dict[str, callable] = {
    "ss": parse_ss,
    "vmess": parse_vmess,
    "vless": parse_vless,
    "trojan": parse_trojan,
    "hysteria2": parse_hysteria2,
    "hy2": parse_hysteria2,
    "hysteria": parse_hysteria,
    "tuic": parse_tuic,
}


def parse_uri(uri: str) -> Optional[Node]:
    """根据 scheme 分发到对应解析函数。"""
    uri = uri.strip()
    if not uri or "://" not in uri:
        return None
    scheme = uri.split("://", 1)[0].lower()
    parser = _SCHEME_MAP.get(scheme)
    if not parser:
        return None
    try:
        return parser(uri)
    except Exception as e:
        logger.warning("解析 URI 失败: %s... — %s", uri[:60], e)
        return None


def parse_uri_list(content: str) -> list[Node]:
    """解析 base64 编码的 URI 列表。"""
    # 先尝试 base64 解码
    try:
        decoded = safe_b64decode(content)
        # 如果解码后包含 :// 说明解码成功
        if "://" in decoded:
            content = decoded
    except Exception:
        pass

    nodes: list[Node] = []
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        node = parse_uri(line)
        if node:
            nodes.append(node)
    return nodes
