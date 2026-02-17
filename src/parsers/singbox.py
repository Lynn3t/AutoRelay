"""sing-box JSON 解析器。"""

from __future__ import annotations

import json
import logging
from typing import Optional

from src.models import Node, ProxyType

logger = logging.getLogger(__name__)

_TYPE_MAP = {
    "shadowsocks": ProxyType.SS,
    "vmess": ProxyType.VMESS,
    "vless": ProxyType.VLESS,
    "trojan": ProxyType.TROJAN,
    "hysteria2": ProxyType.HYSTERIA2,
    "hysteria": ProxyType.HYSTERIA,
    "tuic": ProxyType.TUIC,
}


def is_singbox_json(content: str) -> bool:
    """检测内容是否为 sing-box JSON 格式。"""
    try:
        data = json.loads(content)
        return isinstance(data, dict) and "outbounds" in data
    except Exception:
        return False


def parse_singbox_json(content: str) -> list[Node]:
    """从 sing-box JSON 中提取代理节点。"""
    data = json.loads(content)
    outbounds = data.get("outbounds", [])
    if not isinstance(outbounds, list):
        return []

    nodes: list[Node] = []
    for ob in outbounds:
        node = _outbound_to_node(ob)
        if node:
            nodes.append(node)
    return nodes


def _outbound_to_node(ob: dict) -> Optional[Node]:
    """将 sing-box outbound 映射为 Node。"""
    ob_type = ob.get("type", "")
    proxy_type = _TYPE_MAP.get(ob_type)
    if proxy_type is None:
        return None

    try:
        tls_cfg = ob.get("tls") or {}
        transport = ob.get("transport") or {}
        use_tls = tls_cfg.get("enabled", False)

        network = transport.get("type", "tcp") if transport else "tcp"
        # sing-box transport "http" → 内部用 "h2"
        if network == "http":
            network = "h2"

        node = Node(
            name=ob.get("tag", ""),
            proxy_type=proxy_type,
            server=ob.get("server", ""),
            port=int(ob.get("server_port", 0)),
            # 通用
            password=ob.get("password"),
            uuid=ob.get("uuid"),
            # SS
            method=ob.get("method"),
            plugin=_clash_plugin_name(ob.get("plugin")),
            plugin_opts=_parse_singbox_plugin_opts(ob.get("plugin"), ob.get("plugin_opts")),
            # VMess
            alter_id=int(ob.get("alter_id", 0)),
            security=ob.get("security", "auto"),
            # VLESS
            flow=ob.get("flow"),
            # TLS
            tls=use_tls,
            sni=tls_cfg.get("server_name"),
            skip_cert_verify=tls_cfg.get("insecure", False),
            alpn=tls_cfg.get("alpn"),
            fingerprint=(tls_cfg.get("utls") or {}).get("fingerprint"),
            # Reality
            reality_public_key=(tls_cfg.get("reality") or {}).get("public_key"),
            reality_short_id=(tls_cfg.get("reality") or {}).get("short_id"),
            # 传输层
            network=network,
            ws_path=transport.get("path") if network == "ws" else None,
            ws_host=(transport.get("headers") or {}).get("Host") if network == "ws" else None,
            grpc_service_name=transport.get("service_name") if network == "grpc" else None,
            h2_path=transport.get("path") if network == "h2" else None,
            h2_host=(transport.get("host") if isinstance(transport.get("host"), list) else ([transport["host"]] if transport.get("host") else None)) if network == "h2" else None,
            # Hysteria / Hysteria2
            obfs=(ob.get("obfs") or {}).get("type") if isinstance(ob.get("obfs"), dict) else ob.get("obfs"),
            obfs_password=(ob.get("obfs") or {}).get("password") if isinstance(ob.get("obfs"), dict) else None,
            auth=ob.get("auth_str"),
            up_mbps=ob.get("up_mbps"),
            down_mbps=ob.get("down_mbps"),
            # TUIC
            congestion_control=ob.get("congestion_control", "bbr"),
            udp_relay_mode=ob.get("udp_relay_mode", "native"),
        )
        return node
    except Exception as e:
        logger.warning("解析 sing-box outbound 失败: %s — %s", ob.get("tag", "?"), e)
        return None


# ---------------------------------------------------------------------------
# SS plugin 辅助
# ---------------------------------------------------------------------------

_CLASH_PLUGIN_MAP = {
    "obfs-local": "obfs",
    "simple-obfs": "obfs",
}


def _clash_plugin_name(singbox_name: Optional[str]) -> Optional[str]:
    """Map sing-box plugin name back to Clash-style name for internal model."""
    if not singbox_name:
        return None
    return _CLASH_PLUGIN_MAP.get(singbox_name, singbox_name)


def _parse_singbox_plugin_opts(plugin: Optional[str], opts_str: Optional[str]) -> Optional[dict]:
    """Parse sing-box plugin_opts string into a Clash-style dict."""
    if not plugin or not opts_str:
        return None

    normalized = plugin.lower()
    if normalized in ("obfs-local", "simple-obfs"):
        opts: dict = {}
        for part in opts_str.split(";"):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                if k == "obfs":
                    opts["mode"] = v
                elif k == "obfs-host":
                    opts["host"] = v
                else:
                    opts[k] = v
        return opts or None

    if normalized == "v2ray-plugin":
        opts = {}
        for part in opts_str.split(";"):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                opts[k] = v
            elif part == "tls":
                opts["tls"] = True
            elif part == "mux":
                opts["mux"] = True
        return opts or None

    # Generic: return raw string as-is in a dict
    opts = {}
    for part in opts_str.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            opts[k] = v
        elif part:
            opts[part] = True
    return opts or None
