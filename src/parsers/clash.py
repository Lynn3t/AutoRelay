"""Clash YAML 解析器。"""

from __future__ import annotations

import logging
from typing import Optional

import yaml

from src.models import Node, ProxyType

logger = logging.getLogger(__name__)

_TYPE_MAP = {
    "ss": ProxyType.SS,
    "vmess": ProxyType.VMESS,
    "vless": ProxyType.VLESS,
    "trojan": ProxyType.TROJAN,
    "hysteria2": ProxyType.HYSTERIA2,
    "hysteria": ProxyType.HYSTERIA,
    "tuic": ProxyType.TUIC,
}


def is_clash_yaml(content: str) -> bool:
    """检测内容是否为 Clash YAML 格式。"""
    try:
        data = yaml.safe_load(content)
        return isinstance(data, dict) and "proxies" in data
    except Exception:
        return False


def parse_clash_yaml(content: str) -> list[Node]:
    """从 Clash YAML 中提取节点列表。"""
    data = yaml.safe_load(content)
    proxies = data.get("proxies", [])
    if not isinstance(proxies, list):
        return []

    nodes: list[Node] = []
    for proxy in proxies:
        node = _proxy_to_node(proxy)
        if node:
            nodes.append(node)
    return nodes


def _proxy_to_node(p: dict) -> Optional[Node]:
    """将 Clash proxy 字典映射为 Node。保留 raw_config 以便输出时复用。"""
    proxy_type = _TYPE_MAP.get(p.get("type", ""))
    if proxy_type is None:
        return None

    try:
        network = p.get("network", "tcp")
        ws_opts = p.get("ws-opts") or p.get("ws-opt") or {}
        grpc_opts = p.get("grpc-opts") or {}
        h2_opts = p.get("h2-opts") or {}

        node = Node(
            name=p.get("name", ""),
            proxy_type=proxy_type,
            server=str(p["server"]),
            port=int(p["port"]),
            raw_config=p,
            # 通用
            password=p.get("password"),
            uuid=p.get("uuid"),
            # SS
            method=p.get("cipher"),
            plugin=p.get("plugin"),
            plugin_opts=p.get("plugin-opts"),
            # VMess
            alter_id=int(p.get("alterId", 0)),
            security=p.get("cipher", "auto") if proxy_type == ProxyType.VMESS else "auto",
            # VLESS
            flow=p.get("flow"),
            # TLS
            tls=bool(p.get("tls", False)),
            sni=p.get("sni") or p.get("servername"),
            skip_cert_verify=bool(p.get("skip-cert-verify", False)),
            alpn=p.get("alpn"),
            fingerprint=p.get("client-fingerprint"),
            # Reality
            reality_public_key=(p.get("reality-opts") or {}).get("public-key"),
            reality_short_id=(p.get("reality-opts") or {}).get("short-id"),
            # 传输层
            network=network,
            ws_path=ws_opts.get("path"),
            ws_host=(ws_opts.get("headers") or {}).get("Host"),
            grpc_service_name=grpc_opts.get("grpc-service-name"),
            h2_path=h2_opts.get("path"),
            h2_host=h2_opts.get("host") if isinstance(h2_opts.get("host"), list) else ([h2_opts["host"]] if h2_opts.get("host") else None),
            # Hysteria2
            obfs=p.get("obfs"),
            obfs_password=p.get("obfs-password"),
            up_mbps=p.get("up"),
            down_mbps=p.get("down"),
            # TUIC
            congestion_control=p.get("congestion-controller", "bbr"),
            udp_relay_mode=p.get("udp-relay-mode", "native"),
        )
        # Hysteria auth
        if proxy_type == ProxyType.HYSTERIA:
            node.auth = p.get("auth-str") or p.get("auth_str")
        return node
    except Exception as e:
        logger.warning("解析 Clash proxy 失败: %s — %s", p.get("name", "?"), e)
        return None
