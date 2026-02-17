"""将 Node 转回 URI 格式，用于 base64 订阅输出。"""

from __future__ import annotations

import base64
import json
import logging
from typing import Optional
from urllib.parse import quote, urlencode

from src.models import Node, ProxyType

logger = logging.getLogger(__name__)


def nodes_to_base64(nodes: list[Node]) -> str:
    """将节点列表转换为 base64 编码的 URI 订阅内容。"""
    lines: list[str] = []
    for node in nodes:
        uri = node_to_uri(node)
        if uri:
            lines.append(uri)
    content = "\n".join(lines)
    return base64.b64encode(content.encode("utf-8")).decode("utf-8")


def node_to_uri(node: Node) -> Optional[str]:
    """将 Node 转为对应协议的 URI 字符串。"""
    builders = {
        ProxyType.SS: _to_ss,
        ProxyType.VMESS: _to_vmess,
        ProxyType.VLESS: _to_vless,
        ProxyType.TROJAN: _to_trojan,
        ProxyType.HYSTERIA2: _to_hy2,
        ProxyType.HYSTERIA: _to_hysteria,
        ProxyType.TUIC: _to_tuic,
    }
    builder = builders.get(node.proxy_type)
    if not builder:
        return None
    try:
        return builder(node)
    except Exception as e:
        logger.warning("节点转 URI 失败: %s — %s", node.final_name or node.name, e)
        return None


def _name(node: Node) -> str:
    return node.final_name or node.name


# ---------------------------------------------------------------------------
# 各协议 URI 构建
# ---------------------------------------------------------------------------

def _to_ss(n: Node) -> str:
    """ss:// SIP002 格式。"""
    userinfo = base64.b64encode(
        f"{n.method}:{n.password}".encode()
    ).decode().rstrip("=")
    host = f"[{n.server}]" if ":" in n.server else n.server
    uri = f"ss://{userinfo}@{host}:{n.port}"
    if n.plugin:
        plugin_str = _format_sip002_plugin(n.plugin, n.plugin_opts)
        uri += "?" + urlencode({"plugin": plugin_str})
    uri += "#" + quote(_name(n))
    return uri


def _to_vmess(n: Node) -> str:
    """vmess:// V2RayN JSON base64 格式。"""
    cfg = {
        "v": "2",
        "ps": _name(n),
        "add": n.server,
        "port": str(n.port),
        "id": n.uuid or "",
        "aid": str(n.alter_id),
        "scy": n.security,
        "net": n.network,
        "type": "none",
        "host": "",
        "path": "",
        "tls": "tls" if n.tls else "",
        "sni": n.sni or "",
        "fp": n.fingerprint or "",
    }
    if n.network == "ws":
        cfg["host"] = n.ws_host or ""
        cfg["path"] = n.ws_path or ""
    elif n.network == "grpc":
        cfg["path"] = n.grpc_service_name or ""
    elif n.network == "h2":
        cfg["host"] = n.h2_host[0] if n.h2_host else ""
        cfg["path"] = n.h2_path or ""

    encoded = base64.b64encode(json.dumps(cfg).encode()).decode()
    return f"vmess://{encoded}"


def _to_vless(n: Node) -> str:
    """vless:// 标准 URI 格式。"""
    params: dict[str, str] = {}
    params["type"] = n.network

    if n.tls:
        if n.reality_public_key:
            params["security"] = "reality"
            params["pbk"] = n.reality_public_key
            if n.reality_short_id:
                params["sid"] = n.reality_short_id
        else:
            params["security"] = "tls"
    else:
        params["security"] = "none"

    if n.sni:
        params["sni"] = n.sni
    if n.fingerprint:
        params["fp"] = n.fingerprint
    if n.flow:
        params["flow"] = n.flow
    if n.alpn:
        params["alpn"] = ",".join(n.alpn)
    if n.skip_cert_verify:
        params["allowInsecure"] = "1"

    _add_transport_params(n, params)

    host = f"[{n.server}]" if ":" in n.server else n.server
    qs = urlencode(params)
    return f"vless://{n.uuid}@{host}:{n.port}?{qs}#{quote(_name(n))}"


def _to_trojan(n: Node) -> str:
    """trojan:// URI 格式。"""
    params: dict[str, str] = {}
    params["type"] = n.network

    if n.tls:
        params["security"] = "tls"
    else:
        params["security"] = "none"

    if n.sni:
        params["sni"] = n.sni
    if n.fingerprint:
        params["fp"] = n.fingerprint
    if n.alpn:
        params["alpn"] = ",".join(n.alpn)
    if n.skip_cert_verify:
        params["allowInsecure"] = "1"

    _add_transport_params(n, params)

    host = f"[{n.server}]" if ":" in n.server else n.server
    pw = quote(n.password or "", safe="")
    qs = urlencode(params)
    return f"trojan://{pw}@{host}:{n.port}?{qs}#{quote(_name(n))}"


def _to_hy2(n: Node) -> str:
    """hysteria2:// URI 格式。"""
    params: dict[str, str] = {}
    if n.sni:
        params["sni"] = n.sni
    if n.skip_cert_verify:
        params["insecure"] = "1"
    if n.obfs:
        params["obfs"] = n.obfs
        if n.obfs_password:
            params["obfs-password"] = n.obfs_password

    host = f"[{n.server}]" if ":" in n.server else n.server
    pw = quote(n.password or "", safe="")
    qs = ("?" + urlencode(params)) if params else ""
    return f"hysteria2://{pw}@{host}:{n.port}{qs}#{quote(_name(n))}"


def _to_hysteria(n: Node) -> str:
    """hysteria:// URI 格式。"""
    params: dict[str, str] = {}
    if n.auth:
        params["auth"] = n.auth
    if n.sni:
        params["peer"] = n.sni
    if n.skip_cert_verify:
        params["insecure"] = "1"
    if n.alpn:
        params["alpn"] = ",".join(n.alpn)
    if n.obfs:
        params["obfs"] = n.obfs
        if n.obfs_password:
            params["obfsParam"] = n.obfs_password
    if n.up_mbps:
        params["upmbps"] = str(n.up_mbps)
    if n.down_mbps:
        params["downmbps"] = str(n.down_mbps)

    host = f"[{n.server}]" if ":" in n.server else n.server
    qs = ("?" + urlencode(params)) if params else ""
    return f"hysteria://{host}:{n.port}{qs}#{quote(_name(n))}"


def _to_tuic(n: Node) -> str:
    """tuic:// URI 格式。"""
    params: dict[str, str] = {}
    if n.sni:
        params["sni"] = n.sni
    if n.alpn:
        params["alpn"] = ",".join(n.alpn)
    if n.congestion_control and n.congestion_control != "bbr":
        params["congestion_control"] = n.congestion_control
    if n.udp_relay_mode and n.udp_relay_mode != "native":
        params["udp_relay_mode"] = n.udp_relay_mode
    if n.skip_cert_verify:
        params["allow_insecure"] = "1"

    host = f"[{n.server}]" if ":" in n.server else n.server
    pw = quote(n.password or "", safe="")
    qs = ("?" + urlencode(params)) if params else ""
    return f"tuic://{n.uuid}:{pw}@{host}:{n.port}{qs}#{quote(_name(n))}"


# ---------------------------------------------------------------------------
# 辅助
# ---------------------------------------------------------------------------

def _add_transport_params(n: Node, params: dict) -> None:
    """向 params 添加传输层参数 (ws/grpc/h2)。"""
    if n.network == "ws":
        if n.ws_path:
            params["path"] = n.ws_path
        if n.ws_host:
            params["host"] = n.ws_host
    elif n.network == "grpc":
        if n.grpc_service_name:
            params["serviceName"] = n.grpc_service_name
    elif n.network == "h2":
        if n.h2_path:
            params["path"] = n.h2_path
        if n.h2_host:
            params["host"] = n.h2_host[0]


_SIP002_PLUGIN_NAME_MAP = {
    "obfs": "obfs-local",
    "simple-obfs": "obfs-local",
}


def _format_sip002_plugin(plugin: str, plugin_opts) -> str:
    """Format plugin name + opts into a single SIP002 plugin query value.

    SIP002 format: ``obfs-local;obfs=tls;obfs-host=example.com``
    """
    name = _SIP002_PLUGIN_NAME_MAP.get(plugin, plugin)

    if plugin_opts is None:
        return name

    if isinstance(plugin_opts, str):
        return f"{name};{plugin_opts}" if plugin_opts else name

    if isinstance(plugin_opts, dict):
        normalized = plugin.lower()
        if normalized in ("obfs", "simple-obfs", "obfs-local"):
            parts: list[str] = []
            if plugin_opts.get("mode"):
                parts.append(f"obfs={plugin_opts['mode']}")
            if plugin_opts.get("host"):
                parts.append(f"obfs-host={plugin_opts['host']}")
            return name + (";" + ";".join(parts) if parts else "")

        if normalized == "v2ray-plugin":
            parts = []
            if plugin_opts.get("mode"):
                parts.append(f"mode={plugin_opts['mode']}")
            if plugin_opts.get("host"):
                parts.append(f"host={plugin_opts['host']}")
            if plugin_opts.get("path"):
                parts.append(f"path={plugin_opts['path']}")
            if plugin_opts.get("tls"):
                parts.append("tls")
            if plugin_opts.get("mux"):
                parts.append("mux")
            return name + (";" + ";".join(parts) if parts else "")

        # Generic fallback
        parts = []
        for k, v in plugin_opts.items():
            if isinstance(v, bool):
                if v:
                    parts.append(k)
            else:
                parts.append(f"{k}={v}")
        return name + (";" + ";".join(parts) if parts else "")

    return name
