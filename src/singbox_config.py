"""为每个节点生成 sing-box 最小运行配置。"""

from __future__ import annotations

from src.models import Node, ProxyType


def generate_singbox_config(node: Node, listen_port: int) -> dict:
    """生成最小 sing-box 配置：mixed inbound + 单个 proxy outbound。"""
    return {
        "log": {"level": "error"},
        "inbounds": [
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": listen_port,
            }
        ],
        "outbounds": [_build_outbound(node)],
    }


# ---------------------------------------------------------------------------
# 各协议 outbound 构建
# ---------------------------------------------------------------------------

def _build_outbound(node: Node) -> dict:
    builders = {
        ProxyType.SS: _build_ss,
        ProxyType.VMESS: _build_vmess,
        ProxyType.VLESS: _build_vless,
        ProxyType.TROJAN: _build_trojan,
        ProxyType.HYSTERIA2: _build_hysteria2,
        ProxyType.HYSTERIA: _build_hysteria,
        ProxyType.TUIC: _build_tuic,
    }
    return builders[node.proxy_type](node)


def _build_ss(n: Node) -> dict:
    ob: dict = {
        "type": "shadowsocks",
        "tag": "proxy",
        "server": n.server,
        "server_port": n.port,
        "method": n.method or "aes-128-gcm",
        "password": n.password or "",
    }
    if n.plugin:
        ob["plugin"] = n.plugin
        if n.plugin_opts:
            ob["plugin_opts"] = n.plugin_opts
    return ob


def _build_vmess(n: Node) -> dict:
    ob: dict = {
        "type": "vmess",
        "tag": "proxy",
        "server": n.server,
        "server_port": n.port,
        "uuid": n.uuid or "",
        "security": n.security,
        "alter_id": n.alter_id,
    }
    _apply_tls(ob, n)
    _apply_transport(ob, n)
    return ob


def _build_vless(n: Node) -> dict:
    ob: dict = {
        "type": "vless",
        "tag": "proxy",
        "server": n.server,
        "server_port": n.port,
        "uuid": n.uuid or "",
    }
    if n.flow:
        ob["flow"] = n.flow
    _apply_tls(ob, n)
    _apply_transport(ob, n)
    return ob


def _build_trojan(n: Node) -> dict:
    ob: dict = {
        "type": "trojan",
        "tag": "proxy",
        "server": n.server,
        "server_port": n.port,
        "password": n.password or "",
    }
    _apply_tls(ob, n)
    _apply_transport(ob, n)
    return ob


def _build_hysteria2(n: Node) -> dict:
    ob: dict = {
        "type": "hysteria2",
        "tag": "proxy",
        "server": n.server,
        "server_port": n.port,
        "password": n.password or "",
    }
    if n.obfs:
        ob["obfs"] = {"type": n.obfs}
        if n.obfs_password:
            ob["obfs"]["password"] = n.obfs_password
    if n.up_mbps:
        ob["up_mbps"] = n.up_mbps
    if n.down_mbps:
        ob["down_mbps"] = n.down_mbps
    _apply_tls(ob, n)
    return ob


def _build_hysteria(n: Node) -> dict:
    ob: dict = {
        "type": "hysteria",
        "tag": "proxy",
        "server": n.server,
        "server_port": n.port,
        "up_mbps": n.up_mbps or 100,
        "down_mbps": n.down_mbps or 100,
    }
    if n.auth:
        ob["auth_str"] = n.auth
    if n.obfs:
        ob["obfs"] = n.obfs
    _apply_tls(ob, n)
    return ob


def _build_tuic(n: Node) -> dict:
    ob: dict = {
        "type": "tuic",
        "tag": "proxy",
        "server": n.server,
        "server_port": n.port,
        "uuid": n.uuid or "",
        "password": n.password or "",
        "congestion_control": n.congestion_control,
        "udp_relay_mode": n.udp_relay_mode,
    }
    _apply_tls(ob, n)
    return ob


# ---------------------------------------------------------------------------
# TLS & Transport 辅助
# ---------------------------------------------------------------------------

def _apply_tls(ob: dict, n: Node) -> None:
    if not n.tls:
        return
    tls: dict = {"enabled": True}
    if n.sni:
        tls["server_name"] = n.sni
    if n.skip_cert_verify:
        tls["insecure"] = True
    if n.alpn:
        tls["alpn"] = n.alpn
    if n.fingerprint:
        tls["utls"] = {"enabled": True, "fingerprint": n.fingerprint}
    if n.reality_public_key:
        reality: dict = {"enabled": True, "public_key": n.reality_public_key}
        if n.reality_short_id:
            reality["short_id"] = n.reality_short_id
        tls["reality"] = reality
    ob["tls"] = tls


def _apply_transport(ob: dict, n: Node) -> None:
    if n.network == "ws":
        t: dict = {"type": "ws"}
        if n.ws_path:
            t["path"] = n.ws_path
        if n.ws_host:
            t["headers"] = {"Host": n.ws_host}
        ob["transport"] = t
    elif n.network == "grpc":
        t = {"type": "grpc"}
        if n.grpc_service_name:
            t["service_name"] = n.grpc_service_name
        ob["transport"] = t
    elif n.network == "h2":
        t = {"type": "http"}
        if n.h2_path:
            t["path"] = n.h2_path
        if n.h2_host:
            t["host"] = n.h2_host
        ob["transport"] = t
    elif n.network == "httpupgrade":
        t = {"type": "httpupgrade"}
        if n.ws_path:
            t["path"] = n.ws_path
        if n.ws_host:
            t["host"] = n.ws_host
        ob["transport"] = t
