"""为每个节点生成 sing-box 最小运行配置。"""

from __future__ import annotations

from src.models import Node, ProxyType

# 始终需要 TLS 的协议
_TLS_REQUIRED = {ProxyType.TUIC, ProxyType.HYSTERIA, ProxyType.HYSTERIA2}


def generate_singbox_config(node: Node, listen_port: int) -> dict:
    """生成最小 sing-box 配置：mixed inbound + 单个 proxy outbound。"""
    return {
        "log": {"level": "warn"},
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
        ob["plugin"] = _singbox_plugin_name(n.plugin)
        opts_str = _plugin_opts_to_string(n.plugin, n.plugin_opts)
        if opts_str:
            ob["plugin_opts"] = opts_str
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
    force_tls = n.proxy_type in _TLS_REQUIRED
    if not n.tls and not force_tls:
        return
    tls: dict = {"enabled": True}
    if n.sni:
        tls["server_name"] = n.sni
    elif _is_ip_address(n.server):
        # IP 地址无法做 TLS 域名验证，必须 insecure
        tls["insecure"] = True
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
        # Reality 需要 utls 指纹，如果未指定则默认 chrome
        if "utls" not in tls:
            tls["utls"] = {"enabled": True, "fingerprint": "chrome"}
        # Reality 需要 server_name
        if "server_name" not in tls and n.server:
            tls["server_name"] = n.sni or n.server
    ob["tls"] = tls


def _is_ip_address(server: str) -> bool:
    """判断 server 是否为 IP 地址。"""
    import ipaddress
    try:
        ipaddress.ip_address(server.strip("[]"))
        return True
    except ValueError:
        return False


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


# ---------------------------------------------------------------------------
# SS plugin 辅助
# ---------------------------------------------------------------------------

_PLUGIN_NAME_MAP = {
    "obfs": "obfs-local",
    "simple-obfs": "obfs-local",
}


def _singbox_plugin_name(clash_name: str) -> str:
    """Map Clash plugin name to sing-box plugin name."""
    return _PLUGIN_NAME_MAP.get(clash_name, clash_name)


def _plugin_opts_to_string(plugin: str, opts) -> str:
    """Convert plugin-opts (dict or str) to the semicolon-separated string sing-box expects."""
    if opts is None:
        return ""
    if isinstance(opts, str):
        return opts
    if not isinstance(opts, dict):
        return str(opts)

    normalized = plugin.lower()
    if normalized in ("obfs", "simple-obfs", "obfs-local"):
        parts: list[str] = []
        if opts.get("mode"):
            parts.append(f"obfs={opts['mode']}")
        if opts.get("host"):
            parts.append(f"obfs-host={opts['host']}")
        return ";".join(parts)

    if normalized == "v2ray-plugin":
        parts = []
        if opts.get("mode"):
            parts.append(f"mode={opts['mode']}")
        if opts.get("host"):
            parts.append(f"host={opts['host']}")
        if opts.get("path"):
            parts.append(f"path={opts['path']}")
        if opts.get("tls"):
            parts.append("tls")
        if opts.get("mux"):
            parts.append("mux")
        return ";".join(parts)

    # Fallback: generic key=value pairs
    parts = []
    for k, v in opts.items():
        if isinstance(v, bool):
            if v:
                parts.append(k)
        else:
            parts.append(f"{k}={v}")
    return ";".join(parts)
