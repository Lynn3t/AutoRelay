"""生成 Clash Meta (mihomo) YAML 配置。"""

from __future__ import annotations

import logging
from typing import Any, Optional

import yaml

from src.models import Node, ProxyType

logger = logging.getLogger(__name__)


def generate_clash_yaml(nodes: list[Node]) -> str:
    """将成功测试的节点列表输出为 Clash Meta YAML。"""
    proxies: list[dict] = []
    proxy_names: list[str] = []

    for node in nodes:
        if not node.test_success or not node.final_name:
            continue
        proxy = _node_to_clash_proxy(node)
        if proxy:
            proxies.append(proxy)
            proxy_names.append(proxy["name"])

    if not proxies:
        logger.warning("没有可用节点，生成空配置")
        return yaml.dump({"proxies": []}, allow_unicode=True)

    config: dict[str, Any] = {
        "proxies": proxies,
        "proxy-groups": [
            {
                "name": "AutoRelay",
                "type": "select",
                "proxies": ["Auto"] + proxy_names,
            },
            {
                "name": "Auto",
                "type": "url-test",
                "proxies": proxy_names,
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300,
            },
        ],
    }

    return yaml.dump(
        config, allow_unicode=True, default_flow_style=False, sort_keys=False
    )


# ---------------------------------------------------------------------------
# Node → Clash proxy dict
# ---------------------------------------------------------------------------

def _node_to_clash_proxy(node: Node) -> Optional[dict]:
    """将 Node 转换为 Clash proxy 字典。"""
    # 如果有 raw_config (来自 Clash 解析)，直接修改 name 返回
    if node.raw_config:
        proxy = dict(node.raw_config)
        proxy["name"] = node.final_name
        return proxy

    # 从 Node 字段构建
    builders = {
        ProxyType.SS: _build_ss,
        ProxyType.VMESS: _build_vmess,
        ProxyType.VLESS: _build_vless,
        ProxyType.TROJAN: _build_trojan,
        ProxyType.HYSTERIA2: _build_hy2,
        ProxyType.HYSTERIA: _build_hysteria,
        ProxyType.TUIC: _build_tuic,
    }
    builder = builders.get(node.proxy_type)
    return builder(node) if builder else None


def _base(node: Node, type_name: str) -> dict:
    d: dict[str, Any] = {
        "name": node.final_name,
        "type": type_name,
        "server": node.server,
        "port": node.port,
    }
    return d


def _tls_fields(node: Node, d: dict) -> None:
    if node.tls:
        d["tls"] = True
    if node.sni:
        d["sni"] = node.sni
    if node.skip_cert_verify:
        d["skip-cert-verify"] = True
    if node.alpn:
        d["alpn"] = node.alpn
    if node.fingerprint:
        d["client-fingerprint"] = node.fingerprint


def _transport_fields(node: Node, d: dict) -> None:
    if node.network and node.network != "tcp":
        d["network"] = node.network
    if node.network == "ws":
        opts: dict = {}
        if node.ws_path:
            opts["path"] = node.ws_path
        if node.ws_host:
            opts["headers"] = {"Host": node.ws_host}
        if opts:
            d["ws-opts"] = opts
    elif node.network == "grpc":
        if node.grpc_service_name:
            d["grpc-opts"] = {"grpc-service-name": node.grpc_service_name}
    elif node.network == "h2":
        opts = {}
        if node.h2_path:
            opts["path"] = node.h2_path
        if node.h2_host:
            opts["host"] = node.h2_host
        if opts:
            d["h2-opts"] = opts


def _build_ss(n: Node) -> dict:
    d = _base(n, "ss")
    d["cipher"] = n.method or "aes-128-gcm"
    d["password"] = n.password or ""
    if n.plugin:
        d["plugin"] = n.plugin
        if n.plugin_opts:
            d["plugin-opts"] = n.plugin_opts
    return d


def _build_vmess(n: Node) -> dict:
    d = _base(n, "vmess")
    d["uuid"] = n.uuid or ""
    d["alterId"] = n.alter_id
    d["cipher"] = n.security
    _tls_fields(n, d)
    _transport_fields(n, d)
    return d


def _build_vless(n: Node) -> dict:
    d = _base(n, "vless")
    d["uuid"] = n.uuid or ""
    if n.flow:
        d["flow"] = n.flow
    _tls_fields(n, d)
    _transport_fields(n, d)
    # Reality
    if n.reality_public_key:
        d["reality-opts"] = {"public-key": n.reality_public_key}
        if n.reality_short_id:
            d["reality-opts"]["short-id"] = n.reality_short_id
    return d


def _build_trojan(n: Node) -> dict:
    d = _base(n, "trojan")
    d["password"] = n.password or ""
    _tls_fields(n, d)
    _transport_fields(n, d)
    return d


def _build_hy2(n: Node) -> dict:
    d = _base(n, "hysteria2")
    d["password"] = n.password or ""
    _tls_fields(n, d)
    if n.obfs:
        d["obfs"] = n.obfs
        if n.obfs_password:
            d["obfs-password"] = n.obfs_password
    return d


def _build_hysteria(n: Node) -> dict:
    d = _base(n, "hysteria")
    if n.auth:
        d["auth-str"] = n.auth
    d["up"] = n.up_mbps or 100
    d["down"] = n.down_mbps or 100
    _tls_fields(n, d)
    if n.obfs:
        d["obfs"] = n.obfs
    return d


def _build_tuic(n: Node) -> dict:
    d = _base(n, "tuic")
    d["uuid"] = n.uuid or ""
    d["password"] = n.password or ""
    d["congestion-controller"] = n.congestion_control
    d["udp-relay-mode"] = n.udp_relay_mode
    _tls_fields(n, d)
    return d
