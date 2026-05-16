from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

logger = logging.getLogger(__name__)


class ProxyType(Enum):
    SS = "ss"
    VMESS = "vmess"
    VLESS = "vless"
    TROJAN = "trojan"
    HYSTERIA2 = "hysteria2"
    HYSTERIA = "hysteria"
    TUIC = "tuic"


@dataclass
class Node:
    """统一的节点数据模型，所有解析器输出此对象。"""

    name: str
    proxy_type: ProxyType
    server: str
    port: int

    # --- 通用 ---
    password: Optional[str] = None
    uuid: Optional[str] = None

    # --- Shadowsocks ---
    method: Optional[str] = None
    plugin: Optional[str] = None
    plugin_opts: Optional[Any] = None

    # --- VMess ---
    alter_id: int = 0
    security: str = "auto"

    # --- VLESS ---
    flow: Optional[str] = None
    encryption: str = "none"

    # --- TLS ---
    tls: bool = False
    sni: Optional[str] = None
    skip_cert_verify: bool = False
    alpn: Optional[list[str]] = None
    fingerprint: Optional[str] = None

    # --- Reality (VLESS) ---
    reality_public_key: Optional[str] = None
    reality_short_id: Optional[str] = None

    # --- 传输层 ---
    network: str = "tcp"
    ws_path: Optional[str] = None
    ws_host: Optional[str] = None
    grpc_service_name: Optional[str] = None
    h2_path: Optional[str] = None
    h2_host: Optional[list[str]] = None

    # --- Hysteria / Hysteria2 ---
    obfs: Optional[str] = None
    obfs_password: Optional[str] = None
    auth: Optional[str] = None
    up_mbps: Optional[int] = None
    down_mbps: Optional[int] = None

    # --- TUIC ---
    congestion_control: str = "bbr"
    udp_relay_mode: str = "native"

    # --- 保留原始配置 (Clash 来源直接复用) ---
    raw_config: Optional[dict[str, Any]] = None

    # --- 测试结果 (流水线中填充) ---
    entry_ip: Optional[str] = None
    entry_isp: Optional[str] = None
    entry_country: Optional[str] = None
    exit_ip: Optional[str] = None
    exit_isp: Optional[str] = None
    exit_country: Optional[str] = None
    test_success: bool = False
    final_name: Optional[str] = None

    def dedup_key(self) -> tuple:
        """用于去重的唯一标识：域名 + 入口IP + 出口IP。"""
        return (self.server, self.entry_ip, self.exit_ip)
