"""使用中国 DNS 服务器解析节点域名获取入口 IP。"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
from typing import Optional

import dns.asyncresolver
import dns.resolver

from src.models import Node

logger = logging.getLogger(__name__)

CHINA_DNS_SERVERS = ["114.114.114.114", "223.5.5.5"]


def is_ip(address: str) -> bool:
    """判断字符串是否为有效 IP 地址。"""
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False


async def resolve_domain(domain: str, dns_servers: list[str] | None = None) -> Optional[str]:
    """使用指定 DNS 服务器解析域名，返回第一个 A 记录 IP。"""
    resolver = dns.asyncresolver.Resolver()
    resolver.nameservers = dns_servers or CHINA_DNS_SERVERS
    resolver.lifetime = 5
    try:
        answer = await resolver.resolve(domain, "A")
        return str(answer[0])
    except Exception as e:
        logger.warning("DNS 解析失败: %s — %s", domain, e)
        return None


async def resolve_entry_ips(
    nodes: list[Node],
    dns_servers: list[str] | None = None,
) -> None:
    """并发解析所有节点的入口 IP，结果写入 node.entry_ip。"""
    servers = dns_servers or CHINA_DNS_SERVERS

    # 域名去重，避免重复查询
    domain_set: set[str] = set()
    for node in nodes:
        if is_ip(node.server):
            node.entry_ip = node.server
        else:
            domain_set.add(node.server)

    if not domain_set:
        return

    # 并发解析
    domains = list(domain_set)
    tasks = [resolve_domain(d, servers) for d in domains]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    cache: dict[str, Optional[str]] = {}
    for domain, result in zip(domains, results):
        if isinstance(result, Exception):
            cache[domain] = None
        else:
            cache[domain] = result

    # 回填节点
    for node in nodes:
        if node.entry_ip is None:
            node.entry_ip = cache.get(node.server)
