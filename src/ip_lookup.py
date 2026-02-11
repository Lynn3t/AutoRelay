"""通过 ip-api.com 批量查询 IP 的 ISP 信息。

免费限制:
  - 单次查询: 45 req/min
  - 批量查询: POST /batch, 每次最多 100 个 IP, 15 req/min
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

import aiohttp

logger = logging.getLogger(__name__)

BATCH_URL = "http://ip-api.com/batch"
BATCH_SIZE = 100  # ip-api.com 每次最多 100 个
RATE_LIMIT_DELAY = 4.5  # 15 req/min → 每次间隔 4 秒留余量


async def lookup_isps(ip_list: list[str]) -> dict[str, Optional[str]]:
    """批量查询 IP 对应的 ISP，返回 {ip: isp} 映射。"""
    # 去重
    unique_ips = list(set(ip for ip in ip_list if ip))
    if not unique_ips:
        return {}

    result: dict[str, Optional[str]] = {}

    async with aiohttp.ClientSession() as session:
        for i in range(0, len(unique_ips), BATCH_SIZE):
            batch = unique_ips[i : i + BATCH_SIZE]
            batch_result = await _query_batch(session, batch)
            result.update(batch_result)

            # 限速: 如果还有后续批次，等待
            if i + BATCH_SIZE < len(unique_ips):
                await asyncio.sleep(RATE_LIMIT_DELAY)

    found = sum(1 for v in result.values() if v)
    logger.info("ISP 查询完成: %d/%d 成功", found, len(unique_ips))
    return result


async def _query_batch(
    session: aiohttp.ClientSession, ips: list[str]
) -> dict[str, Optional[str]]:
    """单次批量查询。"""
    payload = [
        {"query": ip, "fields": "status,isp,query"} for ip in ips
    ]

    try:
        async with session.post(
            BATCH_URL, json=payload, timeout=aiohttp.ClientTimeout(total=30)
        ) as resp:
            resp.raise_for_status()
            data = await resp.json()
    except Exception as e:
        logger.warning("ip-api.com 批量查询失败: %s", e)
        return {ip: None for ip in ips}

    result: dict[str, Optional[str]] = {}
    for item in data:
        ip = item.get("query", "")
        if item.get("status") == "success":
            result[ip] = item.get("isp") or None
        else:
            result[ip] = None

    return result
