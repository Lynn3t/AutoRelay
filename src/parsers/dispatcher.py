"""订阅内容格式检测与分发。"""

from __future__ import annotations

import logging

import aiohttp

from src.models import Node
from src.parsers.clash import is_clash_yaml, parse_clash_yaml
from src.parsers.singbox import is_singbox_json, parse_singbox_json
from src.parsers.uri import parse_uri_list

logger = logging.getLogger(__name__)


async def fetch_and_parse(url: str, timeout: int = 30) -> list[Node]:
    """抓取订阅 URL 内容，自动检测格式并解析为节点列表。"""
    content = await _fetch(url, timeout)
    if not content:
        return []

    # 按优先级检测格式
    if is_clash_yaml(content):
        logger.info("检测到 Clash YAML 格式")
        return parse_clash_yaml(content)

    if is_singbox_json(content):
        logger.info("检测到 sing-box JSON 格式")
        return parse_singbox_json(content)

    # 默认尝试 base64 / URI 列表
    logger.info("尝试 base64/URI 列表格式")
    return parse_uri_list(content)


async def _fetch(url: str, timeout: int) -> str:
    """抓取 URL 内容，返回文本。"""
    try:
        ct = aiohttp.ClientTimeout(total=timeout)
        async with aiohttp.ClientSession(timeout=ct) as session:
            async with session.get(url, ssl=False) as resp:
                resp.raise_for_status()
                return await resp.text()
    except Exception as e:
        logger.error("抓取订阅失败: %s", type(e).__name__)
        return ""
