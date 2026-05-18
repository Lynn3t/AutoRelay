"""AutoRelay 主编排脚本。

支持多条订阅链接，每条单独处理后 base64 编码上传到独立的 private gist。
SUB_URLS 格式 (每行一条，可选 name|url 格式指定别名):
    sub1|https://example.com/sub1
    https://example.com/sub2
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys

from src.dns_resolver import resolve_entry_ips
from src.gist_uploader import upload_to_gist
from src.ip_lookup import lookup_isps
from src.models import Node
from src.parsers.dispatcher import fetch_and_parse
from src.renamer import rename_nodes
from src.tester import test_exit_ips
from src.uri_output import nodes_to_base64

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("autorelay")


def deduplicate(nodes: list[Node]) -> list[Node]:
    """按 (server, entry_ip, exit_ip) 去重，仅对成功且三字段齐全的节点去重。"""
    seen: set[tuple] = set()
    result: list[Node] = []
    for node in nodes:
        if not node.test_success or not node.entry_ip or not node.exit_ip:
            result.append(node)
            continue
        key = node.dedup_key()
        if key not in seen:
            seen.add(key)
            result.append(node)
    return result


def filter_non_cn_failed(nodes: list[Node]) -> list[Node]:
    """过滤入口非中国且测试失败的节点。"""
    result: list[Node] = []
    for node in nodes:
        if (
            not node.test_success
            and node.entry_country
            and node.entry_country != "China"
        ):
            continue
        result.append(node)
    return result


def filter_exit_idc_failed(nodes: list[Node]) -> list[Node]:
    """过滤测试成功但出口 ISP 解析失败的节点，入口为中国的保留。测试失败的节点不受此过滤影响。"""
    result: list[Node] = []
    for node in nodes:
        if (
            node.test_success
            and not node.exit_isp
            and node.entry_country != "China"
        ):
            continue
        result.append(node)
    return result


def parse_sub_line(line: str) -> tuple[str, str]:
    """解析订阅行，支持 name|url 和纯 url 格式。返回 (name, url)。"""
    line = line.strip()
    if "|" in line:
        name, url = line.split("|", 1)
        return name.strip(), url.strip()
    return "", line


async def _resolve_and_lookup_isp(nodes: list[Node]) -> None:
    """DNS 解析完成后，立即查询入口 ISP（可与出口测试并行）。"""
    await resolve_entry_ips(nodes)
    entry_ips = [n.entry_ip for n in nodes if n.entry_ip]
    if entry_ips:
        isp_map = await lookup_isps(list(set(entry_ips)))
        for node in nodes:
            if node.entry_ip and node.entry_ip in isp_map:
                info = isp_map[node.entry_ip]
                node.entry_isp = info.isp
                node.entry_country = info.country


async def process_subscription(
    sub_name: str,
    sub_url: str,
    singbox_path: str,
    batch_size: int,
    test_timeout: int,
    gist_token: str,
    drop_non_cn_failed: bool = False,
    port_offset: int = 0,
) -> None:
    """处理单条订阅：解析 → DNS+入口ISP+出口测试(并行) → 去重 → 过滤 → 重命名 → base64 → gist。"""
    logger.info("=" * 60)
    logger.info("处理订阅: [%s]", sub_name)
    logger.info("=" * 60)

    # 1. 解析
    nodes = await fetch_and_parse(sub_url)
    if not nodes:
        logger.warning("[%s] 未解析到节点，跳过", sub_name)
        return

    logger.info("[%s] 解析 %d 个节点", sub_name, len(nodes))

    # 2 & 3 & 5. DNS 解析 + 入口 ISP 查询 + 出口测试（三者并行）
    #   DNS 先完成 → 入口 ISP 查询立即开始（与出口测试并行）
    logger.info("[%s] DNS + 出口测试 + 入口 ISP (batch=%d, timeout=%ds)...", sub_name, batch_size, test_timeout)
    await asyncio.gather(
        _resolve_and_lookup_isp(nodes),
        test_exit_ips(nodes, singbox_path, batch_size, test_timeout, port_offset, sub_name),
    )

    resolved = sum(1 for n in nodes if n.entry_ip)
    ok = sum(1 for n in nodes if n.test_success)
    logger.info("[%s] DNS: %d/%d, 测试: %d/%d 成功", sub_name, resolved, len(nodes), ok, len(nodes))

    # 4. 去重 (基于域名 + 入口IP + 出口IP，需在测试后执行)
    before = len(nodes)
    nodes = deduplicate(nodes)
    logger.info("[%s] 去重: %d → %d", sub_name, before, len(nodes))

    # 6. 过滤入口非中国且测试失败的节点
    if drop_non_cn_failed:
        before = len(nodes)
        nodes = filter_non_cn_failed(nodes)
        dropped = before - len(nodes)
        if dropped:
            logger.info("[%s] 过滤非CN失败节点: %d → %d (移除 %d)", sub_name, before, len(nodes), dropped)

    # 7. 过滤出口 IDC 解析失败的节点（入口为中国则保留）
    before = len(nodes)
    nodes = filter_exit_idc_failed(nodes)
    dropped = before - len(nodes)
    if dropped:
        logger.info("[%s] 过滤出口IDC失败节点: %d → %d (移除 %d)", sub_name, before, len(nodes), dropped)

    # 8. 重命名
    rename_nodes(nodes)

    # 9. 生成 base64 编码的 URI 订阅 (成功节点重命名，失败节点保留原名)
    b64_content = nodes_to_base64(nodes)
    successful = sum(1 for n in nodes if n.test_success)
    logger.info("[%s] 生成 base64 订阅: %d 个节点 (%d 成功)", sub_name, len(nodes), successful)

    # 10. 上传到独立 Gist
    if not gist_token:
        logger.warning("[%s] GIST_TOKEN 未设置，输出到 stdout", sub_name)
        print(f"\n--- {sub_name} ---")
        print(b64_content)
    else:
        await upload_to_gist(gist_token, b64_content, sub_name)
        logger.info("[%s] 已上传到 Gist", sub_name)


async def run() -> None:
    # ---- 读取环境变量 ----
    sub_urls_raw = os.environ.get("SUB_URLS", "")
    if not sub_urls_raw.strip():
        logger.error("SUB_URLS 环境变量为空")
        sys.exit(1)

    gist_token = os.environ.get("GIST_TOKEN", "")
    singbox_path = os.environ.get("SINGBOX_PATH", "./sing-box")
    batch_size = int(os.environ.get("BATCH_SIZE", "10"))
    test_timeout = int(os.environ.get("TEST_TIMEOUT", "15"))
    drop_non_cn_failed = os.environ.get("FILTER_NON_CN_FAILED", "true").lower() not in ("0", "false", "no")

    # ---- 解析订阅列表 ----
    sub_lines = [l.strip() for l in sub_urls_raw.strip().splitlines() if l.strip()]
    subs: list[tuple[str, str]] = []
    for i, line in enumerate(sub_lines):
        name, url = parse_sub_line(line)
        if not name:
            name = f"sub{i + 1}"
        subs.append((name, url))

    logger.info("共 %d 条订阅: %s", len(subs), ", ".join(n for n, _ in subs))

    # ---- 并行处理所有订阅（每条分配独立端口范围） ----
    port_per_sub = batch_size * 10  # 每条订阅预留足够端口空间
    tasks = [
        process_subscription(
            sub_name, sub_url,
            singbox_path, batch_size, test_timeout,
            gist_token, drop_non_cn_failed,
            port_offset=i * port_per_sub,
        )
        for i, (sub_name, sub_url) in enumerate(subs)
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for (sub_name, _), result in zip(subs, results):
        if isinstance(result, Exception):
            logger.error("[%s] 处理失败: %s", sub_name, result, exc_info=result)

    logger.info("AutoRelay 全部完成")


def main() -> None:
    asyncio.run(run())


if __name__ == "__main__":
    main()
