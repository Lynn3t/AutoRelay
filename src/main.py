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
from src.ip_lookup import IP2LocationDB
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
    """按 (server, port, proxy_type) 去重，保留首个。"""
    seen: set[tuple] = set()
    result: list[Node] = []
    for node in nodes:
        key = node.dedup_key()
        if key not in seen:
            seen.add(key)
            result.append(node)
    return result


def parse_sub_line(line: str) -> tuple[str, str]:
    """解析订阅行，支持 name|url 和纯 url 格式。返回 (name, url)。"""
    line = line.strip()
    if "|" in line:
        name, url = line.split("|", 1)
        return name.strip(), url.strip()
    # 无别名则用序号
    return "", line


async def process_subscription(
    sub_name: str,
    sub_url: str,
    db: IP2LocationDB,
    singbox_path: str,
    batch_size: int,
    test_timeout: int,
    gist_token: str,
) -> None:
    """处理单条订阅：解析 → DNS → 测试 → 重命名 → base64 → 上传 gist。"""
    logger.info("=" * 60)
    logger.info("处理订阅: [%s]", sub_name)
    logger.info("=" * 60)

    # 1. 解析
    nodes = await fetch_and_parse(sub_url)
    if not nodes:
        logger.warning("[%s] 未解析到节点，跳过", sub_name)
        return

    # 2. 去重
    before = len(nodes)
    nodes = deduplicate(nodes)
    logger.info("[%s] 解析 %d 个节点 (去重后 %d)", sub_name, before, len(nodes))

    # 3. DNS 解析入口 IP
    logger.info("[%s] 解析入口 IP (中国 DNS)...", sub_name)
    await resolve_entry_ips(nodes)

    # 4. 查询入口 ISP
    for node in nodes:
        if node.entry_ip:
            node.entry_isp = db.lookup(node.entry_ip)

    resolved = sum(1 for n in nodes if n.entry_ip)
    logger.info("[%s] 入口 IP 解析: %d/%d", sub_name, resolved, len(nodes))

    # 5. 并发测试出口 IP
    logger.info("[%s] 测试出口 IP (batch=%d, timeout=%ds)...", sub_name, batch_size, test_timeout)
    await test_exit_ips(nodes, singbox_path, batch_size, test_timeout)

    # 6. 查询出口 ISP
    for node in nodes:
        if node.exit_ip:
            node.exit_isp = db.lookup(node.exit_ip)

    ok = sum(1 for n in nodes if n.test_success)
    logger.info("[%s] 测试完成: %d/%d 成功", sub_name, ok, len(nodes))

    if ok == 0:
        logger.warning("[%s] 所有节点测试失败，跳过上传", sub_name)
        return

    # 7. 重命名
    rename_nodes(nodes)

    # 8. 生成 base64 编码的 URI 订阅
    successful = [n for n in nodes if n.test_success]
    b64_content = nodes_to_base64(successful)
    logger.info("[%s] 生成 base64 订阅: %d 个节点", sub_name, len(successful))

    # 9. 上传到独立 Gist
    if not gist_token:
        logger.warning("[%s] GIST_TOKEN 未设置，输出到 stdout", sub_name)
        print(f"\n--- {sub_name} ---")
        print(b64_content)
    else:
        url = upload_to_gist(gist_token, b64_content, sub_name)
        logger.info("[%s] 已上传 → %s", sub_name, url)


async def run() -> None:
    # ---- 读取环境变量 ----
    sub_urls_raw = os.environ.get("SUB_URLS", "")
    if not sub_urls_raw.strip():
        logger.error("SUB_URLS 环境变量为空")
        sys.exit(1)

    gist_token = os.environ.get("GIST_TOKEN", "")
    singbox_path = os.environ.get("SINGBOX_PATH", "./sing-box")
    ip2loc_csv = os.environ.get("IP2LOCATION_CSV", "")
    batch_size = int(os.environ.get("BATCH_SIZE", "10"))
    test_timeout = int(os.environ.get("TEST_TIMEOUT", "15"))

    # ---- 加载 IP2Location 数据库 ----
    if not ip2loc_csv or not os.path.exists(ip2loc_csv):
        logger.error("IP2Location CSV 文件不存在: %s", ip2loc_csv)
        sys.exit(1)

    logger.info("加载 IP2Location 数据库: %s", ip2loc_csv)
    db = IP2LocationDB(ip2loc_csv)

    # ---- 解析订阅列表 ----
    sub_lines = [l.strip() for l in sub_urls_raw.strip().splitlines() if l.strip()]
    subs: list[tuple[str, str]] = []
    for i, line in enumerate(sub_lines):
        name, url = parse_sub_line(line)
        if not name:
            name = f"sub{i + 1}"
        subs.append((name, url))

    logger.info("共 %d 条订阅: %s", len(subs), ", ".join(n for n, _ in subs))

    # ---- 逐条处理 ----
    for sub_name, sub_url in subs:
        try:
            await process_subscription(
                sub_name, sub_url, db,
                singbox_path, batch_size, test_timeout,
                gist_token,
            )
        except Exception as e:
            logger.error("[%s] 处理失败: %s", sub_name, e, exc_info=True)

    logger.info("AutoRelay 全部完成")


def main() -> None:
    asyncio.run(run())


if __name__ == "__main__":
    main()
