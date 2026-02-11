"""并发出口 IP 测试 — 管理 sing-box 进程，通过代理 curl ip.sb。"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Optional

from src.dns_resolver import is_ip
from src.models import Node
from src.singbox_config import generate_singbox_config

logger = logging.getLogger(__name__)

BASE_PORT = 10000

IP_CHECK_URLS = [
    "http://ip.sb",
    "http://ifconfig.me",
    "http://api.ipify.org",
]


async def test_exit_ips(
    nodes: list[Node],
    singbox_path: str,
    batch_size: int = 10,
    timeout: int = 15,
) -> None:
    """分批并发测试所有节点的出口 IP。"""
    total = len(nodes)
    for i in range(0, total, batch_size):
        batch = nodes[i : i + batch_size]
        batch_num = i // batch_size + 1
        logger.info(
            "测试批次 %d/%d (%d 个节点)",
            batch_num,
            (total + batch_size - 1) // batch_size,
            len(batch),
        )
        tasks = [
            _test_single(node, singbox_path, BASE_PORT + j, timeout)
            for j, node in enumerate(batch)
        ]
        await asyncio.gather(*tasks, return_exceptions=True)

        ok = sum(1 for n in batch if n.test_success)
        logger.info("批次 %d 完成: %d/%d 成功", batch_num, ok, len(batch))


async def _test_single(
    node: Node, singbox_path: str, port: int, timeout: int
) -> None:
    """测试单个节点的出口 IP。"""
    config = generate_singbox_config(node, port)
    config_path = f"/tmp/singbox_{port}.json"

    with open(config_path, "w") as f:
        json.dump(config, f)

    process: Optional[asyncio.subprocess.Process] = None
    try:
        process = await asyncio.create_subprocess_exec(
            singbox_path, "run", "-c", config_path,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )

        # 等待 sing-box 启动
        await asyncio.sleep(1.5)

        # 检查进程是否仍在运行
        if process.returncode is not None:
            logger.warning("sing-box 启动失败 (exit %d): %s", process.returncode, node.name)
            return

        exit_ip = await _get_exit_ip(port, timeout)
        if exit_ip:
            node.exit_ip = exit_ip
            node.test_success = True
            logger.debug("节点 %s 出口 IP: %s", node.name, exit_ip)
        else:
            logger.debug("节点 %s 无法获取出口 IP", node.name)

    except Exception as e:
        logger.warning("测试节点失败 %s: %s", node.name, e)
    finally:
        if process and process.returncode is None:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=3)
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
        try:
            os.remove(config_path)
        except OSError:
            pass


async def _get_exit_ip(port: int, timeout: int) -> Optional[str]:
    """依次尝试多个 IP 检测服务，通过 socks5 代理获取出口 IP。"""
    for url in IP_CHECK_URLS:
        try:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s",
                "--max-time", str(timeout),
                "--proxy", f"socks5://127.0.0.1:{port}",
                url,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(
                proc.communicate(), timeout=timeout + 5
            )
            ip = stdout.decode().strip()
            if ip and is_ip(ip):
                return ip
        except (asyncio.TimeoutError, Exception):
            continue
    return None
