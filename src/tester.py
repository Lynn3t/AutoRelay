"""并发出口 IP 测试 — 管理 sing-box 进程，通过代理查询 ip-api.com 同时获取出口 IP 和 ISP。"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from typing import Optional

from src.models import Node
from src.singbox_config import generate_singbox_config

logger = logging.getLogger(__name__)

BASE_PORT = 10000

# 通过代理访问，每个代理 IP 有独立限速配额，不受 runner IP 限制
IP_API_URL = "http://ip-api.com/json/?fields=status,query,isp,country"
# 备选（仅获取 IP，无 ISP）
IP_FALLBACK_URLS = [
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
    """分批并发测试所有节点的出口 IP 和 ISP。"""
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
    """测试单个节点，失败时重试一次。"""
    if await _try_once(node, singbox_path, port, timeout):
        return
    logger.debug("节点 %s 首次测试失败，重试...", node.name)
    await _try_once(node, singbox_path, port, timeout)


async def _try_once(
    node: Node, singbox_path: str, port: int, timeout: int
) -> bool:
    """单次测试：启动 sing-box → 通过代理查询 ip-api.com → 获取出口 IP + ISP。返回是否成功。"""
    config = generate_singbox_config(node, port)
    config_path = f"/tmp/singbox_{port}.json"

    with open(config_path, "w") as f:
        json.dump(config, f)

    process: Optional[asyncio.subprocess.Process] = None
    try:
        process = await asyncio.create_subprocess_exec(
            singbox_path, "run", "-c", config_path,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )

        # 等待 sing-box 启动
        await asyncio.sleep(1.5)

        # 检查进程是否仍在运行
        if process.returncode is not None:
            stderr_text = ""
            if process.stderr:
                try:
                    raw = await asyncio.wait_for(process.stderr.read(), timeout=2)
                    stderr_text = _sanitize_log(raw.decode("utf-8", errors="replace"))
                except asyncio.TimeoutError:
                    stderr_text = "(read timeout)"
            logger.warning(
                "sing-box 启动失败 (exit %d): %s | stderr: %s",
                process.returncode, node.name, stderr_text or "(empty)",
            )
            return False

        # 通过代理查询 ip-api.com，同时获取出口 IP 和 ISP
        result = await _query_exit_info(port, timeout)
        if result:
            node.exit_ip = result["ip"]
            node.exit_isp = result.get("isp")
            node.exit_country = result.get("country")
            node.test_success = True
            logger.debug("节点 %s → 出口 %s (%s)", node.name, result["ip"], result.get("isp", "?"))
            return True
        else:
            logger.debug("节点 %s 无法获取出口信息", node.name)
            return False

    except Exception as e:
        logger.warning("测试节点失败 %s: %s", node.name, e)
        return False
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


async def _query_exit_info(port: int, timeout: int) -> Optional[dict]:
    """通过 socks5 代理查询 ip-api.com，返回 {"ip": ..., "isp": ...}。"""
    # 优先用 ip-api.com（同时拿 IP + ISP）
    try:
        proc = await asyncio.create_subprocess_exec(
            "curl", "-s",
            "--max-time", str(timeout),
            "--proxy", f"socks5://127.0.0.1:{port}",
            IP_API_URL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(
            proc.communicate(), timeout=timeout + 5
        )
        data = json.loads(stdout.decode().strip())
        if data.get("status") == "success" and data.get("query"):
            return {"ip": data["query"], "isp": data.get("isp"), "country": data.get("country")}
    except (asyncio.TimeoutError, json.JSONDecodeError, Exception):
        pass

    # 备选：只获取 IP（无 ISP）
    for url in IP_FALLBACK_URLS:
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
            if ip and _is_ip(ip):
                return {"ip": ip, "isp": None}
        except (asyncio.TimeoutError, Exception):
            continue
    return None


def _is_ip(address: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False


def _sanitize_log(text: str) -> str:
    """Remove sensitive credentials from sing-box log output."""
    # Mask UUIDs
    text = re.sub(
        r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
        '[UUID]', text, flags=re.IGNORECASE,
    )
    # Mask JSON password fields
    text = re.sub(r'"password"\s*:\s*"[^"]*"', '"password":"[REDACTED]"', text)
    # Mask auth_str fields
    text = re.sub(r'"auth_str"\s*:\s*"[^"]*"', '"auth_str":"[REDACTED]"', text)
    # Mask public_key fields (Reality)
    text = re.sub(r'"public_key"\s*:\s*"[^"]*"', '"public_key":"[REDACTED]"', text)
    # Mask short_id fields (Reality)
    text = re.sub(r'"short_id"\s*:\s*"[^"]*"', '"short_id":"[REDACTED]"', text)
    # Mask long base64-like strings (potential keys/tokens, 32+ chars)
    text = re.sub(r'(?<![A-Za-z0-9+/=])[A-Za-z0-9+/=]{32,}(?![A-Za-z0-9+/=])', '[REDACTED_KEY]', text)
    return text.strip()
