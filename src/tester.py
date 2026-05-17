"""并发出口 IP 测试 — 管理 sing-box 进程，通过代理查询 ip-api.com 同时获取出口 IP 和 ISP。"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from typing import Optional

import aiohttp

try:
    from aiohttp_socks import ProxyConnector
    HAS_SOCKS = True
except ImportError:
    HAS_SOCKS = False

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
# ISP 补查（当 ip-api.com 拿到 IP 但缺 ISP 时使用）
IP_SB_GEO_URL = "https://api.ip.sb/geoip"


async def test_exit_ips(
    nodes: list[Node],
    singbox_path: str,
    batch_size: int = 10,
    timeout: int = 15,
    port_offset: int = 0,
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
            _test_single(node, singbox_path, BASE_PORT + port_offset + j, timeout)
            for j, node in enumerate(batch)
        ]
        await asyncio.gather(*tasks, return_exceptions=True)

        ok = sum(1 for n in batch if n.test_success)
        isp_ok = sum(1 for n in batch if n.test_success and n.exit_isp)
        logger.info("批次 %d 完成: %d/%d 成功", batch_num, ok, len(batch))
        if isp_ok < ok:
            missing_nodes = [n for n in batch if n.test_success and not n.exit_isp]
            missing_ips = [f"{n.exit_ip} ({n.name})" for n in missing_nodes]
            logger.warning(
                "批次 %d: %d/%d 个成功节点缺少出口 ISP (将显示为 Unknown): %s",
                batch_num, ok - isp_ok, ok, ", ".join(missing_ips),
            )


async def _test_single(
    node: Node, singbox_path: str, port: int, timeout: int
) -> None:
    """测试单个节点，失败时重试一次。"""
    if await _try_once(node, singbox_path, port, timeout):
        return
    logger.debug("节点 %s 首次测试失败，重试...", node.name)
    await _try_once(node, singbox_path, port, timeout)


async def _wait_for_port(port: int, timeout: float = 5.0, interval: float = 0.1) -> bool:
    """轮询等待端口就绪，替代固定 sleep。"""
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.close()
            await writer.wait_closed()
            return True
        except (ConnectionRefusedError, OSError):
            await asyncio.sleep(interval)
    return False


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

        # 轮询等待端口就绪
        if not await _wait_for_port(port, timeout=5.0):
            stderr_text = await _read_stderr(process)
            logger.warning(
                "sing-box 启动超时 (port %d): %s | stderr: %s",
                port, node.name, stderr_text or "(empty)",
            )
            return False

        # 检查进程是否仍在运行
        if process.returncode is not None:
            stderr_text = await _read_stderr(process)
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

        # 连接失败 — 终止进程并捕获 stderr 以便诊断
        process.terminate()
        try:
            await asyncio.wait_for(process.wait(), timeout=3)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
        stderr_text = await _read_stderr(process)
        logger.warning("节点 %s 连接失败 | stderr: %s", node.name, stderr_text or "(empty)")
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
    if HAS_SOCKS:
        return await _query_exit_info_aiohttp(port, timeout)
    return await _query_exit_info_curl(port, timeout)


async def _query_exit_info_aiohttp(port: int, timeout: int) -> Optional[dict]:
    """通过 aiohttp+socks 查询出口信息（无子进程开销）。"""
    proxy_url = f"socks5://127.0.0.1:{port}"
    connector = ProxyConnector.from_url(proxy_url)
    client_timeout = aiohttp.ClientTimeout(total=timeout)

    try:
        async with aiohttp.ClientSession(connector=connector, timeout=client_timeout) as session:
            async with session.get(IP_API_URL) as resp:
                data = await resp.json(content_type=None)
                if data.get("status") == "success" and data.get("query"):
                    result = {"ip": data["query"], "isp": data.get("isp"), "country": data.get("country")}
                    if not result["isp"]:
                        result = await _supplement_isp(session, result)
                    return result
                logger.debug(
                    "ip-api.com 返回非成功状态 (port %d): %s",
                    port, data.get("message", data.get("status")),
                )
    except asyncio.TimeoutError:
        logger.debug("ip-api.com 通过代理查询超时 (port %d)", port)
    except Exception as e:
        logger.debug("ip-api.com 通过代理查询失败 (port %d): %s", port, e)

    # 备选：只获取 IP（无 ISP）
    logger.debug("ip-api.com 失败，使用备选 URL (port %d)", port)
    for url in IP_FALLBACK_URLS:
        try:
            async with aiohttp.ClientSession(connector=connector, timeout=client_timeout) as session:
                async with session.get(url) as resp:
                    ip = (await resp.text()).strip()
                    if ip and _is_ip(ip):
                        result = {"ip": ip, "isp": None}
                        result = await _supplement_isp(session, result)
                        return result
        except (asyncio.TimeoutError, Exception):
            continue
    return None


async def _supplement_isp(session: aiohttp.ClientSession, result: dict) -> dict:
    """当 result 缺少 isp 时，通过 ip.sb geo API 补查。"""
    if result.get("isp"):
        return result
    try:
        async with session.get(IP_SB_GEO_URL) as resp:
            data = await resp.json(content_type=None)
            if data.get("isp"):
                result["isp"] = data["isp"]
            if data.get("country") and not result.get("country"):
                result["country"] = data["country"]
    except Exception as e:
        logger.debug("ip.sb geo 补查失败: %s", e)
    if not result.get("isp"):
        logger.debug("ip.sb 补查后仍无 ISP，IP: %s", result.get("ip"))
    return result


async def _query_exit_info_curl(port: int, timeout: int) -> Optional[dict]:
    """通过 curl 子进程查询出口信息（降级方案）。"""
    proxy = f"socks5://127.0.0.1:{port}"
    # 优先用 ip-api.com（同时拿 IP + ISP）
    try:
        proc = await asyncio.create_subprocess_exec(
            "curl", "-s",
            "--max-time", str(timeout),
            "--proxy", proxy,
            IP_API_URL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(
            proc.communicate(), timeout=timeout + 5
        )
        data = json.loads(stdout.decode().strip())
        if data.get("status") == "success" and data.get("query"):
            result = {"ip": data["query"], "isp": data.get("isp"), "country": data.get("country")}
            if not result["isp"]:
                result = await _supplement_isp_curl(proxy, timeout, result)
            return result
        logger.debug(
            "ip-api.com 返回非成功状态 (port %d): %s",
            port, data.get("message", data.get("status")),
        )
    except asyncio.TimeoutError:
        logger.debug("ip-api.com 通过代理查询超时 (port %d)", port)
    except json.JSONDecodeError as e:
        logger.debug("ip-api.com 返回非 JSON 响应 (port %d): %s", port, e)
    except Exception as e:
        logger.debug("ip-api.com 通过代理查询失败 (port %d): %s", port, e)

    # 备选：只获取 IP（无 ISP）
    logger.debug("ip-api.com 失败，使用备选 URL (port %d)", port)
    for url in IP_FALLBACK_URLS:
        try:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s",
                "--max-time", str(timeout),
                "--proxy", proxy,
                url,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(
                proc.communicate(), timeout=timeout + 5
            )
            ip = stdout.decode().strip()
            if ip and _is_ip(ip):
                result = {"ip": ip, "isp": None}
                result = await _supplement_isp_curl(proxy, timeout, result)
                return result
        except (asyncio.TimeoutError, Exception):
            continue
    return None


async def _supplement_isp_curl(proxy: str, timeout: int, result: dict) -> dict:
    """当 result 缺少 isp 时，通过 curl 查询 ip.sb geo API 补查。"""
    if result.get("isp"):
        return result
    try:
        proc = await asyncio.create_subprocess_exec(
            "curl", "-s",
            "--max-time", str(timeout),
            "--proxy", proxy,
            IP_SB_GEO_URL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(
            proc.communicate(), timeout=timeout + 5
        )
        data = json.loads(stdout.decode().strip())
        if data.get("isp"):
            result["isp"] = data["isp"]
        if data.get("country") and not result.get("country"):
            result["country"] = data["country"]
    except Exception as e:
        logger.debug("ip.sb geo 补查失败 (curl): %s", e)
    if not result.get("isp"):
        logger.debug("ip.sb 补查后仍无 ISP，IP: %s", result.get("ip"))
    return result


def _is_ip(address: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False


async def _read_stderr(process: asyncio.subprocess.Process) -> str:
    """Read and sanitize stderr from a (terminated) process."""
    if not process.stderr:
        return ""
    try:
        raw = await asyncio.wait_for(process.stderr.read(), timeout=2)
        return _sanitize_log(raw.decode("utf-8", errors="replace"))
    except (asyncio.TimeoutError, Exception):
        return "(read error)"


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
