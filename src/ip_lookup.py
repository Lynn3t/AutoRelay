"""IP2Location PX4 LITE CSV 查询 — 二分查找 ISP。"""

from __future__ import annotations

import bisect
import csv
import ipaddress
import logging
from typing import Optional

logger = logging.getLogger(__name__)


class IP2LocationDB:
    """加载 IP2Location PX4 LITE CSV 并提供 IP → ISP 查询。"""

    def __init__(self, csv_path: str):
        self._ip_from: list[int] = []
        self._ip_to: list[int] = []
        self._isp: list[str] = []
        self._load(csv_path)

    def _load(self, csv_path: str) -> None:
        """加载 CSV 到内存。"""
        count = 0
        with open(csv_path, "r", encoding="utf-8-sig") as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) < 8:
                    continue
                try:
                    ip_from = int(row[0].strip('"'))
                    ip_to = int(row[1].strip('"'))
                    isp = row[7].strip('" ')
                except (ValueError, IndexError):
                    continue
                self._ip_from.append(ip_from)
                self._ip_to.append(ip_to)
                self._isp.append(isp)
                count += 1
        logger.info("IP2Location 已加载 %d 条记录", count)

    def lookup(self, ip_str: str) -> Optional[str]:
        """查询 IP 对应的 ISP，未找到返回 None。"""
        ip_num = self._ip_to_int(ip_str)
        if ip_num is None:
            return None

        # 二分查找：最大的 ip_from <= ip_num
        idx = bisect.bisect_right(self._ip_from, ip_num) - 1
        if idx < 0:
            return None

        if self._ip_from[idx] <= ip_num <= self._ip_to[idx]:
            isp = self._isp[idx]
            return isp if isp and isp != "-" else None
        return None

    @staticmethod
    def _ip_to_int(ip_str: str) -> Optional[int]:
        try:
            return int(ipaddress.ip_address(ip_str))
        except ValueError:
            return None
