"""节点重命名 — 格式: 入口ISP - 出口ISP。"""

from __future__ import annotations

import logging

from src.models import Node

logger = logging.getLogger(__name__)

# 常见 ISP 名称简化映射 (英文原名关键词 → 简称)
ISP_SIMPLIFY: list[tuple[str, str]] = [
    # 中国大陆
    ("tencent", "腾讯云"),
    ("alibaba", "阿里云"),
    ("alicloud", "阿里云"),
    ("aliyun", "阿里云"),
    ("huawei cloud", "华为云"),
    ("china telecom", "电信"),
    ("china unicom", "联通"),
    ("china mobile", "移动"),
    ("chinanet", "电信"),
    ("cernet", "教育网"),
    ("baidu", "百度云"),
    ("ucloud", "UCloud"),
    ("bytedance", "字节"),
    # 国际
    ("amazon", "AWS"),
    ("microsoft", "Azure"),
    ("google", "GCP"),
    ("cloudflare", "Cloudflare"),
    ("digitalocean", "DO"),
    ("linode", "Linode"),
    ("vultr", "Vultr"),
    ("oracle", "Oracle"),
    ("hetzner", "Hetzner"),
    ("ovh", "OVH"),
    ("bandwagon", "搬瓦工"),
    ("cogent", "Cogent"),
    ("comcast", "Comcast"),
    ("verizon", "Verizon"),
    ("at&t", "AT&T"),
    ("att services", "AT&T"),
    ("charter", "Charter"),
    ("t-mobile", "T-Mobile"),
    ("sprint", "Sprint"),
    ("softbank", "SoftBank"),
    ("ntt", "NTT"),
    ("kddi", "KDDI"),
    ("sk broadband", "SK"),
    ("kt corporation", "KT"),
    ("hinet", "HiNet"),
    ("chunghwa", "中华电信"),
    ("pccw", "PCCW"),
    ("hong kong broadband", "HKBN"),
    ("singtel", "Singtel"),
    ("starhub", "StarHub"),
]


def simplify_isp(isp: str) -> str:
    """简化 ISP 名称。"""
    if not isp:
        return "Unknown"
    lower = isp.lower()
    for keyword, short in ISP_SIMPLIFY:
        if keyword in lower:
            return short
    # 如果太长，截取公司名主体（第一个逗号之前）
    if len(isp) > 20 and "," in isp:
        isp = isp.split(",")[0].strip()
    return isp


def rename_nodes(nodes: list[Node]) -> None:
    """重命名所有成功测试的节点，处理重复名称。"""
    name_count: dict[str, int] = {}

    for node in nodes:
        if not node.test_success:
            continue

        entry = simplify_isp(node.entry_isp or "")
        exit_ = simplify_isp(node.exit_isp or "")
        base_name = f"{entry} - {exit_}"

        name_count[base_name] = name_count.get(base_name, 0) + 1
        if name_count[base_name] > 1:
            node.final_name = f"{base_name} #{name_count[base_name]}"
        else:
            node.final_name = base_name

    # 如果某个 base_name 只出现 1 次，第一个不需要加序号 — 上面逻辑已自然处理
