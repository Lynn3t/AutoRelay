"""节点重命名 — 格式: [国家] 入口ISP - [国家] 出口ISP。

直连节点（入口与出口同一IP段）只显示出口信息。
中国节点不显示国家名。
"""

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
    ("jd cloud", "京东云"),
    ("ksyun", "金山云"),
    # 港台
    ("hinet", "中华电信"),
    ("chunghwa", "中华电信"),
    ("taiwan mobile", "台湾大哥大"),
    ("aptg", "远传电信"),
    ("fareastone", "远传电信"),
    ("seednet", "SeedNet"),
    ("pccw", "PCCW"),
    ("hong kong broadband", "HKBN"),
    ("hkt", "HKT"),
    ("smartone", "SmarTone"),
    ("hutchison", "和记"),
    # 日韩
    ("softbank", "SoftBank"),
    ("ntt", "NTT"),
    ("kddi", "KDDI"),
    ("iij", "IIJ"),
    ("sakura", "Sakura"),
    ("sk broadband", "SK"),
    ("kt corporation", "KT"),
    ("lg uplus", "LG U+"),
    ("lg powercomm", "LG U+"),
    # 东南亚
    ("singtel", "Singtel"),
    ("starhub", "StarHub"),
    ("m1 limited", "M1"),
    ("viewqwest", "ViewQwest"),
    # 北美
    ("amazon", "AWS"),
    ("microsoft", "Azure"),
    ("google", "GCP"),
    ("cloudflare", "Cloudflare"),
    ("digitalocean", "DO"),
    ("linode", "Linode"),
    ("vultr", "Vultr"),
    ("oracle", "Oracle"),
    ("bandwagon", "搬瓦工"),
    ("cogent", "Cogent"),
    ("comcast", "Comcast"),
    ("verizon", "Verizon"),
    ("at&t", "AT&T"),
    ("att services", "AT&T"),
    ("charter", "Charter"),
    ("spectrum", "Spectrum"),
    ("t-mobile", "T-Mobile"),
    ("sprint", "Sprint"),
    ("frontier", "Frontier"),
    ("wave broadband", "Wave"),
    ("waveg", "Wave"),
    ("cox comm", "Cox"),
    ("centurylink", "CenturyLink"),
    ("lumen", "Lumen"),
    ("zayo", "Zayo"),
    ("he.net", "HE"),
    ("hurricane", "HE"),
    ("quadranet", "QuadraNet"),
    ("multacom", "Multacom"),
    ("psychz", "Psychz"),
    ("colocrossing", "ColoCrossing"),
    ("buyvm", "BuyVM"),
    ("racknerd", "RackNerd"),
    ("hostdare", "HostDare"),
    # 云/VPS 服务商
    ("akari", "Akari"),
    ("akari networks", "Akari"),
    ("dmit", "DMIT"),
    ("gigsgigscloud", "GigsGigs"),
    ("rackspace", "Rackspace"),
    ("contabo", "Contabo"),
    ("kamatera", "Kamatera"),
    ("hostwinds", "HostWinds"),
    ("scaleway", "Scaleway"),
    ("upcloud", "UpCloud"),
    ("ionos", "IONOS"),
    ("lightsail", "Lightsail"),
    ("netlify", "Netlify"),
    ("fly.io", "Fly.io"),
    # 欧洲
    ("hetzner", "Hetzner"),
    ("ovh", "OVH"),
    ("online s.a.s", "Scaleway"),
    ("iliad", "Iliad"),
    ("vodafone", "Vodafone"),
    ("deutsche telekom", "DT"),
    ("british telecom", "BT"),
    ("orange", "Orange"),
    ("telefonica", "Telefonica"),
    ("telia", "Telia"),
    ("swisscom", "Swisscom"),
    ("m247", "M247"),
    ("datacamp", "DataCamp"),
    ("leaseweb", "LeaseWeb"),
    # 其他
    ("choopa", "Vultr"),
    ("the constant company", "Vultr"),
    ("hostinger", "Hostinger"),
    ("akamai", "Akamai"),
    ("fastly", "Fastly"),
]

# 国家名翻译映射 (ip-api.com 返回的英文国家名 → 中文)
COUNTRY_TRANSLATE: dict[str, str] = {
    "China": "中国",
    "Hong Kong": "香港",
    "Taiwan": "台湾",
    "Japan": "日本",
    "South Korea": "韩国",
    "Singapore": "新加坡",
    "United States": "美国",
    "Canada": "加拿大",
    "United Kingdom": "英国",
    "Germany": "德国",
    "France": "法国",
    "Netherlands": "荷兰",
    "Australia": "澳大利亚",
    "Russia": "俄罗斯",
    "India": "印度",
    "Brazil": "巴西",
    "Thailand": "泰国",
    "Vietnam": "越南",
    "Philippines": "菲律宾",
    "Malaysia": "马来西亚",
    "Indonesia": "印尼",
    "Turkey": "土耳其",
    "Italy": "意大利",
    "Spain": "西班牙",
    "Sweden": "瑞典",
    "Switzerland": "瑞士",
    "Ireland": "爱尔兰",
    "Finland": "芬兰",
    "Norway": "挪威",
    "Poland": "波兰",
    "Romania": "罗马尼亚",
    "Ukraine": "乌克兰",
    "South Africa": "南非",
    "Argentina": "阿根廷",
    "Mexico": "墨西哥",
    "Chile": "智利",
    "Colombia": "哥伦比亚",
    "Israel": "以色列",
    "United Arab Emirates": "阿联酋",
    "Kazakhstan": "哈萨克斯坦",
}

# 视为"中国"不需要显示国家名的地区
CHINA_REGIONS = {"中国", "China"}


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


def translate_country(country: str | None) -> str:
    """将英文国家名翻译为中文，没有映射则保留原名。"""
    if not country:
        return ""
    return COUNTRY_TRANSLATE.get(country, country)


def is_direct_connection(entry_ip: str | None, exit_ip: str | None) -> bool:
    """判断是否为直连（入口和出口在同一 /24 网段）。"""
    if not entry_ip or not exit_ip:
        return False
    try:
        entry_parts = entry_ip.split(".")
        exit_parts = exit_ip.split(".")
        if len(entry_parts) == 4 and len(exit_parts) == 4:
            return entry_parts[:3] == exit_parts[:3]
    except (ValueError, IndexError):
        pass
    return False


def _format_label(country: str | None, isp: str) -> str:
    """格式化单端标签: 中国不显示国家，其它显示 '国家 ISP'。"""
    cn = translate_country(country)
    if not cn or cn in CHINA_REGIONS:
        return isp
    return f"{cn} {isp}"


def rename_nodes(nodes: list[Node]) -> None:
    """重命名所有成功测试的节点，处理重复名称。

    失败但有入口 ISP 的节点重命名为: entry_isp - 原名。
    """
    name_count: dict[str, int] = {}

    for node in nodes:
        if not node.test_success:
            # 失败节点：如果有入口 ISP，用 entry_isp - 原名
            if node.entry_isp:
                entry_isp = simplify_isp(node.entry_isp)
                entry_label = _format_label(node.entry_country, entry_isp)
                node.final_name = f"{entry_label} - {node.name}"
            continue

        exit_isp = simplify_isp(node.exit_isp or "")

        if is_direct_connection(node.entry_ip, node.exit_ip):
            # 直连: 只显示出口信息
            base_name = _format_label(node.exit_country, exit_isp)
        else:
            entry_isp = simplify_isp(node.entry_isp or "")
            entry_label = _format_label(node.entry_country, entry_isp)
            exit_label = _format_label(node.exit_country, exit_isp)
            base_name = f"{entry_label} - {exit_label}"

        name_count[base_name] = name_count.get(base_name, 0) + 1
        if name_count[base_name] > 1:
            node.final_name = f"{base_name} #{name_count[base_name]}"
        else:
            node.final_name = base_name
