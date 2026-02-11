"""GitHub Gist 创建/更新 — 支持多条订阅分别存入不同 Gist。"""

from __future__ import annotations

import logging
from typing import Optional

import requests

logger = logging.getLogger(__name__)

GIST_DESC_PREFIX = "AutoRelay"


def upload_to_gist(
    token: str,
    content: str,
    sub_name: str = "default",
) -> str:
    """创建或更新私有 Gist，返回 Gist raw URL。

    每条订阅通过 sub_name 区分，映射到独立的 Gist。
    """
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github+json",
    }

    description = f"{GIST_DESC_PREFIX} - {sub_name}"
    filename = f"{sub_name}"

    gist_id = _find_existing_gist(headers, description)

    payload = {
        "description": description,
        "public": False,
        "files": {
            filename: {"content": content},
        },
    }

    if gist_id:
        logger.info("更新已有 Gist [%s]", sub_name)
        resp = requests.patch(
            f"https://api.github.com/gists/{gist_id}",
            headers=headers,
            json=payload,
            timeout=30,
        )
    else:
        logger.info("创建新 Gist [%s]", sub_name)
        resp = requests.post(
            "https://api.github.com/gists",
            headers=headers,
            json=payload,
            timeout=30,
        )

    resp.raise_for_status()
    data = resp.json()

    # 取 raw URL (可直接作为订阅链接)
    raw_url = ""
    files = data.get("files", {})
    if filename in files:
        raw_url = files[filename].get("raw_url", "")

    logger.info("Gist [%s] 上传成功", sub_name)

    return raw_url or data.get("html_url", "")


def _find_existing_gist(headers: dict, description: str) -> Optional[str]:
    """通过描述查找已有的 Gist。"""
    try:
        resp = requests.get(
            "https://api.github.com/gists",
            headers=headers,
            params={"per_page": 100},
            timeout=15,
        )
        resp.raise_for_status()
        for gist in resp.json():
            if gist.get("description") == description:
                return gist["id"]
    except Exception as e:
        logger.warning("查找 Gist 失败: %s", e)
    return None
