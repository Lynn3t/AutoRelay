"""Shared fixtures for AutoRelay tests."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.models import Node, ProxyType


@pytest.fixture
def make_node():
    """Factory fixture for creating test Node instances."""

    def _make(
        name: str = "test",
        server: str = "example.com",
        port: int = 443,
        proxy_type: ProxyType = ProxyType.VLESS,
        **kwargs,
    ) -> Node:
        defaults = dict(uuid="test-uuid-1234")
        defaults.update(kwargs)
        return Node(name=name, proxy_type=proxy_type, server=server, port=port, **defaults)

    return _make


@pytest.fixture
def make_mock_process():
    """Factory fixture for creating mock asyncio subprocess Process objects."""

    def _make(returncode=None, stdout=b"", stderr=b""):
        proc = AsyncMock()
        # returncode=None means process is still running
        proc.returncode = returncode
        proc.stderr = AsyncMock()
        proc.stderr.read = AsyncMock(return_value=stderr)
        proc.communicate = AsyncMock(return_value=(stdout, stderr))
        proc.wait = AsyncMock(return_value=returncode if returncode is not None else 0)

        # Make terminate() set returncode to simulate process stopping
        def _terminate():
            proc.returncode = 0

        proc.terminate = MagicMock(side_effect=_terminate)
        proc.kill = MagicMock()
        return proc

    return _make
