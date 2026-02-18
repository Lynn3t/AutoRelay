"""Multithreading (async concurrency) tests for AutoRelay.

Tests cover:
  Part 1 — Relay tests (tester.py): batch processing, task isolation,
           retry logic, process cleanup, exit info queries.
  Part 2 — Subscription tests: DNS resolution, ISP lookup, subscription fetching.
  Part 3 — End-to-end pipeline concurrency.
"""

from __future__ import annotations

import asyncio
import base64
import json
from unittest.mock import AsyncMock, MagicMock, patch, call

import pytest
from aioresponses import aioresponses

from src.models import Node, ProxyType
from src.tester import test_exit_ips as run_exit_ip_tests
from src.tester import _test_single, _try_once, _query_exit_info, BASE_PORT
from src.dns_resolver import resolve_entry_ips, resolve_domain
from src.ip_lookup import lookup_isps, IpInfo, BATCH_SIZE, RATE_LIMIT_DELAY
from src.main import process_subscription, deduplicate
from src.parsers.dispatcher import fetch_and_parse


# ======================================================================
# Part 1: Relay / tester.py concurrency tests
# ======================================================================


class TestRelayBatchProcessing:
    """Tests for batch processing and port allocation in test_exit_ips."""

    @pytest.mark.asyncio
    async def test_batch_processing_correct_port_allocation(self, make_node):
        """Verify batch sizes and per-batch port offset reset."""
        nodes = [make_node(name=f"n{i}", server=f"s{i}.example.com") for i in range(25)]
        call_log = []

        async def mock_test_single(node, singbox_path, port, timeout):
            call_log.append((node.name, port))

        with patch("src.tester._test_single", side_effect=mock_test_single):
            await run_exit_ip_tests(nodes, singbox_path="./sing-box", batch_size=10, timeout=15)

        assert len(call_log) == 25

        # Batch 1: nodes 0-9, ports BASE_PORT+0 .. BASE_PORT+9
        for j in range(10):
            assert call_log[j] == (f"n{j}", BASE_PORT + j)

        # Batch 2: nodes 10-19, ports reset to BASE_PORT+0 .. BASE_PORT+9
        for j in range(10):
            assert call_log[10 + j] == (f"n{10 + j}", BASE_PORT + j)

        # Batch 3: nodes 20-24, ports BASE_PORT+0 .. BASE_PORT+4
        for j in range(5):
            assert call_log[20 + j] == (f"n{20 + j}", BASE_PORT + j)

    @pytest.mark.asyncio
    async def test_batch_partial_success(self, make_node):
        """Mixed success/failure within a batch — independent handling."""
        nodes = [make_node(name=f"n{i}", server=f"s{i}.com") for i in range(10)]

        async def mock_test_single(node, singbox_path, port, timeout):
            idx = int(node.name[1:])
            if idx % 2 == 0:
                node.test_success = True
                node.exit_ip = f"1.1.1.{idx}"

        with patch("src.tester._test_single", side_effect=mock_test_single):
            await run_exit_ip_tests(nodes, "./sing-box", batch_size=10, timeout=15)

        success = [n for n in nodes if n.test_success]
        failed = [n for n in nodes if not n.test_success]
        assert len(success) == 5
        assert len(failed) == 5
        for n in success:
            assert int(n.name[1:]) % 2 == 0

    @pytest.mark.asyncio
    async def test_gather_return_exceptions_handling(self, make_node):
        """One failing task must not cancel sibling tasks."""
        nodes = [make_node(name=f"n{i}", server=f"s{i}.com") for i in range(5)]
        completed = []

        async def mock_test_single(node, singbox_path, port, timeout):
            idx = int(node.name[1:])
            if idx == 3:
                raise RuntimeError("boom")
            node.test_success = True
            completed.append(node.name)

        with patch("src.tester._test_single", side_effect=mock_test_single):
            await run_exit_ip_tests(nodes, "./sing-box", batch_size=10, timeout=15)

        # 4 out of 5 should complete (n3 raised)
        assert len(completed) == 4
        assert "n3" not in completed
        assert not nodes[3].test_success


class TestRelayTaskIsolation:
    """Tests for concurrent task isolation — no result bleed."""

    @pytest.mark.asyncio
    async def test_concurrent_task_isolation_no_result_bleed(self, make_node, make_mock_process):
        """Each node gets its own exit_ip/isp when tested concurrently."""
        nodes = [make_node(name=f"n{i}", server=f"s{i}.com") for i in range(5)]

        async def mock_subprocess(*args, **kwargs):
            if "sing-box" in str(args[0]):
                return make_mock_process(returncode=None)
            elif "curl" in str(args[0]):
                # Extract port from --proxy arg
                port = None
                for k, a in enumerate(args):
                    if a == "--proxy":
                        port = int(args[k + 1].split(":")[-1])
                        break
                idx = port - BASE_PORT if port else 0
                body = json.dumps({
                    "status": "success",
                    "query": f"1.2.3.{idx}",
                    "isp": f"ISP-{idx}",
                    "country": "US",
                }).encode()
                return make_mock_process(returncode=0, stdout=body)
            return make_mock_process(returncode=0)

        with (
            patch("asyncio.create_subprocess_exec", side_effect=mock_subprocess),
            patch("src.tester.asyncio.sleep", new_callable=AsyncMock),
            patch("builtins.open", MagicMock()),
            patch("os.remove", MagicMock()),
        ):
            await run_exit_ip_tests(nodes, "./sing-box", batch_size=5, timeout=15)

        for i, node in enumerate(nodes):
            assert node.test_success is True, f"node n{i} should succeed"
            assert node.exit_ip == f"1.2.3.{i}", f"node n{i} got wrong exit_ip: {node.exit_ip}"
            assert node.exit_isp == f"ISP-{i}"

        # Verify no two nodes share exit_ip
        exit_ips = [n.exit_ip for n in nodes]
        assert len(set(exit_ips)) == len(exit_ips)


class TestRelayRetryLogic:
    """Tests for _test_single retry logic."""

    @pytest.mark.asyncio
    async def test_retry_logic_under_concurrent_load(self, make_node):
        """_test_single retries once on failure; concurrent retries don't interfere."""
        nodes = [make_node(name=f"n{i}", server=f"s{i}.com") for i in range(5)]
        call_counts: dict[str, int] = {}

        async def mock_try_once(node, singbox_path, port, timeout):
            call_counts[node.name] = call_counts.get(node.name, 0) + 1
            if call_counts[node.name] == 1:
                return False  # First attempt fails
            node.test_success = True
            node.exit_ip = f"10.0.0.{int(node.name[1:])}"
            return True  # Retry succeeds

        with patch("src.tester._try_once", side_effect=mock_try_once):
            tasks = [_test_single(n, "./sing-box", BASE_PORT + i, 15) for i, n in enumerate(nodes)]
            await asyncio.gather(*tasks)

        assert sum(call_counts.values()) == 10  # 2 calls per node
        for n in nodes:
            assert n.test_success is True

    @pytest.mark.asyncio
    async def test_retry_both_attempts_fail(self, make_node):
        """Node stays test_success=False when both attempts fail."""
        node = make_node(name="fail-node")

        async def mock_try_once(n, sp, port, timeout):
            return False

        with patch("src.tester._try_once", side_effect=mock_try_once):
            await _test_single(node, "./sing-box", BASE_PORT, 15)

        assert node.test_success is False
        assert node.exit_ip is None


class TestRelayProcessCleanup:
    """Tests for process cleanup under failure conditions."""

    @pytest.mark.asyncio
    async def test_process_cleanup_on_concurrent_failures(self, make_node, make_mock_process):
        """terminate() called on all processes when all curl queries fail."""
        nodes = [make_node(name=f"n{i}", server=f"s{i}.com") for i in range(5)]
        processes_created = []

        async def mock_subprocess(*args, **kwargs):
            if "sing-box" in str(args[0]):
                proc = make_mock_process(returncode=None)
                processes_created.append(proc)
                return proc
            elif "curl" in str(args[0]):
                # Curl returns invalid response
                return make_mock_process(returncode=0, stdout=b"invalid")
            return make_mock_process(returncode=0)

        with (
            patch("asyncio.create_subprocess_exec", side_effect=mock_subprocess),
            patch("src.tester.asyncio.sleep", new_callable=AsyncMock),
            patch("builtins.open", MagicMock()),
            patch("os.remove", MagicMock()),
        ):
            await run_exit_ip_tests(nodes, "./sing-box", batch_size=5, timeout=15)

        for n in nodes:
            assert n.test_success is False

    @pytest.mark.asyncio
    async def test_process_cleanup_on_exception(self, make_node):
        """Cleanup works when generate_singbox_config raises."""
        nodes = [make_node(name=f"n{i}", server=f"s{i}.com") for i in range(3)]

        with patch("src.tester.generate_singbox_config", side_effect=ValueError("bad config")):
            await run_exit_ip_tests(nodes, "./sing-box", batch_size=3, timeout=15)

        # All fail gracefully — no unhandled exceptions
        for n in nodes:
            assert n.test_success is False


class TestQueryExitInfo:
    """Tests for _query_exit_info primary + fallback logic."""

    @pytest.mark.asyncio
    async def test_query_exit_info_primary_success(self, make_mock_process):
        """ip-api.com returns valid data on first try."""
        body = json.dumps({
            "status": "success",
            "query": "5.6.7.8",
            "isp": "TestISP",
            "country": "US",
        }).encode()

        async def mock_subprocess(*args, **kwargs):
            return make_mock_process(returncode=0, stdout=body)

        with patch("asyncio.create_subprocess_exec", side_effect=mock_subprocess):
            result = await _query_exit_info(BASE_PORT, timeout=15)

        assert result is not None
        assert result["ip"] == "5.6.7.8"
        assert result["isp"] == "TestISP"
        assert result["country"] == "US"

    @pytest.mark.asyncio
    async def test_query_exit_info_fallback_urls(self, make_mock_process):
        """Falls through to fallback URLs when primary fails."""
        call_count = 0

        async def mock_subprocess(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                # Primary ip-api.com fails (invalid JSON)
                return make_mock_process(returncode=0, stdout=b"not json")
            elif call_count == 2:
                # First fallback (ip.sb) returns invalid
                return make_mock_process(returncode=0, stdout=b"not-an-ip")
            elif call_count == 3:
                # Second fallback (ifconfig.me) returns valid IP
                return make_mock_process(returncode=0, stdout=b"9.8.7.6")
            return make_mock_process(returncode=0, stdout=b"")

        with patch("asyncio.create_subprocess_exec", side_effect=mock_subprocess):
            result = await _query_exit_info(BASE_PORT, timeout=15)

        assert result is not None
        assert result["ip"] == "9.8.7.6"
        assert result["isp"] is None
        assert call_count == 3

    @pytest.mark.asyncio
    async def test_query_exit_info_all_fail(self, make_mock_process):
        """Returns None when all endpoints fail."""
        async def mock_subprocess(*args, **kwargs):
            return make_mock_process(returncode=0, stdout=b"garbage")

        with patch("asyncio.create_subprocess_exec", side_effect=mock_subprocess):
            result = await _query_exit_info(BASE_PORT, timeout=15)

        assert result is None


# ======================================================================
# Part 2: Subscription concurrency tests
# ======================================================================


class TestDNSResolution:
    """Tests for concurrent DNS resolution in resolve_entry_ips."""

    @pytest.mark.asyncio
    async def test_dns_resolve_concurrent_deduplication(self, make_node):
        """Deduplicates domains before resolving; all nodes sharing a domain
        get the same entry_ip."""
        domains = ["a.com", "b.com", "c.com"]
        nodes = []
        for d in domains:
            for _ in range(4):
                nodes.append(make_node(server=d))
        # Also add nodes with IP addresses
        nodes.append(make_node(server="1.2.3.4"))
        nodes.append(make_node(server="5.6.7.8"))

        resolve_calls = []

        async def mock_resolve(domain, rdtype="A"):
            resolve_calls.append(domain)
            mock_answer = MagicMock()
            ip = f"10.0.{domains.index(domain)}.1"
            mock_answer.__getitem__ = MagicMock(return_value=MagicMock(__str__=MagicMock(return_value=ip)))
            # Make str() on the first item return the IP
            item = MagicMock()
            item.__str__ = MagicMock(return_value=ip)
            mock_answer.__getitem__ = MagicMock(return_value=item)
            return mock_answer

        with patch("src.dns_resolver.dns.asyncresolver.Resolver") as MockResolver:
            instance = MockResolver.return_value
            instance.resolve = mock_resolve

            await resolve_entry_ips(nodes)

        # Only 3 unique domains should be resolved
        assert len(resolve_calls) == 3

        # IP-based nodes get entry_ip set directly
        assert nodes[-2].entry_ip == "1.2.3.4"
        assert nodes[-1].entry_ip == "5.6.7.8"

        # All nodes sharing a domain should have the same entry_ip
        for d_idx, d in enumerate(domains):
            d_nodes = [n for n in nodes if n.server == d]
            ips = {n.entry_ip for n in d_nodes}
            assert len(ips) == 1, f"Nodes for {d} should all share one entry_ip"

    @pytest.mark.asyncio
    async def test_dns_resolve_partial_failures(self, make_node):
        """Failed DNS lookups only affect those nodes; others succeed."""
        nodes = [
            make_node(server="good1.com"),
            make_node(server="good2.com"),
            make_node(server="bad.com"),
        ]

        async def mock_resolve(domain, rdtype="A"):
            if domain == "bad.com":
                raise Exception("NXDOMAIN")
            mock_answer = MagicMock()
            item = MagicMock()
            item.__str__ = MagicMock(return_value=f"10.0.0.{hash(domain) % 256}")
            mock_answer.__getitem__ = MagicMock(return_value=item)
            return mock_answer

        with patch("src.dns_resolver.dns.asyncresolver.Resolver") as MockResolver:
            instance = MockResolver.return_value
            instance.resolve = mock_resolve
            await resolve_entry_ips(nodes)

        assert nodes[0].entry_ip is not None
        assert nodes[1].entry_ip is not None
        assert nodes[2].entry_ip is None

    @pytest.mark.asyncio
    async def test_dns_resolve_all_ip_addresses_no_queries(self, make_node):
        """When all servers are IPs, no DNS queries are made."""
        nodes = [
            make_node(server="1.2.3.4"),
            make_node(server="5.6.7.8"),
            make_node(server="10.0.0.1"),
        ]

        with patch("src.dns_resolver.dns.asyncresolver.Resolver") as MockResolver:
            instance = MockResolver.return_value
            instance.resolve = AsyncMock(side_effect=Exception("should not be called"))
            await resolve_entry_ips(nodes)

        # All should have entry_ip set from server directly
        assert nodes[0].entry_ip == "1.2.3.4"
        assert nodes[1].entry_ip == "5.6.7.8"
        assert nodes[2].entry_ip == "10.0.0.1"
        instance.resolve.assert_not_called()


class TestISPLookup:
    """Tests for concurrent ISP batch lookups."""

    @pytest.mark.asyncio
    async def test_isp_lookup_batch_splitting_and_rate_limiting(self):
        """250 IPs → 3 batches with rate-limiting sleeps between them."""
        ips = [f"10.0.{i // 256}.{i % 256}" for i in range(250)]

        def make_batch_response(batch_ips):
            return [
                {"status": "success", "query": ip, "isp": f"ISP-{ip}", "country": "US"}
                for ip in batch_ips
            ]

        with aioresponses() as m:
            # Register 3 batch responses
            m.post("http://ip-api.com/batch", payload=make_batch_response(ips[:100]))
            m.post("http://ip-api.com/batch", payload=make_batch_response(ips[100:200]))
            m.post("http://ip-api.com/batch", payload=make_batch_response(ips[200:]))

            with patch("src.ip_lookup.asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
                result = await lookup_isps(ips)

            # Rate-limiting: 2 sleeps (between batch 1-2 and 2-3)
            assert mock_sleep.call_count == 2
            mock_sleep.assert_called_with(RATE_LIMIT_DELAY)

        assert len(result) == 250

    @pytest.mark.asyncio
    async def test_isp_lookup_deduplication(self):
        """Duplicate IPs are deduplicated before API call."""
        ips = ["1.1.1.1", "1.1.1.1", "2.2.2.2", "2.2.2.2", "3.3.3.3"]

        with aioresponses() as m:
            m.post(
                "http://ip-api.com/batch",
                payload=[
                    {"status": "success", "query": "1.1.1.1", "isp": "CF", "country": "US"},
                    {"status": "success", "query": "2.2.2.2", "isp": "GCP", "country": "US"},
                    {"status": "success", "query": "3.3.3.3", "isp": "AWS", "country": "US"},
                ],
            )
            result = await lookup_isps(ips)

        # Only 3 unique entries in the result
        assert len(result) == 3
        assert result["1.1.1.1"].isp == "CF"
        assert result["2.2.2.2"].isp == "GCP"
        assert result["3.3.3.3"].isp == "AWS"

    @pytest.mark.asyncio
    async def test_isp_lookup_api_failure_returns_empty_info(self):
        """API failure returns empty IpInfo for all IPs in the batch."""
        ips = ["1.1.1.1", "2.2.2.2"]

        with aioresponses() as m:
            m.post("http://ip-api.com/batch", exception=Exception("API down"))
            result = await lookup_isps(ips)

        assert len(result) == 2
        for ip in ips:
            assert result[ip].isp is None
            assert result[ip].country is None


class TestSubscriptionFetching:
    """Tests for subscription fetching and parsing concurrency."""

    @pytest.mark.asyncio
    async def test_subscription_fetching_concurrent(self):
        """fetch_and_parse correctly fetches and parses URI subscription content."""
        uris = [
            "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@server1.com:8388#Node1",
            "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@server2.com:8388#Node2",
            "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@server3.com:8388#Node3",
        ]
        content = base64.b64encode("\n".join(uris).encode()).decode()

        with aioresponses() as m:
            m.get("https://example.com/sub", body=content)
            nodes = await fetch_and_parse("https://example.com/sub")

        assert len(nodes) == 3
        for n in nodes:
            assert n.proxy_type == ProxyType.SS

    @pytest.mark.asyncio
    async def test_multiple_subscriptions_sequential_isolation(self, make_node):
        """Multiple subscriptions don't share state across calls."""
        sub1_nodes = [make_node(name=f"s1-n{i}", server=f"s1-{i}.com") for i in range(3)]
        sub2_nodes = [make_node(name=f"s2-n{i}", server=f"s2-{i}.com") for i in range(3)]

        fetch_calls = []

        async def mock_fetch(url, timeout=30):
            fetch_calls.append(url)
            if "sub1" in url:
                return sub1_nodes
            return sub2_nodes

        async def mock_resolve(nodes, dns_servers=None):
            for n in nodes:
                n.entry_ip = f"10.0.0.{hash(n.server) % 256}"

        async def mock_test(nodes, sp, bs, to):
            for n in nodes:
                n.test_success = True
                n.exit_ip = f"20.0.0.{hash(n.server) % 256}"

        async def mock_isps(ips):
            return {ip: IpInfo(isp="TestISP", country="US") for ip in ips}

        with (
            patch("src.main.fetch_and_parse", side_effect=mock_fetch),
            patch("src.main.resolve_entry_ips", side_effect=mock_resolve),
            patch("src.main.test_exit_ips", side_effect=mock_test),
            patch("src.main.lookup_isps", side_effect=mock_isps),
            patch("src.main.upload_to_gist") as mock_gist,
        ):
            await process_subscription("sub1", "https://sub1.com", "./sb", 10, 15, "token")
            await process_subscription("sub2", "https://sub2.com", "./sb", 10, 15, "token")

        assert len(fetch_calls) == 2
        assert "sub1" in fetch_calls[0]
        assert "sub2" in fetch_calls[1]
        assert mock_gist.call_count == 2


# ======================================================================
# Part 3: End-to-end pipeline tests
# ======================================================================


class TestDeduplication:
    """Unit tests for the deduplicate() pure function."""

    def test_deduplicate_correctness(self, make_node):
        """Removes duplicates by (server, entry_ip, exit_ip); keeps failed nodes."""
        # 3 successful nodes with same dedup key
        dup_nodes = []
        for i in range(3):
            n = make_node(name=f"dup{i}", server="server1.com")
            n.test_success = True
            n.entry_ip = "1.1.1.1"
            n.exit_ip = "2.2.2.2"
            dup_nodes.append(n)

        # 2 successful nodes with different dedup key
        unique_nodes = []
        for i in range(2):
            n = make_node(name=f"uniq{i}", server=f"server{i+2}.com")
            n.test_success = True
            n.entry_ip = f"3.3.3.{i}"
            n.exit_ip = f"4.4.4.{i}"
            unique_nodes.append(n)

        # 1 failed node (should always be kept)
        failed = make_node(name="failed", server="server1.com")
        failed.test_success = False

        all_nodes = dup_nodes + unique_nodes + [failed]
        result = deduplicate(all_nodes)

        # 1 from dup group + 2 unique + 1 failed = 4
        assert len(result) == 4
        names = [n.name for n in result]
        assert "dup0" in names  # First of the dup group kept
        assert "uniq0" in names
        assert "uniq1" in names
        assert "failed" in names


class TestEndToEndPipeline:
    """Integration tests for the full process_subscription pipeline."""

    @pytest.mark.asyncio
    async def test_e2e_pipeline_full(self, make_node):
        """Full pipeline: parse → DNS → test → dedup → ISP → rename → upload."""
        nodes = [make_node(name=f"n{i}", server=f"s{i}.com") for i in range(4)]

        async def mock_fetch(url, timeout=30):
            return nodes

        async def mock_resolve(ns, dns_servers=None):
            for n in ns:
                n.entry_ip = f"10.0.0.{int(n.name[1:])}"

        async def mock_test(ns, sp, bs, to):
            for n in ns:
                n.test_success = True
                n.exit_ip = f"20.0.0.{int(n.name[1:])}"
                n.exit_isp = f"ExitISP-{n.name}"
                n.exit_country = "US"

        async def mock_isps(ips):
            return {ip: IpInfo(isp="EntryISP", country="China") for ip in ips}

        captured_content = {}

        def mock_upload(token, content, sub_name):
            captured_content[sub_name] = content
            return "https://gist.github.com/test"

        with (
            patch("src.main.fetch_and_parse", side_effect=mock_fetch),
            patch("src.main.resolve_entry_ips", side_effect=mock_resolve),
            patch("src.main.test_exit_ips", side_effect=mock_test),
            patch("src.main.lookup_isps", side_effect=mock_isps),
            patch("src.main.upload_to_gist", side_effect=mock_upload),
        ):
            await process_subscription("test-sub", "https://example.com/sub", "./sb", 10, 15, "token")

        # Verify gist was uploaded
        assert "test-sub" in captured_content
        # Verify the content is valid base64
        decoded = base64.b64decode(captured_content["test-sub"]).decode()
        lines = [l for l in decoded.splitlines() if l.strip()]
        assert len(lines) == 4  # All 4 nodes

    @pytest.mark.asyncio
    async def test_e2e_pipeline_empty_subscription(self):
        """Empty subscription → early exit, no further pipeline calls."""
        async def mock_fetch(url, timeout=30):
            return []

        with (
            patch("src.main.fetch_and_parse", side_effect=mock_fetch),
            patch("src.main.resolve_entry_ips") as mock_resolve,
            patch("src.main.test_exit_ips") as mock_test,
            patch("src.main.upload_to_gist") as mock_gist,
        ):
            await process_subscription("empty", "https://empty.com", "./sb", 10, 15, "token")

        mock_resolve.assert_not_called()
        mock_test.assert_not_called()
        mock_gist.assert_not_called()

    @pytest.mark.asyncio
    async def test_e2e_pipeline_all_tests_fail(self, make_node):
        """All node tests fail → pipeline still completes, uploads results."""
        nodes = [make_node(name=f"n{i}", server=f"s{i}.com") for i in range(3)]

        async def mock_fetch(url, timeout=30):
            return nodes

        async def mock_resolve(ns, dns_servers=None):
            for n in ns:
                n.entry_ip = f"10.0.0.{int(n.name[1:])}"

        async def mock_test(ns, sp, bs, to):
            # All tests fail — test_success stays False
            pass

        async def mock_isps(ips):
            return {ip: IpInfo(isp="EntryISP", country="US") for ip in ips}

        with (
            patch("src.main.fetch_and_parse", side_effect=mock_fetch),
            patch("src.main.resolve_entry_ips", side_effect=mock_resolve),
            patch("src.main.test_exit_ips", side_effect=mock_test),
            patch("src.main.lookup_isps", side_effect=mock_isps),
            patch("src.main.upload_to_gist") as mock_gist,
        ):
            await process_subscription("fail-sub", "https://fail.com", "./sb", 10, 15, "token")

        # All nodes failed
        for n in nodes:
            assert n.test_success is False

        # Gist still uploaded
        mock_gist.assert_called_once()
        # Nodes with entry_isp should be renamed with "EntryISP - original_name" format
        for n in nodes:
            assert n.entry_isp == "EntryISP"
