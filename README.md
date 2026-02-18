# AutoRelay

Automated proxy subscription pipeline that fetches, tests, deduplicates, and republishes proxy nodes with informative ISP-based naming.

## What It Does

AutoRelay processes proxy subscription links through a multi-stage pipeline:

1. **Fetch & Parse** -- Downloads subscriptions and auto-detects the format (Clash YAML, sing-box JSON, or base64/URI list)
2. **DNS Resolve** -- Resolves entry IPs using Chinese DNS servers (114.114.114.114, 223.5.5.5)
3. **Connectivity Test** -- Spins up [sing-box](https://github.com/SagerNet/sing-box) instances and tests each node's exit IP and ISP via `ip-api.com`
4. **Deduplicate** -- Removes duplicate nodes based on (server, entry IP, exit IP)
5. **ISP Lookup** -- Queries entry IP ISP and country info via ip-api.com batch API
6. **Rename** -- Generates descriptive names like `电信 - 美国 AWS` or `阿里云 - 日本 NTT`
7. **Publish** -- Encodes results as base64 URI subscription and uploads to a private GitHub Gist

## Supported Protocols

| Protocol | URI | Clash YAML | sing-box JSON |
|---|---|---|---|
| Shadowsocks | `ss://` | `ss` | `shadowsocks` |
| VMess | `vmess://` | `vmess` | `vmess` |
| VLESS | `vless://` | `vless` | `vless` |
| Trojan | `trojan://` | `trojan` | `trojan` |
| Hysteria2 | `hysteria2://` / `hy2://` | `hysteria2` | `hysteria2` |
| Hysteria | `hysteria://` | `hysteria` | `hysteria` |
| TUIC | `tuic://` | `tuic` | `tuic` |

## Setup

### Prerequisites

- Python 3.11+
- [sing-box](https://github.com/SagerNet/sing-box) binary
- A GitHub personal access token with Gist permissions

### Installation

```bash
pip install -r requirements.txt
```

Dependencies: `pyyaml`, `aiohttp`, `dnspython`, `requests`

### Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `SUB_URLS` | Yes | -- | Subscription URLs, one per line. Supports `name\|url` format for aliases |
| `GIST_TOKEN` | No | -- | GitHub token for Gist upload. If unset, output goes to stdout |
| `SINGBOX_PATH` | No | `./sing-box` | Path to the sing-box binary |
| `BATCH_SIZE` | No | `10` | Number of nodes to test concurrently per batch |
| `TEST_TIMEOUT` | No | `15` | Timeout in seconds for each node test |
| `FILTER_NON_CN_FAILED` | No | `true` | Drop failed nodes whose entry point is outside China |

### SUB_URLS Format

```
my-sub|https://example.com/subscription1
https://example.com/subscription2
vpn|https://example.com/subscription3
```

Each subscription is processed independently and uploaded to its own private Gist.

## Usage

### Run Locally

```bash
export SUB_URLS="my-sub|https://example.com/sub"
export GIST_TOKEN="ghp_xxxx"
export SINGBOX_PATH="./sing-box"

python -m src.main
```

### GitHub Actions (Automated)

The included workflow (`.github/workflows/relay.yml`) runs hourly. Configure these repository secrets:

- `SUB_URLS` -- Your subscription URLs
- `GIST_TOKEN` -- GitHub personal access token

The workflow automatically downloads sing-box, installs dependencies, and runs the pipeline.

## Project Structure

```
src/
  main.py              # Orchestrator: subscription loop + pipeline stages
  models.py            # Node dataclass and ProxyType enum
  parsers/
    dispatcher.py      # Auto-detects format and dispatches to parser
    uri.py             # Parses ss/vmess/vless/trojan/hy2/hysteria/tuic URIs
    clash.py           # Parses Clash YAML proxy configs
    singbox.py         # Parses sing-box JSON outbound configs
  dns_resolver.py      # Resolves domains to entry IPs via Chinese DNS
  tester.py            # Launches sing-box instances to test exit IP/ISP
  singbox_config.py    # Generates minimal sing-box configs for testing
  ip_lookup.py         # Batch ISP/country lookup via ip-api.com
  renamer.py           # Renames nodes with ISP and country labels
  uri_output.py        # Converts nodes back to URI format + base64 encoding
  clash_output.py      # Generates Clash Meta YAML output
  gist_uploader.py     # Creates/updates private GitHub Gists
```

## Node Naming Convention

Nodes are renamed based on their entry and exit network path:

- **Relay nodes**: `[Entry Country] Entry ISP - [Exit Country] Exit ISP`
  - Example: `电信 - 美国 AWS`, `阿里云 - 日本 NTT`
- **Direct nodes** (entry and exit in same /24 subnet): `[Country] ISP`
  - Example: `美国 Cloudflare`
- Chinese entry/exit nodes omit the country label for brevity
- Duplicate names get a `#2`, `#3` suffix

## License

This project is for personal use.
