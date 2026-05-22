# ReconMaster Pro

> Automated reconnaissance workflows for Burp Suite Community Edition

## Features

| Module | Description |
|--------|-------------|
| **Smart Endpoint Discovery** | Extracts and deduplicates endpoints from JS/HTML/JSON, groups by pattern (`/api/{id}`), scores by exploit probability |
| **Attack Surface Timeline** | Tracks how the attack surface changes over time — alerts on new or removed endpoints |
| **Tech Stack Fingerprinting** | Detects frameworks, library versions, and cross-references an offline CVE database |
| **GraphQL Schema Extractor** | Auto-discovers GraphQL endpoints and runs introspection queries |
| **Secrets Scanner** | Shannon entropy + context-aware detection with severity scoring |
| **CORS Hunter** | Tests all discovered endpoints for CORS misconfigurations, generates PoC HTML |
| **Cloud Assets Aggregator** | Discovers S3/Azure/GCS buckets from JS/HTML/CSP headers, checks public exposure |
| **Report Generator** | Exports to JSON, CSV, Markdown, or standalone HTML |

## Installation

**Via BApp Store (recommended)**
1. Burp → Extender → BApp Store → search "ReconMaster Pro" → Install

**Manual**
1. Download `reconmaster-pro.jar` from [Releases](../../releases)
2. Burp → Extender → Extensions → Add → select JAR

## Usage

**Passive (automatic):** Browse your target — ReconMaster collects data in the background.

**Active (manual):** Right-click any request → ReconMaster → "Run Full Recon"

## Configuration

Settings → ReconMaster Pro:

| Setting | Default | Description |
|---------|---------|-------------|
| Entropy threshold | 4.0 | Sensitivity for secrets detection |
| Active scanning | Off | Enable active endpoint probing |
| Timeline window | 60 min | How far back to show timeline |
| Export format | JSON | Default report format |

## Performance

Tested on 1000 endpoints: ~80MB RAM, <5% CPU overhead.

## Tech Stack

Java + Burp Extender API 2.3 · Gson 2.10.1 · SQLite (timeline storage) · offline CVE database (no external API calls)

## License

MIT — see [LICENSE](LICENSE)

## Author

Przemysław Majdak · [baluarte.pl](https://baluarte.pl) · majdak.przemyslaw@gmail.com
