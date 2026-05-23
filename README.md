# ReconMaster Pro

> Automated reconnaissance workflows for Burp Suite Community Edition (Powered by the modern Montoya API)

ReconMaster Pro is an offline, high-performance target reconnaissance extension for Burp Suite. It passively collects and analyzes traffic to map your target's attack surface without triggering external lookups or violating privacy constraints.

## Features

| Module | Description |
|--------|-------------|
| **Smart Endpoint Discovery** | Passively extracts and clusters API endpoints (e.g. mapping `/api/users/{id}`), scoring them by security risk. |
| **Attack Surface Timeline** | Tracks target changes over time in an embedded SQLite database, alerting you on new or removed endpoints. |
| **Tech Stack Fingerprinting** | Offline framework detection with library version matching against an embedded CVE database. |
| **GraphQL Schema Extractor** | Auto-discovers GraphQL endpoints and builds schema visualization trees. |
| **Secrets Scanner** | Shannon entropy calculations paired with strict regex context heuristics. |
| **CORS Hunter** | Passive auditing for wildcard, null origin, and credentials misconfigurations with PoC generator. |
| **Cloud Assets Aggregator** | Detects public S3, Azure Blob, and Google Cloud Storage buckets in JS/HTML/CSP headers. |
| **Report Generator** | Offloads report compilation to a background thread to generate HTML, JSON, CSV, or Markdown. |

## Requirements
* Java 17+ (JDK runtime)
* Burp Suite 2023.1.1+ (Minimum version supporting the Montoya API)

## Installation

### Via BApp Store (Recommended)
1. In Burp Suite: **Extensions** → **BApp Store**
2. Search for **"ReconMaster Pro"**
3. Click **Install**

### Manual Installation
1. Compile the JAR using Maven or download the release version:
   ```bash
   mvn clean package
   ```
2. In Burp Suite: **Extensions** → **Installed** → **Add**
3. Select extension type **Java** and choose the shaded JAR: `target/reconmaster-pro-1.0.0-jar-with-dependencies.jar`

## Configuration
Go to the **ReconMaster Pro** tab and open **Settings**:

| Setting | Default | Description |
|---------|---------|-------------|
| Entropy threshold | 4.0 | Sensitivity limit for the secrets detection scanner |
| Active scanning | Off | Run active target endpoint discovery probes |
| Timeline window | 60 min | Time window for active changes analysis |
| Export format | JSON | Default report export format |

## Tech Stack
* **Burp Suite Montoya API** (`2026.4`)
* **Java 17** (LTS Features)
* **Gson** (`2.10.1`) — JSON parsing
* **SQLite JDBC** (`3.45.0.0`) — Asynchronous local database storage
* **GitHub Actions** — CI/CD Maven builder

## Author
Przemysław Majdak (przemyslvw) · [baluarte.pl](https://baluarte.pl) · majdak.przemyslaw@gmail.com

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
