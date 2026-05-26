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
| **🤖 AI Security Analyst** | Feeds all collected recon data into an AI model (Google Gemini, DeepSeek, or local Ollama) to generate a prioritized attack surface report with exploitation recommendations. |

## 🤖 AI Security Analyst

The **AI Assistant** tab gives you an autonomous AI-powered analyst that reviews all recon findings collected by ReconMaster Pro and generates a structured security assessment.

### How It Works
1. Configure which modules to include (Technologies & CVEs, Endpoints, CORS, GraphQL, Cloud Assets, Secrets).
2. Select an AI provider in **Settings** — supports **Google Gemini**, **DeepSeek**, and **Ollama** (local).
3. Click **Analyze Attack Surface** — the AI agent receives your recon data and returns a prioritized report with:
   - Critical vulnerabilities and exploitation paths
   - Risk-ranked findings per module
   - Concrete command-line PoC examples
   - Remediation recommendations

### Privacy & OpSec
| Mode | Privacy |
|------|---------|
| **Local (Ollama)** | 🛡️ All data stays on your machine — recommended for confidential engagements |
| **Cloud (Gemini / DeepSeek)** | ⚠️ Findings are transmitted to the cloud API — use masking options |

Enable **Mask Secrets** and **Mask Domains** in Settings to anonymize sensitive values before transmission.

### Supported AI Providers
- **Google Gemini** — gemini-2.0-flash, gemini-1.5-pro (default)
- **DeepSeek** — deepseek-chat, deepseek-reasoner
- **Ollama (Local)** — llama3, mistral, codellama, and any locally hosted model

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
3. Select extension type **Java** and choose the shaded JAR: `target/reconmaster-pro-1.0.2-jar-with-dependencies.jar`

## Configuration
Go to the **ReconMaster Pro** tab and open **Settings**:

| Setting | Default | Description |
|---------|---------|-------------|
| Entropy threshold | 4.0 | Sensitivity limit for the secrets detection scanner |
| Active scanning | Off | Run active target endpoint discovery probes |
| Timeline window | 60 min | Time window for active changes analysis |
| Export format | JSON | Default report export format |
| AI Provider | Gemini | AI backend for the AI Analyst (`GOOGLE`, `DEEPSEEK`, `LOCAL`) |
| AI Model | gemini-1.5-flash | Model name sent to the AI provider |
| AI API Key | — | Your API key for the selected cloud provider |
| Mask Secrets | On | Anonymize detected secrets before sending to AI |
| Mask Domains | On | Replace real hostnames with placeholders before sending to AI |
| Local AI URL | http://localhost:11434/v1 | OpenAI-compatible endpoint for local inference (Ollama) |

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
