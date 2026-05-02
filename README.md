# Automated Cloud OSINT & Threat Intel Framework

A passive, fully automated Threat Intelligence and Open Source Intelligence (OSINT) framework designed for continuous 24/7 cloud deployment. 

## Features
- **Passive Subdomain Discovery:** Integrates with `crt.sh` to track SSL certificates and discover unreleased endpoints.
- **Automated Threat Intelligence:** Cross-references discovered assets with VirusTotal, AlienVault OTX, and URLScan.io APIs.
- **Historical Analysis:** Queries the Wayback Machine CDX API to find legacy IP exposures.
- **Local Simulation Environment:** Includes a Mock Server with WAF (Rate Limiting, Honeypots) and SSRF vulnerabilities for safe, legal penetration testing practice.
- **Advanced API Interaction Console:** A Python-based terminal client supporting SOCKS5 routing (Tor), experimental header injection, and raw JSON payload manipulation for interacting with highly restricted APIs.

## Architecture
This framework is built to run autonomously on a minimal Google Cloud Platform (GCP) Compute Engine instance using `systemd`. It features a resilient SQLite backend for data correlation and generates daily hypothesis reports on potential attack vectors without ever directly pinging the target infrastructure.

## Setup (Local Development)
1. Clone this repository.
2. Install dependencies: `pip install -r requirements.txt`
3. Configure your API keys (VirusTotal, SecurityTrails) in `config.yaml`.
4. Run the local mock server for testing: `python mock_target_server.py`
5. Test the offensive console: `python api_interaction_console.py --use-mock --model ProjectX --key REDACTED_API_KEY`

*Disclaimer: This project was built exclusively for defensive monitoring, threat intelligence gathering, and educational Red Teaming. All identifying information and credentials have been redacted.*
