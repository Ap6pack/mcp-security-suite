# 🛡️ Complete Cybersecurity MCP Suite Integration Guide

## Overview

You now have a comprehensive suite of MCP servers for cybersecurity operations:

1. **Security Tools Server** - Core security assessment capabilities
2. **ASM Server** - Attack Surface Management and reconnaissance
3. **Penetration Testing Server** - Vulnerability assessment and exploitation
4. **Red Team Operations Server** - Advanced adversary simulation

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     MCP Client (Claude/Custom)              │
└─────────────┬───────────────────────────────────┬───────────┘
              │                                   │
    ┌─────────▼─────────┐               ┌────────▼──────────┐
    │  Security Tools   │               │    ASM Server     │
    │   - SSL Check     │               │  - Subdomain Enum │
    │   - CVE Query     │               │  - Tech Discovery │
    │   - DNS/WHOIS     │               │  - Attack Surface │
    └───────────────────┘               └───────────────────┘
              │                                   │
    ┌─────────▼─────────┐               ┌────────▼──────────┐
    │   Pentest Server  │               │  Red Team Server  │
    │  - Vuln Scanning  │               │  - Phishing Sim   │
    │  - Fuzzing        │               │  - C2 Infrastructure│
    │  - Exploitation   │               │  - MITRE ATT&CK   │
    └───────────────────┘               └───────────────────┘
```

## 🚀 Quick Start Setup

### 1. Install All Dependencies

```bash
# Create virtual environment
python -m venv security-mcp-env
source security-mcp-env/bin/activate  # Windows: security-mcp-env\Scripts\activate

# Install core dependencies
pip install mcp aiohttp dnspython python-whois

# Install optional dependencies for advanced features
pip install shodan censys python-nmap paramiko cryptography
pip install beautifulsoup4 lxml requests pyyaml

# For reporting
pip install jinja2 matplotlib pandas
```

### 2. Environment Configuration

Create `.env` file with all API keys:

```env
# Core APIs
HIBP_API_KEY=your_hibp_key
SHODAN_API_KEY=your_shodan_key
VT_API_KEY=your_virustotal_key
CENSYS_API_ID=your_censys_id
CENSYS_API_SECRET=your_censys_secret

# Additional APIs
ABUSEIPDB_KEY=your_abuseipdb_key
ALIENVAULT_KEY=your_otx_key
GREYNOISE_KEY=your_greynoise_key

# Operation Config
AUTHORIZED_SCOPE=target1.com,target2.com,192.168.1.0/24
OPERATION_NAME=SecurityAssessment2024
LOG_LEVEL=INFO
```

### 3. Complete Claude Desktop Configuration

```json
{
  "mcpServers": {
    "security-tools": {
      "command": "python",
      "args": ["/path/to/security_server.py"],
      "env": {
        "HIBP_API_KEY": "${HIBP_API_KEY}",
        "VT_API_KEY": "${VT_API_KEY}"
      }
    },
    "asm-tools": {
      "command": "python",
      "args": ["/path/to/asm_server.py"],
      "env": {
        "SHODAN_API_KEY": "${SHODAN_API_KEY}",
        "CENSYS_API_ID": "${CENSYS_API_ID}",
        "CENSYS_API_SECRET": "${CENSYS_API_SECRET}"
      }
    },
    "pentest-tools": {
      "command": "python",
      "args": ["/path/to/pentest_server.py"],
      "env": {
        "AUTHORIZED_SCOPE": "${AUTHORIZED_SCOPE}",
        "ENABLE_EXPLOITS": "false"
      }
    },
    "redteam-ops": {
      "command": "python",
      "args": ["/path/to/redteam_server.py"],
      "env": {
        "OPERATION_NAME": "${OPERATION_NAME}",
        "AUTHORIZED_TARGETS": "${AUTHORIZED_SCOPE}",
        "ENABLE_PERSISTENCE": "false",
        "ENABLE_LATERAL": "false"
      }
    }
  }
}