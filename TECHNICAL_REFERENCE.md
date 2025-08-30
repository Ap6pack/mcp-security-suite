# 🛡️ MCP Security Suite - Technical Reference

> **New users: Start with [GETTING_STARTED.md](GETTING_STARTED.md) instead!**

This document provides technical details for advanced users and developers.

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

## 📋 Complete Configuration Reference

### Full Environment Variables
```env
# Core APIs
HIBP_API_KEY=your_hibp_key
SHODAN_API_KEY=your_shodan_key
VT_API_KEY=your_virustotal_key
CENSYS_API_ID=your_censys_id
CENSYS_API_SECRET=your_censys_secret

# Additional APIs (optional)
ABUSEIPDB_KEY=your_abuseipdb_key
ALIENVAULT_KEY=your_otx_key
GREYNOISE_KEY=your_greynoise_key

# Operation Configuration
AUTHORIZED_SCOPE=target1.com,target2.com,192.168.1.0/24
OPERATION_NAME=SecurityAssessment2024
LOG_LEVEL=INFO
RATE_LIMIT=10
TIMEOUT=30
```

### Complete Claude Desktop Configuration

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
