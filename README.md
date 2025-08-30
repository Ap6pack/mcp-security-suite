# MCP Security Tools Suite

A collection of Model Context Protocol (MCP) servers for ethical security testing, attack surface management, and penetration testing workflows.

## 🚀 New to MCP Security Suite?

**[Start with our Getting Started Guide →](GETTING_STARTED.md)**

It will get you up and running in under 5 minutes!

**Using a different MCP client?** Check out our [Integration Guide](MCP_INTEGRATION_GUIDE.md) for examples with web apps, CI/CD, REST APIs, and more!

## 🔒 Important Security & Legal Notice

**These tools are for authorized security testing only!**

- Always obtain explicit written permission before testing any systems
- Follow responsible disclosure practices
- Comply with all applicable laws and regulations
- Never use these tools for malicious purposes
- Respect rate limits and avoid causing service disruptions

## 📦 Components

### 1. **Security Tools Server** (`security_server.py`)
Core security assessment capabilities:
- SSL certificate validation
- CVE database queries
- Security header analysis
- DNS lookups and WHOIS
- Breach database checking

### 2. **ASM Server** (`asm_server.py`)
Attack Surface Management features:
- Subdomain enumeration
- Technology identification
- Attack surface mapping
- Exposed service discovery
- API endpoint enumeration

### 3. **Threat Intelligence Server** (Coming Soon)
- IP reputation checking
- IOC analysis
- Threat feed integration
- MITRE ATT&CK mapping

## 🚀 Installation

### Quick Start

```bash
# Clone the repository
git clone https://github.com/Ap6pack/mcp-security-suite.git
cd mcp-security-suite

# Install dependencies
pip install -r requirements.txt

# Run the setup wizard
python setup_wizard.py
```

The setup wizard will guide you through:
- API key configuration
- Claude Desktop integration
- Server verification

### Manual Installation

#### Prerequisites

```bash
# Python 3.8+ required
python --version

# Create virtual environment (optional but recommended)
python -m venv mcp-security-env
source mcp-security-env/bin/activate  # On Windows: mcp-security-env\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

#### API Keys Setup

Create a `.env` file in your project directory:

```env
# API Keys for enhanced functionality (all optional)
HIBP_API_KEY=your_have_i_been_pwned_key
SHODAN_API_KEY=your_shodan_api_key
VT_API_KEY=your_virustotal_api_key
CENSYS_API_ID=your_censys_id
CENSYS_API_SECRET=your_censys_secret
```

Get your API keys from:
- **HIBP**: https://haveibeenpwned.com/API/Key
- **Shodan**: https://account.shodan.io/
- **VirusTotal**: https://www.virustotal.com/gui/my-apikey
- **Censys**: https://censys.io/account/api

## 🔧 Configuration

### For Claude Desktop

1. Locate your Claude configuration file:
   - macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
   - Windows: `%APPDATA%\Claude\claude_desktop_config.json`
   - Linux: `~/.config/Claude/claude_desktop_config.json`

2. Add the MCP servers:

```json
{
  "mcpServers": {
    "security-tools": {
      "command": "python",
      "args": ["/absolute/path/to/security_server.py"],
      "env": {
        "HIBP_API_KEY": "your-api-key"
      }
    },
    "asm-tools": {
      "command": "python",
      "args": ["/absolute/path/to/asm_server.py"]
    }
  }
}
```

3. Restart Claude Desktop

### For Custom Clients

```python
import subprocess
import json

# Start MCP server
process = subprocess.Popen(
    ["python", "security_server.py"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE
)

# Send requests via JSON-RPC
request = {
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
        "name": "check_ssl_certificate",
        "arguments": {"domain": "example.com"}
    },
    "id": 1
}

process.stdin.write(json.dumps(request).encode())
process.stdin.flush()
```

## 📚 Usage Examples

### Basic SSL Certificate Check

```python
# Via MCP tool call
result = await check_ssl_certificate("github.com")
print(f"Certificate expires: {result['not_after']}")
```

### Subdomain Enumeration

```python
# Passive reconnaissance only
subdomains = await discover_subdomains(
    domain="example.com",
    passive_only=True,
    sources=["crtsh", "wayback"]
)
```

### Attack Surface Mapping

```python
# Comprehensive asset discovery
surface = await map_attack_surface(
    domain="example.com",
    include_subdomains=True,
    check_ports=False,  # Requires explicit permission
    identify_tech=True
)
```

### Security Header Analysis

```python
# Check security posture
headers = await analyze_security_headers("https://example.com")
print(f"Security score: {headers['percentage']}%")
```

## 🛡️ Best Practices

### 1. **Authorization & Scope**
- Always define scope clearly before testing
- Use scope configuration files
- Implement IP/domain allowlists
- Log all activities for audit trails

### 2. **Rate Limiting**
- Respect target rate limits
- Implement exponential backoff
- Use async operations efficiently
- Cache results when appropriate

### 3. **Data Handling**
- Encrypt sensitive findings
- Follow data retention policies
- Redact PII in reports
- Use secure communication channels

### 4. **Operational Security**
- Use VPN/proxy when appropriate
- Rotate API keys regularly
- Monitor for abuse patterns
- Implement kill switches

## 🔍 Advanced Configuration

### Custom Wordlists

```python
# Add custom wordlists for enumeration
CUSTOM_SUBDOMAINS = [
    "api", "dev", "staging", "test", "admin",
    "portal", "secure", "vpn", "remote", "cloud"
]

CUSTOM_API_PATHS = [
    "/api/v1", "/api/v2", "/graphql", "/rest",
    "/oauth", "/auth", "/token", "/refresh"
]
```

### Proxy Configuration

```python
# Route through proxy for testing
PROXY_CONFIG = {
    "http": "http://proxy.example.com:8080",
    "https": "https://proxy.example.com:8080"
}
```

### Custom User Agents

```python
# Identify your scanner properly
USER_AGENTS = {
    "default": "MCP-Security-Scanner/1.0 (Authorized Testing)",
    "mobile": "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)",
    "bot": "SecurityBot/1.0 (+https://example.com/bot-info)"
}
```

## 🐛 Debugging

### Enable Debug Logging

```python
import logging

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('mcp_security.log'),
        logging.StreamHandler()
    ]
)
```

### Common Issues

1. **"Nothing happens when I run a server!"**
   - This is normal! MCP servers wait for connections from Claude
   - Run `python test_servers.py` to verify servers work
   - Use `python setup_wizard.py` to configure Claude Desktop

2. **"Claude doesn't see the tools"**
   - Make sure you restarted Claude Desktop after configuration
   - Check that the paths in claude_desktop_config.json are absolute paths
   - Verify Python is in your system PATH

3. **"Module not found" errors**
   - Run `pip install -r requirements.txt`
   - Make sure you're using Python 3.8 or higher
   - If using a virtual environment, ensure it's activated

4. **Connection Timeouts**
   - Increase timeout values in the server configuration
   - Check network connectivity
   - Verify firewall rules aren't blocking connections

5. **Rate Limiting**
   - Add API keys for higher limits
   - Implement backoff strategies
   - Cache results when possible

6. **SSL/Certificate Errors**
   - Update certificates
   - Configure SSL verification settings
   - Check proxy settings if behind corporate firewall

## 📊 Output Formats

### JSON Export

```python
import json

# Export results
with open('scan_results.json', 'w') as f:
    json.dump(attack_surface, f, indent=2)
```

### CSV Reports

```python
import csv

# Generate CSV report
with open('vulnerabilities.csv', 'w', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=['host', 'port', 'service', 'severity'])
    writer.writeheader()
    writer.writerows(findings)
```

### HTML Reports

```python
# Generate HTML report with findings
html_template = """
<!DOCTYPE html>
<html>
<head><title>Security Assessment Report</title></head>
<body>
    <h1>Attack Surface Report</h1>
    <h2>Executive Summary</h2>
    <p>Risk Level: {risk_level}</p>
    <h2>Findings</h2>
    <ul>
        {findings}
    </ul>
</body>
</html>
"""
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Follow secure coding practices
4. Add tests for new features
5. Submit a pull request

## 📜 License & Disclaimer

This software is provided for educational and authorized testing purposes only. The authors assume no liability for misuse or damage caused by this software. Always ensure you have explicit permission before testing any systems.

## 🔗 Resources

- [MCP Documentation](https://modelcontextprotocol.io)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [Responsible Disclosure Guidelines](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerability_Disclosure_Cheat_Sheet.html)

## 💡 Future Enhancements

- [ ] Integration with Metasploit modules
- [ ] Automated vulnerability scanning
- [ ] Cloud security posture management
- [ ] Container security assessment
- [ ] GraphQL security testing
- [ ] WebSocket security analysis
- [ ] Mobile API testing support
- [ ] Compliance reporting (PCI, HIPAA, SOC2)
- [ ] Integration with SIEM platforms
- [ ] Threat modeling automation

## ⚠️ Ethical Usage Guidelines

Remember the security professional's creed:
- **Do no harm**
- **Respect privacy**
- **Follow the law**
- **Get permission**
- **Report responsibly**
- **Protect findings**
- **Educate others**

---

*Built with respect for security and privacy by the cybersecurity community*
