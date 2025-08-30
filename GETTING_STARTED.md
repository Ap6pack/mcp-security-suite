# 🚀 Getting Started with MCP Security Suite

Welcome! This guide will help you get up and running with the MCP Security Suite in under 5 minutes.

## What is this?

The MCP Security Suite is a collection of security tools that work with Claude Desktop (or other MCP clients) to provide:
- 🛡️ **Security assessments** - SSL checks, vulnerability scanning
- 🔍 **Reconnaissance** - Subdomain discovery, technology identification  
- 🔓 **Penetration testing** - Authorized security testing
- 🎯 **Red team operations** - Adversary simulation

## Quick Start (3 Steps)

### Step 1: Install Dependencies

```bash
# Clone the repository
git clone https://github.com/Ap6pack/mcp-security-suite.git
cd mcp-security-suite

# Install required packages
pip install -r requirements.txt
```

### Step 2: Run Setup Wizard

```bash
python setup_wizard.py
```

The wizard will:
- ✅ Help you configure API keys (optional)
- ✅ Set up Claude Desktop integration
- ✅ Test that all servers work correctly

### Step 3: Start Using with Claude

After setup, restart Claude Desktop and you'll see the security tools available!

## Understanding MCP Servers

**What happens when you run a server directly?**

If you run `python security_server.py`, you'll see:
```
============================================================
🛡️  MCP Security Tools Server
============================================================

This is an MCP (Model Context Protocol) server that provides
security assessment tools for use with Claude or other MCP clients.

⚠️  This server is waiting for MCP client connections...
It won't show any output when running correctly.
```

This is normal! MCP servers wait for connections from Claude Desktop. They don't have a user interface.

## Available Servers

| Server | Purpose | Example Tools |
|--------|---------|---------------|
| `security_server.py` | Core security tools | SSL checks, CVE queries, DNS lookups |
| `asm_server.py` | Attack surface management | Subdomain discovery, tech identification |
| `pentest_server.py` | Penetration testing | Vulnerability scanning, fuzzing |
| `redteam_server.py` | Red team operations | Phishing simulation, MITRE ATT&CK |

## Common Questions

### "Nothing happens when I run a server!"

That's correct! MCP servers are meant to be used through Claude Desktop, not run directly. Use the setup wizard to configure Claude Desktop to connect to these servers.

### "How do I know if it's working?"

Run `python test_servers.py` - it will verify all servers can start properly.

### "Do I need API keys?"

No! API keys are optional but enable additional features:
- **HIBP API** - Check breach databases
- **Shodan API** - Enhanced reconnaissance
- **VirusTotal API** - Malware analysis

### "What's the difference between README and this guide?"

- **This guide** - Quick start for beginners
- **README.md** - Detailed documentation
- **SECURITY.md** - Security policies and guidelines

## Next Steps

1. **Try it out** - Ask Claude to "check SSL certificate for github.com"
2. **Explore tools** - Ask Claude "what security tools are available?"
3. **Read more** - Check README.md for advanced usage

## Need Help?

- **Setup issues?** Run `python setup_wizard.py` again
- **Server not working?** Run `python test_servers.py` 
- **Still stuck?** Check the troubleshooting section in README.md

---

**Remember**: Always get authorization before testing any systems! 🔒
