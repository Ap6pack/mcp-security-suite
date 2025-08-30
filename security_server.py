#!/usr/bin/env python3
"""
MCP Security Server - Ethical Security Tools Integration
This server provides legitimate security assessment capabilities
"""

import json
import asyncio
import logging
from typing import Any, Dict, List, Optional
from datetime import datetime, timedelta
import aiohttp
import ssl
import socket
from dataclasses import dataclass

# MCP Server imports
from mcp.server import Server
from mcp.server.stdio import stdio_server
import mcp.types as types

logger = logging.getLogger(__name__)

@dataclass
class SecurityConfig:
    """Configuration for security tools"""
    rate_limit: int = 10  # requests per minute
    timeout: int = 30  # seconds
    verify_ssl: bool = True
    allowed_ports: List[int] = None
    
    def __post_init__(self):
        if self.allowed_ports is None:
            # Only common service ports for legitimate scanning
            self.allowed_ports = [80, 443, 22, 21, 25, 110, 143]

class SecurityToolsServer:
    """MCP server for security assessment tools"""
    
    def __init__(self, config: SecurityConfig = None):
        self.config = config or SecurityConfig()
        self.server = Server("security-tools")
        self.setup_tools()
        
    def setup_tools(self):
        """Register available security tools"""
        
        # Register the list_tools handler
        @self.server.list_tools()
        async def handle_list_tools() -> List[types.Tool]:
            """Return the list of available tools"""
            return [
                types.Tool(
                    name="check_ssl_certificate",
                    description="Check SSL certificate information for a domain",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "domain": {
                                "type": "string",
                                "description": "The domain to check (e.g., example.com)"
                            }
                        },
                        "required": ["domain"]
                    }
                ),
                types.Tool(
                    name="query_cve_database",
                    description="Query CVE database for vulnerability information",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "cve_id": {
                                "type": "string",
                                "description": "Specific CVE ID to look up"
                            },
                            "keyword": {
                                "type": "string",
                                "description": "Search keyword for CVEs"
                            },
                            "last_n_days": {
                                "type": "integer",
                                "description": "Get CVEs from last N days",
                                "default": 7
                            }
                        }
                    }
                ),
                types.Tool(
                    name="analyze_security_headers",
                    description="Analyze security headers for a given URL",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "url": {
                                "type": "string",
                                "description": "The URL to analyze"
                            }
                        },
                        "required": ["url"]
                    }
                ),
                types.Tool(
                    name="dns_lookup",
                    description="Perform DNS lookup for a domain",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "domain": {
                                "type": "string",
                                "description": "The domain to lookup"
                            },
                            "record_type": {
                                "type": "string",
                                "description": "DNS record type (A, AAAA, MX, TXT, NS, CNAME)",
                                "default": "A"
                            }
                        },
                        "required": ["domain"]
                    }
                ),
                types.Tool(
                    name="whois_lookup",
                    description="Perform WHOIS lookup for a domain",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "domain": {
                                "type": "string",
                                "description": "The domain to lookup"
                            }
                        },
                        "required": ["domain"]
                    }
                ),
                types.Tool(
                    name="check_breach_database",
                    description="Check if email or domain appears in breach databases (via HIBP API)",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "email": {
                                "type": "string",
                                "description": "Email address to check"
                            },
                            "domain": {
                                "type": "string",
                                "description": "Domain to check for breaches"
                            }
                        }
                    }
                )
            ]
        
        # Register the call_tool handler
        @self.server.call_tool()
        async def handle_call_tool(name: str, arguments: dict) -> List[types.TextContent]:
            """Handle tool calls"""
            
            if name == "check_ssl_certificate":
                result = await self._check_ssl_certificate(arguments.get("domain", ""))
            elif name == "query_cve_database":
                result = await self._query_cve_database(
                    arguments.get("cve_id"),
                    arguments.get("keyword"),
                    arguments.get("last_n_days", 7)
                )
            elif name == "analyze_security_headers":
                result = await self._analyze_security_headers(arguments.get("url", ""))
            elif name == "dns_lookup":
                result = await self._dns_lookup(
                    arguments.get("domain", ""),
                    arguments.get("record_type", "A")
                )
            elif name == "whois_lookup":
                result = await self._whois_lookup(arguments.get("domain", ""))
            elif name == "check_breach_database":
                result = await self._check_breach_database(
                    arguments.get("email"),
                    arguments.get("domain")
                )
            else:
                result = {"error": f"Unknown tool: {name}"}
            
            return [types.TextContent(type="text", text=json.dumps(result, indent=2))]
        
    async def _check_ssl_certificate(self, domain: str) -> Dict[str, Any]:
        """Check SSL certificate information for a domain"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=self.config.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
            return {
                "domain": domain,
                "issuer": dict(x[0] for x in cert['issuer']),
                "subject": dict(x[0] for x in cert['subject']),
                "not_before": cert['notBefore'],
                "not_after": cert['notAfter'],
                "san": cert.get('subjectAltName', []),
                "version": cert['version']
            }
        except Exception as e:
            return {"error": str(e), "domain": domain}
    
    async def _query_cve_database(self, cve_id: str = None, keyword: str = None, last_n_days: int = 7) -> Dict[str, Any]:
        """Query CVE database for vulnerability information"""
        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        
        params = {}
        if cve_id:
            params['cveId'] = cve_id
        if keyword:
            params['keywordSearch'] = keyword
            
        # Add date range for recent CVEs
        if last_n_days and not cve_id:
            end_date = datetime.now()
            start_date = end_date - timedelta(days=last_n_days)
            params['lastModStartDate'] = start_date.isoformat()
            params['lastModEndDate'] = end_date.isoformat()
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(base_url, params=params, timeout=self.config.timeout) as response:
                    data = await response.json()
                    return self._parse_cve_response(data)
        except Exception as e:
            return {"error": str(e)}
    
    async def _analyze_security_headers(self, url: str) -> Dict[str, Any]:
        """Analyze security headers for a given URL"""
        security_headers = {
            'Strict-Transport-Security': {'required': True, 'description': 'Enforces HTTPS'},
            'X-Content-Type-Options': {'required': True, 'description': 'Prevents MIME sniffing'},
            'X-Frame-Options': {'required': True, 'description': 'Prevents clickjacking'},
            'Content-Security-Policy': {'required': True, 'description': 'Controls resource loading'},
            'X-XSS-Protection': {'required': False, 'description': 'Legacy XSS protection'},
            'Referrer-Policy': {'required': True, 'description': 'Controls referrer information'},
            'Permissions-Policy': {'required': False, 'description': 'Controls browser features'}
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=self.config.timeout, ssl=self.config.verify_ssl) as response:
                    headers = response.headers
                    
                    analysis = {
                        'url': url,
                        'status_code': response.status,
                        'headers_present': {},
                        'headers_missing': [],
                        'score': 0,
                        'max_score': 0
                    }
                    
                    for header, info in security_headers.items():
                        if header in headers:
                            analysis['headers_present'][header] = headers[header]
                            if info['required']:
                                analysis['score'] += 1
                        elif info['required']:
                            analysis['headers_missing'].append({
                                'header': header,
                                'description': info['description']
                            })
                        
                        if info['required']:
                            analysis['max_score'] += 1
                    
                    analysis['percentage'] = (analysis['score'] / analysis['max_score'] * 100) if analysis['max_score'] > 0 else 0
                    
                    return analysis
                    
        except Exception as e:
            return {"error": str(e), "url": url}
    
    async def _dns_lookup(self, domain: str, record_type: str = "A") -> Dict[str, Any]:
        """Perform DNS lookup for a domain"""
        import dns.resolver
        
        valid_types = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"]
        if record_type not in valid_types:
            return {"error": f"Invalid record type. Must be one of: {valid_types}"}
        
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = self.config.timeout
            resolver.lifetime = self.config.timeout
            
            answers = resolver.resolve(domain, record_type)
            
            records = []
            for rdata in answers:
                if record_type == "MX":
                    records.append({
                        "priority": rdata.preference,
                        "exchange": str(rdata.exchange)
                    })
                else:
                    records.append(str(rdata))
            
            return {
                "domain": domain,
                "record_type": record_type,
                "records": records,
                "ttl": answers.ttl
            }
            
        except dns.resolver.NXDOMAIN:
            return {"error": "Domain does not exist", "domain": domain}
        except Exception as e:
            return {"error": str(e), "domain": domain}
    
    async def _whois_lookup(self, domain: str) -> Dict[str, Any]:
        """Perform WHOIS lookup for a domain"""
        import whois
        
        try:
            w = whois.whois(domain)
            
            # Convert to serializable format
            result = {
                "domain": domain,
                "registrar": w.registrar,
                "creation_date": str(w.creation_date) if w.creation_date else None,
                "expiration_date": str(w.expiration_date) if w.expiration_date else None,
                "last_updated": str(w.last_updated) if w.last_updated else None,
                "status": w.status,
                "name_servers": w.name_servers if isinstance(w.name_servers, list) else [w.name_servers]
            }
            
            return result
            
        except Exception as e:
            return {"error": str(e), "domain": domain}
    
    async def _check_breach_database(self, email: str = None, domain: str = None) -> Dict[str, Any]:
        """Check if email or domain appears in breach databases"""
        if not email and not domain:
            return {"error": "Either email or domain must be provided"}
        
        # Note: This is demonstration code
        # Real implementation would need proper API key and rate limiting
        return {
            "note": "This would check Have I Been Pwned API",
            "email": email,
            "domain": domain,
            "implementation": "Requires HIBP API key for production use"
        }
    
    def _parse_cve_response(self, data: Dict) -> Dict[str, Any]:
        """Parse CVE API response"""
        if 'vulnerabilities' not in data:
            return {"error": "No vulnerabilities found"}
        
        cves = []
        for vuln in data['vulnerabilities'][:10]:  # Limit to 10 results
            cve = vuln.get('cve', {})
            cves.append({
                'id': cve.get('id'),
                'description': cve.get('descriptions', [{}])[0].get('value', 'No description'),
                'published': cve.get('published'),
                'last_modified': cve.get('lastModified'),
                'cvss': self._extract_cvss(cve)
            })
        
        return {
            'total_results': data.get('totalResults', 0),
            'cves': cves
        }
    
    def _extract_cvss(self, cve: Dict) -> Optional[Dict]:
        """Extract CVSS score from CVE data"""
        metrics = cve.get('metrics', {})
        
        # Try CVSS v3 first
        if 'cvssMetricV31' in metrics:
            cvss = metrics['cvssMetricV31'][0]['cvssData']
            return {
                'version': '3.1',
                'score': cvss.get('baseScore'),
                'severity': cvss.get('baseSeverity')
            }
        elif 'cvssMetricV30' in metrics:
            cvss = metrics['cvssMetricV30'][0]['cvssData']
            return {
                'version': '3.0',
                'score': cvss.get('baseScore'),
                'severity': cvss.get('baseSeverity')
            }
        
        return None
    
    async def run(self):
        """Run the MCP server"""
        async with stdio_server() as (read_stream, write_stream):
            await self.server.run(
                read_stream,
                write_stream,
                self.server.create_initialization_options()
            )

async def main():
    """Main entry point"""
    logging.basicConfig(level=logging.INFO)
    
    config = SecurityConfig(
        rate_limit=10,
        timeout=30,
        verify_ssl=True
    )
    
    server = SecurityToolsServer(config)
    await server.run()

if __name__ == "__main__":
    print("\n" + "="*60)
    print("🛡️  MCP Security Tools Server")
    print("="*60)
    print("\nThis is an MCP (Model Context Protocol) server that provides")
    print("security assessment tools for use with Claude or other MCP clients.")
    print("\n⚠️  This server is waiting for MCP client connections...")
    print("It won't show any output when running correctly.\n")
    print("To get started:")
    print("  1. Run 'python setup_wizard.py' for guided setup")
    print("  2. Run 'python test_servers.py' to verify all servers work")
    print("  3. Configure Claude Desktop to use this server\n")
    print("Press Ctrl+C to stop the server.\n")
    print("-"*60 + "\n")
    
    asyncio.run(main())
