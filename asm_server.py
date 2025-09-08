#!/usr/bin/env python3
"""
ASM (Attack Surface Management) MCP Server
For authorized asset discovery and monitoring
"""

import asyncio
import json
import logging
import re
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import aiohttp
import dns.resolver
import ssl
import socket
from urllib.parse import urlparse

from mcp.server import Server
from mcp.server.stdio import stdio_server
import mcp.types as types

logger = logging.getLogger(__name__)

@dataclass
class AssetDiscoveryConfig:
    """Configuration for asset discovery"""
    target_domain: str
    recursive_depth: int = 2
    include_third_party: bool = False
    passive_only: bool = True  # Only passive reconnaissance by default
    timeout: int = 30
    max_subdomains: int = 100
    excluded_patterns: List[str] = field(default_factory=list)

class ASMServer:
    """Attack Surface Management MCP Server"""
    
    def __init__(self):
        self.server = Server("asm-tools")
        self.discovered_assets = {}
        self.setup_tools()
    
    def setup_tools(self):
        """Register ASM tools"""
        
        # Register the list_tools handler
        @self.server.list_tools()
        async def handle_list_tools() -> List[types.Tool]:
            """Return the list of available tools"""
            return [
                types.Tool(
                    name="discover_subdomains",
                    description="Discover subdomains for a target domain",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "domain": {
                                "type": "string",
                                "description": "Target domain to enumerate"
                            },
                            "passive_only": {
                                "type": "boolean",
                                "description": "Use only passive sources",
                                "default": True
                            },
                            "sources": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "List of sources to use (crtsh, wayback, dns)"
                            }
                        },
                        "required": ["domain"]
                    }
                ),
                types.Tool(
                    name="map_attack_surface",
                    description="Create comprehensive attack surface map",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "domain": {
                                "type": "string",
                                "description": "Target domain"
                            },
                            "include_subdomains": {
                                "type": "boolean",
                                "description": "Include subdomain enumeration",
                                "default": True
                            },
                            "check_ports": {
                                "type": "boolean",
                                "description": "Check common ports (requires permission)",
                                "default": False
                            },
                            "identify_tech": {
                                "type": "boolean",
                                "description": "Identify technologies",
                                "default": True
                            }
                        },
                        "required": ["domain"]
                    }
                ),
                types.Tool(
                    name="identify_technologies",
                    description="Identify technologies used by a web application",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "url": {
                                "type": "string",
                                "description": "Target URL to analyze"
                            }
                        },
                        "required": ["url"]
                    }
                ),
                types.Tool(
                    name="find_exposed_services",
                    description="Find exposed services (databases, admin panels, etc.)",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "ip_range": {
                                "type": "string",
                                "description": "IP range to scan (CIDR notation)"
                            },
                            "domain": {
                                "type": "string",
                                "description": "Domain to check"
                            },
                            "services": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Specific services to look for"
                            }
                        }
                    }
                ),
                types.Tool(
                    name="enumerate_api_endpoints",
                    description="Enumerate API endpoints (passive discovery)",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "base_url": {
                                "type": "string",
                                "description": "Base URL of the API"
                            },
                            "wordlist": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Custom wordlist for endpoint discovery"
                            }
                        },
                        "required": ["base_url"]
                    }
                ),
                types.Tool(
                    name="analyze_business_impact",
                    description="Analyze security findings for business impact and risk prioritization",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "findings": {
                                "type": "array",
                                "items": {"type": "object"},
                                "description": "List of security findings to analyze"
                            },
                            "asset_context": {
                                "type": "object",
                                "description": "Additional business context for assets"
                            }
                        },
                        "required": ["findings"]
                    }
                )
            ]
        
        # Register the call_tool handler
        @self.server.call_tool()
        async def handle_call_tool(name: str, arguments: dict) -> List[types.TextContent]:
            """Handle tool calls"""
            
            if name == "discover_subdomains":
                result = await self._discover_subdomains(
                    arguments.get("domain", ""),
                    arguments.get("passive_only", True),
                    arguments.get("sources")
                )
            elif name == "map_attack_surface":
                result = await self._map_attack_surface(
                    arguments.get("domain", ""),
                    arguments.get("include_subdomains", True),
                    arguments.get("check_ports", False),
                    arguments.get("identify_tech", True)
                )
            elif name == "identify_technologies":
                result = await self._identify_technologies(arguments.get("url", ""))
            elif name == "find_exposed_services":
                result = await self._find_exposed_services(
                    arguments.get("ip_range"),
                    arguments.get("domain"),
                    arguments.get("services")
                )
            elif name == "enumerate_api_endpoints":
                result = await self._enumerate_api_endpoints(
                    arguments.get("base_url", ""),
                    arguments.get("wordlist")
                )
            elif name == "analyze_business_impact":
                result = await self._analyze_business_impact(
                    arguments.get("findings", [])    )
            else:
                result = {"error": f"Unknown tool: {name}"}
            
            return [types.TextContent(type="text", text=json.dumps(result, indent=2))]
        
    async def _discover_subdomains(
        self,
        domain: str,
        passive_only: bool = True,
        sources: List[str] = None
    ) -> Dict[str, Any]:
        """Discover subdomains for a target domain"""
        if sources is None:
            sources = ['crtsh', 'wayback'] if passive_only else ['crtsh', 'wayback', 'dns']
        
        discovered = set()
        results = {
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'sources_used': sources,
            'subdomains': [],
            'total_found': 0
        }
        
        # Certificate Transparency Logs (crt.sh)
        if 'crtsh' in sources:
            crtsh_subs = await self._query_crtsh(domain)
            discovered.update(crtsh_subs)
            results['crtsh_count'] = len(crtsh_subs)
        
        # Wayback Machine
        if 'wayback' in sources:
            wayback_subs = await self._query_wayback(domain)
            discovered.update(wayback_subs)
            results['wayback_count'] = len(wayback_subs)
        
        # DNS Brute Force (only if not passive_only)
        if 'dns' in sources and not passive_only:
            dns_subs = await self._dns_enumeration(domain)
            discovered.update(dns_subs)
            results['dns_count'] = len(dns_subs)
        
        # Verify and enrich discovered subdomains
        for subdomain in discovered:
            sub_info = await self._verify_subdomain(subdomain)
            if sub_info['exists']:
                results['subdomains'].append(sub_info)
        
        results['total_found'] = len(results['subdomains'])
        
        # Store in discovered assets
        self.discovered_assets[domain] = results
        
        return results
    
    async def _map_attack_surface(
        self,
        domain: str,
        include_subdomains: bool = True,
        check_ports: bool = False,
        identify_tech: bool = True
    ) -> Dict[str, Any]:
        """Create comprehensive attack surface map"""
        attack_surface = {
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'assets': [],
            'technologies': [],
            'endpoints': [],
            'security_headers': {},
            'certificates': [],
            'dns_records': {}
        }
        
        # Get subdomains if requested
        targets = [domain]
        if include_subdomains:
            sub_result = await self._discover_subdomains(domain, passive_only=True)
            targets.extend([s['subdomain'] for s in sub_result.get('subdomains', [])])
        
        # Analyze each target
        for target in targets[:20]:  # Limit to prevent abuse
            asset = {
                'hostname': target,
                'ip_addresses': [],
                'open_ports': [],
                'technologies': [],
                'headers': {}
            }
            
            # DNS resolution
            try:
                ips = await self._resolve_domain(target)
                asset['ip_addresses'] = ips
            except:
                continue
            
            # Check HTTP/HTTPS
            for protocol in ['https', 'http']:
                url = f"{protocol}://{target}"
                response_data = await self._analyze_web_target(url)
                
                if response_data:
                    asset['technologies'].extend(response_data.get('technologies', []))
                    asset['headers'] = response_data.get('headers', {})
                    
                    if protocol == 'https':
                        asset['certificate'] = response_data.get('certificate')
            
            # Port scanning (if authorized)
            if check_ports and asset['ip_addresses']:
                # Only scan limited common ports
                common_ports = [80, 443, 22, 21, 25, 3306, 5432, 27017]
                asset['open_ports'] = await self._check_ports(
                    asset['ip_addresses'][0],
                    common_ports
                )
            
            attack_surface['assets'].append(asset)
        
        # Aggregate technologies
        all_techs = set()
        for asset in attack_surface['assets']:
            all_techs.update(asset.get('technologies', []))
        attack_surface['technologies'] = list(all_techs)
        
        # Security posture summary
        attack_surface['summary'] = self._generate_summary(attack_surface)
        
        return attack_surface
    
    async def _identify_technologies(self, url: str) -> Dict[str, Any]:
        """Identify technologies used by a web application"""
        technologies = {
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'technologies': [],
            'headers': {},
            'meta_tags': [],
            'scripts': [],
            'frameworks': []
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=30, ssl=False) as response:
                    headers = dict(response.headers)
                    body = await response.text()
                    
                    # Analyze headers
                    tech_from_headers = self._identify_from_headers(headers)
                    technologies['technologies'].extend(tech_from_headers)
                    technologies['headers'] = headers
                    
                    # Analyze response body
                    tech_from_body = self._identify_from_body(body)
                    technologies['technologies'].extend(tech_from_body)
                    
                    # Extract meta tags
                    technologies['meta_tags'] = self._extract_meta_tags(body)
                    
                    # Identify JavaScript libraries
                    technologies['scripts'] = self._extract_scripts(body)
                    
                    # Identify frameworks
                    technologies['frameworks'] = self._identify_frameworks(body, headers)
                    
        except Exception as e:
            technologies['error'] = str(e)
        
        return technologies
    
    async def _find_exposed_services(
        self,
        ip_range: str = None,
        domain: str = None,
        services: List[str] = None
    ) -> Dict[str, Any]:
        """Find exposed services"""
        if services is None:
            services = ['mongodb', 'elasticsearch', 'redis', 'mysql', 'postgresql']
        
        exposed = {
            'timestamp': datetime.now().isoformat(),
            'target': ip_range or domain,
            'exposed_services': [],
            'recommendations': []
        }
        
        # Common exposed service patterns
        service_patterns = {
            'mongodb': {'port': 27017, 'path': None},
            'elasticsearch': {'port': 9200, 'path': '/_cat/indices'},
            'redis': {'port': 6379, 'path': None},
            'mysql': {'port': 3306, 'path': None},
            'postgresql': {'port': 5432, 'path': None},
            'jenkins': {'port': 8080, 'path': '/login'},
            'gitlab': {'port': 80, 'path': '/users/sign_in'},
            'phpmyadmin': {'port': 80, 'path': '/phpmyadmin'},
            'kibana': {'port': 5601, 'path': '/app/kibana'}
        }
        
        # Check for exposed services
        targets = []
        if domain:
            ips = await self._resolve_domain(domain)
            targets.extend(ips)
        elif ip_range:
            # Parse CIDR and generate IPs (limited scope)
            targets = self._parse_cidr(ip_range)[:10]  # Limit to 10 IPs
        
        for target_ip in targets:
            for service_name in services:
                if service_name in service_patterns:
                    pattern = service_patterns[service_name]
                    is_exposed = await self._check_service_exposure(
                        target_ip,
                        pattern['port'],
                        pattern.get('path')
                    )
                    
                    if is_exposed:
                        exposed['exposed_services'].append({
                            'ip': target_ip,
                            'service': service_name,
                            'port': pattern['port'],
                            'severity': 'high' if service_name in ['mongodb', 'elasticsearch', 'redis'] else 'medium'
                        })
        
        # Generate recommendations
        if exposed['exposed_services']:
            exposed['recommendations'] = self._generate_security_recommendations(exposed['exposed_services'])
        
        return exposed
    
    async def _enumerate_api_endpoints(self, base_url: str, wordlist: List[str] = None) -> Dict[str, Any]:
        """Enumerate API endpoints"""
        if wordlist is None:
            # Common API endpoints
            wordlist = [
                'api', 'v1', 'v2', 'auth', 'users', 'login', 'logout',
                'register', 'profile', 'settings', 'admin', 'dashboard',
                'search', 'upload', 'download', 'files', 'documents',
                'health', 'status', 'info', 'version', 'swagger',
                'docs', 'graphql', 'api-docs', 'openapi.json'
            ]
        
        discovered_endpoints = {
            'base_url': base_url,
            'timestamp': datetime.now().isoformat(),
            'endpoints': [],
            'api_documentation': None,
            'authentication_required': []
        }
        
        async with aiohttp.ClientSession() as session:
            # Check for API documentation
            doc_paths = ['/swagger', '/api-docs', '/docs', '/openapi.json', '/swagger.json']
            for doc_path in doc_paths:
                url = f"{base_url}{doc_path}"
                if await self._check_endpoint_exists(session, url):
                    discovered_endpoints['api_documentation'] = url
                    break
            
            # Enumerate endpoints
            for endpoint in wordlist:
                for prefix in ['', '/api', '/v1', '/api/v1']:
                    url = f"{base_url}{prefix}/{endpoint}"
                    endpoint_info = await self._analyze_endpoint(session, url)
                    
                    if endpoint_info['exists']:
                        discovered_endpoints['endpoints'].append(endpoint_info)
                        
                        if endpoint_info.get('requires_auth'):
                            discovered_endpoints['authentication_required'].append(url)
        
        return discovered_endpoints
    
    # Helper methods
    async def _query_crtsh(self, domain: str) -> Set[str]:
        """Query crt.sh for certificate transparency logs"""
        subdomains = set()
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=30) as response:
                    if response.status == 200:
                        data = await response.json()
                        for entry in data:
                            name = entry.get('name_value', '')
                            if name and '*' not in name:
                                subdomains.add(name.lower())
        except Exception as e:
            logger.error(f"crt.sh query failed: {e}")
        
        return subdomains
    
    async def _query_wayback(self, domain: str) -> Set[str]:
        """Query Wayback Machine for historical URLs"""
        subdomains = set()
        try:
            url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}&output=json&fl=original&collapse=urlkey"
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=30) as response:
                    if response.status == 200:
                        data = await response.json()
                        for entry in data[1:]:  # Skip header
                            parsed = urlparse(entry[0])
                            if parsed.hostname:
                                subdomains.add(parsed.hostname.lower())
        except Exception as e:
            logger.error(f"Wayback query failed: {e}")
        
        return subdomains
    
    async def _dns_enumeration(self, domain: str) -> Set[str]:
        """Perform DNS enumeration (active)"""
        subdomains = set()
        common_prefixes = [
            'www', 'mail', 'ftp', 'admin', 'api', 'test', 'dev',
            'staging', 'prod', 'vpn', 'remote', 'webmail', 'ns1', 'ns2'
        ]
        
        for prefix in common_prefixes:
            subdomain = f"{prefix}.{domain}"
            try:
                await self._resolve_domain(subdomain)
                subdomains.add(subdomain)
            except:
                pass
        
        return subdomains
    
    async def _verify_subdomain(self, subdomain: str) -> Dict[str, Any]:
        """Verify if subdomain exists and gather info"""
        info = {
            'subdomain': subdomain,
            'exists': False,
            'ip_addresses': [],
            'cname': None
        }
        
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5
            
            # Try A records
            try:
                answers = resolver.resolve(subdomain, 'A')
                info['exists'] = True
                info['ip_addresses'] = [str(rdata) for rdata in answers]
            except:
                pass
            
            # Try CNAME records
            try:
                answers = resolver.resolve(subdomain, 'CNAME')
                info['exists'] = True
                info['cname'] = str(answers[0])
            except:
                pass
            
        except Exception as e:
            logger.debug(f"Failed to verify {subdomain}: {e}")
        
        return info
    
    async def _resolve_domain(self, domain: str) -> List[str]:
        """Resolve domain to IP addresses"""
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        
        try:
            answers = resolver.resolve(domain, 'A')
            return [str(rdata) for rdata in answers]
        except:
            return []
    
    async def _analyze_web_target(self, url: str) -> Optional[Dict[str, Any]]:
        """Analyze a web target"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=10, ssl=False) as response:
                    headers = dict(response.headers)
                    body = await response.text()
                    
                    result = {
                        'status_code': response.status,
                        'headers': headers,
                        'technologies': self._identify_from_headers(headers) + self._identify_from_body(body)
                    }
                    
                    # Get certificate info for HTTPS
                    if url.startswith('https'):
                        result['certificate'] = await self._get_cert_info(urlparse(url).hostname)
                    
                    return result
        except:
            return None
    
    async def _get_cert_info(self, hostname: str) -> Optional[Dict[str, Any]]:
        """Get SSL certificate information"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    return {
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'subject': dict(x[0] for x in cert['subject']),
                        'not_after': cert['notAfter']
                    }
        except:
            return None
    
    async def _check_ports(self, ip: str, ports: List[int]) -> List[int]:
        """Check which ports are open"""
        open_ports = []
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        return open_ports
    
    def _identify_from_headers(self, headers: Dict[str, str]) -> List[str]:
        """Identify technologies from HTTP headers"""
        technologies = []
        
        # Server header
        if 'server' in headers:
            server = headers['server'].lower()
            if 'nginx' in server:
                technologies.append('nginx')
            elif 'apache' in server:
                technologies.append('apache')
            elif 'microsoft-iis' in server:
                technologies.append('IIS')
        
        # X-Powered-By
        if 'x-powered-by' in headers:
            powered = headers['x-powered-by'].lower()
            if 'php' in powered:
                technologies.append('PHP')
            elif 'asp.net' in powered:
                technologies.append('ASP.NET')
            elif 'express' in powered:
                technologies.append('Express.js')
        
        # Other technology indicators
        if 'x-aspnet-version' in headers:
            technologies.append('ASP.NET')
        if 'x-drupal-cache' in headers:
            technologies.append('Drupal')
        if 'x-generator' in headers and 'wordpress' in headers['x-generator'].lower():
            technologies.append('WordPress')
        
        return technologies
    
    def _identify_from_body(self, body: str) -> List[str]:
        """Identify technologies from response body"""
        technologies = []
        body_lower = body.lower()
        
        # CMS detection
        if 'wp-content' in body_lower or 'wordpress' in body_lower:
            technologies.append('WordPress')
        if 'joomla' in body_lower:
            technologies.append('Joomla')
        if 'drupal' in body_lower:
            technologies.append('Drupal')
        
        # Framework detection
        if 'react' in body_lower or 'react.js' in body_lower:
            technologies.append('React')
        if 'angular' in body_lower:
            technologies.append('Angular')
        if 'vue.js' in body_lower or 'vuejs' in body_lower:
            technologies.append('Vue.js')
        if 'jquery' in body_lower:
            technologies.append('jQuery')
        
        return technologies
    
    def _extract_meta_tags(self, body: str) -> List[Dict[str, str]]:
        """Extract meta tags from HTML"""
        meta_tags = []
        # Simple regex pattern for meta tags
        pattern = r'<meta\s+(?:name|property)="([^"]+)"\s+content="([^"]+)"'
        matches = re.findall(pattern, body, re.IGNORECASE)
        for name, content in matches:
            meta_tags.append({'name': name, 'content': content})
        return meta_tags[:10]  # Limit to 10 tags
    
    def _extract_scripts(self, body: str) -> List[str]:
        """Extract script sources from HTML"""
        scripts = []
        pattern = r'<script[^>]+src="([^"]+)"'
        matches = re.findall(pattern, body, re.IGNORECASE)
        return matches[:20]  # Limit to 20 scripts
    
    def _identify_frameworks(self, body: str, headers: Dict[str, str]) -> List[str]:
        """Identify web frameworks"""
        frameworks = []
        
        # Check for framework-specific patterns
        if 'csrftoken' in body or 'django' in body.lower():
            frameworks.append('Django')
        if 'rails' in headers.get('x-powered-by', '').lower():
            frameworks.append('Ruby on Rails')
        if 'laravel' in body.lower() or 'laravel_session' in headers.get('set-cookie', ''):
            frameworks.append('Laravel')
        
        return frameworks
    
    def _parse_cidr(self, cidr: str) -> List[str]:
        """Parse CIDR notation to IP list (limited)"""
        # Simple implementation - would need ipaddress module for full support
        base_ip = cidr.split('/')[0]
        base_parts = base_ip.split('.')
        
        # Just return a few IPs for demo
        ips = []
        for i in range(1, 6):
            ip = f"{base_parts[0]}.{base_parts[1]}.{base_parts[2]}.{int(base_parts[3]) + i}"
            ips.append(ip)
        
        return ips
    
    async def _check_service_exposure(self, ip: str, port: int, path: Optional[str]) -> bool:
        """Check if a service is exposed"""
        try:
            # Check port
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((ip, port))
            sock.close()
            
            if result == 0:
                # Port is open
                if path:
                    # Check HTTP endpoint
                    url = f"http://{ip}:{port}{path}"
                    async with aiohttp.ClientSession() as session:
                        async with session.get(url, timeout=5) as response:
                            return response.status < 500
                return True
            return False
        except:
            return False
    
    def _generate_security_recommendations(self, exposed_services: List[Dict]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        for service in exposed_services:
            if service['service'] == 'mongodb':
                recommendations.append(f"MongoDB on {service['ip']}:{service['port']} - Enable authentication and bind to localhost")
            elif service['service'] == 'elasticsearch':
                recommendations.append(f"Elasticsearch on {service['ip']}:{service['port']} - Enable authentication and use TLS")
            elif service['service'] == 'redis':
                recommendations.append(f"Redis on {service['ip']}:{service['port']} - Set requirepass and bind to localhost")
            elif service['service'] == 'mysql':
                recommendations.append(f"MySQL on {service['ip']}:{service['port']} - Disable remote root login, use strong passwords")
        
        return recommendations
    
    async def _check_endpoint_exists(self, session: aiohttp.ClientSession, url: str) -> bool:
        """Check if an endpoint exists"""
        try:
            async with session.get(url, timeout=5) as response:
                return response.status < 500
        except:
            return False
    
    async def _analyze_endpoint(self, session: aiohttp.ClientSession, url: str) -> Dict[str, Any]:
        """Analyze an API endpoint"""
        endpoint_info = {
            'url': url,
            'exists': False,
            'methods': [],
            'requires_auth': False,
            'status_code': None
        }
        
        try:
            # Try GET request
            async with session.get(url, timeout=5) as response:
                endpoint_info['exists'] = response.status < 500
                endpoint_info['status_code'] = response.status
                
                if response.status == 401 or response.status == 403:
                    endpoint_info['requires_auth'] = True
                
                # Check allowed methods
                if 'allow' in response.headers:
                    endpoint_info['methods'] = response.headers['allow'].split(', ')
        except:
            pass
        
        return endpoint_info
    
    def _generate_summary(self, attack_surface: Dict[str, Any]) -> Dict[str, Any]:
        """Generate attack surface summary"""
        summary = {
            'total_assets': len(attack_surface['assets']),
            'total_ips': len(set(ip for asset in attack_surface['assets'] for ip in asset['ip_addresses'])),
            'technologies_count': len(attack_surface['technologies']),
            'risk_level': 'low',
            'key_findings': []
        }
        
        # Analyze for risks
        exposed_services = 0
        missing_https = 0
        
        for asset in attack_surface['assets']:
            if asset.get('open_ports'):
                exposed_services += len(asset['open_ports'])
            if not asset.get('certificate'):
                missing_https += 1
        
        if exposed_services > 5:
            summary['risk_level'] = 'medium'
            summary['key_findings'].append(f"{exposed_services} exposed services detected")
        
        if missing_https > 0:
            summary['key_findings'].append(f"{missing_https} assets without HTTPS")
        
        if exposed_services > 10:
            summary['risk_level'] = 'high'
        
        return summary
    
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
    server = ASMServer()
    await server.run()

if __name__ == "__main__":
    print("\n" + "="*60)
    print("🔍 MCP Attack Surface Management (ASM) Server")
    print("="*60)
    print("\nThis is an MCP server that provides attack surface")
    print("management and reconnaissance tools.")
    print("\n⚠️  This server is waiting for MCP client connections...")
    print("It won't show any output when running correctly.\n")
    print("To get started:")
    print("  1. Run 'python setup_wizard.py' for guided setup")
    print("  2. Run 'python test_servers.py' to verify all servers work")
    print("  3. Configure Claude Desktop to use this server\n")
    print("Press Ctrl+C to stop the server.\n")
    print("-"*60 + "\n")
    
    asyncio.run(main())
