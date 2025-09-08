#!/usr/bin/env python3
"""
MCP Security Server - Ethical Security Tools Integration
This server provides legitimate security assessment capabilities
"""

import os
import json
import asyncio
import logging
from typing import Any, Dict, List, Optional
from datetime import datetime, timedelta
import aiohttp
import ssl
import socket
from dataclasses import dataclass
from enum import Enum


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
            elif name == "analyze_business_impact":
                result = await self._analyze_business_impact(
                    arguments.get("findings", [])
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

class BusinessRiskLevel(Enum):
    CRITICAL = 10
    HIGH = 8
    MEDIUM = 5
    LOW = 2
    INFO = 1

class AssetCategory(Enum):
    PUBLIC_FACING = "public_facing"
    INTERNAL_PROD = "internal_production"
    INTERNAL_DEV = "internal_development"
    ADMIN_SYSTEM = "admin_system"
    TEST_SYSTEM = "test_system"

@dataclass
class BusinessContext:
    asset_name: str
    category: AssetCategory
    business_value: int  # 1-10 scale
    internet_facing: bool
    data_classification: str  # public, internal, confidential, restricted
    owner_team: str
    criticality: str  # mission_critical, important, standard, low

class SecurityAnalyst:
    """AI Security Analyst for business-aware vulnerability management"""
    
    def __init__(self):
        self.business_rules = self._load_business_rules()
        self.escalation_history = {}
        
    def _load_business_rules(self) -> Dict[str, Any]:
        """Load company-specific business rules"""
        return {
            'auto_escalate_threshold': 8,
            'ticket_creation_threshold': 6,
            'review_threshold': 4,
            'critical_assets': ['auth', 'api', 'admin', 'prod', 'payment'],
            'dev_keywords': ['dev', 'test', 'staging', 'sandbox'],
            'risk_multipliers': {
                'internet_facing': 2.0,
                'contains_pii': 1.5,
                'financial_system': 2.5,
                'admin_access': 2.0
            }
        }
    
    async def analyze_finding_business_impact(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze a security finding for business impact"""
        
        # Get business context for the asset
        business_context = await self._determine_business_context(finding.get('asset', ''))
        
        # Calculate business risk score
        business_risk = self._calculate_business_risk(
            technical_severity=finding.get('severity', 'low'),
            cvss_score=finding.get('cvss_score', 0),
            business_context=business_context
        )
        
        # Determine action needed
        action = await self._determine_action(business_risk, finding, business_context)
        
        # Enhanced finding with business intelligence
        enhanced_finding = {
            **finding,
            'business_context': business_context.__dict__,
            'business_risk_score': business_risk,
            'business_risk_level': self._get_risk_level(business_risk).name,
            'recommended_action': action,
            'escalation_required': business_risk >= self.business_rules['auto_escalate_threshold'],
            'business_justification': self._generate_business_justification(business_risk, finding, business_context)
        }
        
        return enhanced_finding
    
    async def _determine_business_context(self, asset: str) -> BusinessContext:
        """Determine business context for an asset"""
        asset_lower = asset.lower()
        
        # Categorize asset based on naming patterns
        if any(keyword in asset_lower for keyword in ['api', 'prod', 'www', 'app']):
            category = AssetCategory.PUBLIC_FACING
            business_value = 9
            internet_facing = True
        elif any(keyword in asset_lower for keyword in ['admin', 'mgmt', 'control']):
            category = AssetCategory.ADMIN_SYSTEM
            business_value = 8
            internet_facing = False
        elif any(keyword in asset_lower for keyword in ['dev', 'test', 'staging']):
            category = AssetCategory.INTERNAL_DEV
            business_value = 3
            internet_facing = False
        else:
            category = AssetCategory.INTERNAL_PROD
            business_value = 6
            internet_facing = False
        
        # Determine data classification
        if any(keyword in asset_lower for keyword in ['payment', 'billing', 'financial']):
            data_classification = "restricted"
            business_value = min(business_value + 2, 10)
        elif any(keyword in asset_lower for keyword in ['admin', 'mgmt']):
            data_classification = "confidential"
        elif 'dev' in asset_lower or 'test' in asset_lower:
            data_classification = "internal"
        else:
            data_classification = "internal"
        
        # Determine owner team (could be enhanced with asset inventory integration)
        owner_team = self._guess_owner_team(asset_lower)
        
        # Determine criticality
        if business_value >= 8:
            criticality = "mission_critical"
        elif business_value >= 6:
            criticality = "important"
        elif business_value >= 4:
            criticality = "standard"
        else:
            criticality = "low"
        
        return BusinessContext(
            asset_name=asset,
            category=category,
            business_value=business_value,
            internet_facing=internet_facing,
            data_classification=data_classification,
            owner_team=owner_team,
            criticality=criticality
        )
    
    def _calculate_business_risk(self, technical_severity: str, cvss_score: float, business_context: BusinessContext) -> float:
        """Calculate business risk score (1-10)"""
        
        # Convert technical severity to base score
        severity_scores = {
            'critical': 9,
            'high': 7,
            'medium': 5,
            'low': 3,
            'info': 1
        }
        
        base_score = severity_scores.get(technical_severity.lower(), 3)
        
        # If we have CVSS score, use that as base instead
        if cvss_score > 0:
            base_score = cvss_score
        
        # Apply business context multipliers
        business_multiplier = 1.0
        
        # Asset category multiplier
        category_multipliers = {
            AssetCategory.PUBLIC_FACING: 1.5,
            AssetCategory.ADMIN_SYSTEM: 1.3,
            AssetCategory.INTERNAL_PROD: 1.0,
            AssetCategory.INTERNAL_DEV: 0.7,
            AssetCategory.TEST_SYSTEM: 0.5
        }
        business_multiplier *= category_multipliers.get(business_context.category, 1.0)
        
        # Internet facing multiplier
        if business_context.internet_facing:
            business_multiplier *= self.business_rules['risk_multipliers']['internet_facing']
        
        # Data classification multiplier
        classification_multipliers = {
            'restricted': 2.0,
            'confidential': 1.5,
            'internal': 1.0,
            'public': 0.8
        }
        business_multiplier *= classification_multipliers.get(business_context.data_classification, 1.0)
        
        # Business value multiplier
        business_multiplier *= (business_context.business_value / 10.0) * 1.5
        
        # Calculate final business risk
        business_risk = min(base_score * business_multiplier, 10.0)
        
        return round(business_risk, 1)
    
    async def _determine_action(self, business_risk: float, finding: Dict, business_context: BusinessContext) -> str:
        """Determine what action should be taken"""
        
        if business_risk >= self.business_rules['auto_escalate_threshold']:
            return "immediate_escalation"
        elif business_risk >= self.business_rules['ticket_creation_threshold']:
            return "create_ticket"
        elif business_risk >= self.business_rules['review_threshold']:
            return "weekly_review"
        else:
            return "log_only"
    
    def _generate_business_justification(self, business_risk: float, finding: Dict, business_context: BusinessContext) -> str:
        """Generate human-readable business justification"""
        
        justifications = []
        
        # Risk level explanation
        if business_risk >= 8:
            justifications.append(f"High business risk ({business_risk}/10)")
        
        # Asset criticality
        if business_context.criticality == "mission_critical":
            justifications.append("affects mission-critical system")
        
        # Exposure
        if business_context.internet_facing:
            justifications.append("internet-facing asset")
        
        # Data sensitivity
        if business_context.data_classification in ['restricted', 'confidential']:
            justifications.append(f"handles {business_context.data_classification} data")
        
        # Technical severity
        technical_severity = finding.get('severity', 'unknown')
        if technical_severity in ['critical', 'high']:
            justifications.append(f"{technical_severity} severity vulnerability")
        
        return "; ".join(justifications).capitalize()
    
    def _guess_owner_team(self, asset: str) -> str:
        """Guess owner team based on asset name patterns"""
        if any(keyword in asset for keyword in ['api', 'backend', 'service']):
            return "backend_team"
        elif any(keyword in asset for keyword in ['web', 'frontend', 'www']):
            return "frontend_team"
        elif any(keyword in asset for keyword in ['admin', 'mgmt']):
            return "platform_team"
        elif any(keyword in asset for keyword in ['dev', 'test']):
            return "qa_team"
        else:
            return "infrastructure_team"
    
    def _get_risk_level(self, score: float) -> BusinessRiskLevel:
        """Convert numeric risk score to risk level enum"""
        if score >= 9:
            return BusinessRiskLevel.CRITICAL
        elif score >= 7:
            return BusinessRiskLevel.HIGH
        elif score >= 5:
            return BusinessRiskLevel.MEDIUM
        elif score >= 3:
            return BusinessRiskLevel.LOW
        else:
            return BusinessRiskLevel.INFO

# Integration into SecurityToolsServer class
class SecurityToolsServer:
    def __init__(self, config: SecurityConfig = None):
        self.config = config or SecurityConfig()
        self.server = Server("security-tools")
        self.analyst = SecurityAnalyst()  # Add AI analyst
        self.setup_tools()
    
    # Add new tool for business analysis
    async def _analyze_business_impact(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze findings for business impact"""
        
        enhanced_findings = []
        summary_stats = {
            'total_findings': len(findings),
            'critical_business_risk': 0,
            'high_business_risk': 0,
            'escalations_needed': 0,
            'tickets_to_create': 0
        }
        
        for finding in findings:
            # Get business analysis
            enhanced_finding = await self.analyst.analyze_finding_business_impact(finding)
            enhanced_findings.append(enhanced_finding)
            
            # Update summary stats
            risk_level = enhanced_finding['business_risk_level']
            if risk_level == 'CRITICAL':
                summary_stats['critical_business_risk'] += 1
            elif risk_level == 'HIGH':
                summary_stats['high_business_risk'] += 1
            
            if enhanced_finding['escalation_required']:
                summary_stats['escalations_needed'] += 1
            elif enhanced_finding['recommended_action'] == 'create_ticket':
                summary_stats['tickets_to_create'] += 1
        
        return {
            'enhanced_findings': enhanced_findings,
            'summary': summary_stats,
            'executive_summary': self._generate_executive_summary(summary_stats),
            'recommended_actions': self._generate_action_plan(enhanced_findings)
        }
    
    def _generate_executive_summary(self, stats: Dict) -> str:
        """Generate executive summary for leadership"""
        total = stats['total_findings']
        critical = stats['critical_business_risk']
        high = stats['high_business_risk']
        
        if critical > 0:
            return f"URGENT: {critical} critical business risks found among {total} total findings. Immediate attention required."
        elif high > 0:
            return f"{high} high business risks identified among {total} findings. Recommend prioritizing remediation."
        else:
            return f"{total} findings analyzed. No critical business risks identified. Normal monitoring recommended."
    
    def _generate_action_plan(self, findings: List[Dict]) -> List[str]:
        """Generate actionable next steps"""
        actions = []
        
        escalations = [f for f in findings if f['escalation_required']]
        if escalations:
            actions.append(f"Immediately escalate {len(escalations)} critical findings to security team")
        
        tickets = [f for f in findings if f['recommended_action'] == 'create_ticket']
        if tickets:
            actions.append(f"Create {len(tickets)} development tickets for remediation")
        
        # Group by owner team for coordination
        teams = {}
        for finding in findings:
            team = finding['business_context']['owner_team']
            if team not in teams:
                teams[team] = 0
            teams[team] += 1
        
        for team, count in teams.items():
            if count > 0:
                actions.append(f"Coordinate with {team} on {count} findings")
        
        return actions

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
