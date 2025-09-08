#!/usr/bin/env python3
"""
Advanced MCP Security Client using FastMCP
Based on the fastmcp library for modern async MCP interactions
"""

import asyncio
import logging
import json
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from fastmcp import Client
import sys

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class ToolResult:
    """Structured tool result"""
    success: bool
    data: Any
    error: Optional[str] = None
    server: Optional[str] = None
    execution_time: Optional[float] = None

class AdvancedSecurityClient:
    """Advanced MCP client using FastMCP for comprehensive security testing"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Initialize FastMCP clients for each server
        # FastMCP client configuration with proper MCP server format
        import os
        self.clients = {
            'security': Client({
                "mcpServers": {
                    "security": {
                        "command": "python",
                        "args": [os.path.abspath("security_server.py")]
                    }
                }
            }),
            'asm': Client({
                "mcpServers": {
                    "asm": {
                        "command": "python", 
                        "args": [os.path.abspath("asm_server.py")]
                    }
                }
            }),
            'pentest': Client({
                "mcpServers": {
                    "pentest": {
                        "command": "python",
                        "args": [os.path.abspath("pentest_server.py")]
                    }
                }
            }), 
            'redteam': Client({
                "mcpServers": {
                    "redteam": {
                        "command": "python",
                        "args": [os.path.abspath("redteam_server.py")]
                    }
                }
            })
        }
        
        # Track which clients are connected
        self.connected_clients = set()
        
    async def connect(self, servers: List[str] = None):
        """Connect to specified servers (or all by default)"""
        if servers is None:
            servers = ['security', 'asm']  # Connect to core servers by default
            
        for server_name in servers:
            if server_name in self.clients:
                try:
                    client = self.clients[server_name]
                    # Test connection by listing tools
                    async with client:
                        tools = await client.list_tools()
                        self.connected_clients.add(server_name)
                        self.logger.info(f"✅ Connected to {server_name} server ({len(tools)} tools)")
                except Exception as e:
                    self.logger.error(f"❌ Failed to connect to {server_name}: {e}")
    
    async def disconnect(self):
        """Disconnect from all servers"""
        self.connected_clients.clear()
        self.logger.info("Disconnected from all servers")
    
    async def list_all_tools(self) -> Dict[str, List[Dict]]:
        """List tools from all connected servers"""
        all_tools = {}
        
        for server_name in self.connected_clients:
            try:
                client = self.clients[server_name]
                async with client:
                    tools = await client.list_tools()
                    all_tools[server_name] = tools
            except Exception as e:
                self.logger.error(f"Error listing tools from {server_name}: {e}")
                all_tools[server_name] = []
        
        return all_tools
    
    async def call_tool(self, server: str, tool_name: str, arguments: Dict[str, Any]) -> ToolResult:
        """Call a tool on a specific server"""
        import time
        
        if server not in self.connected_clients:
            return ToolResult(
                success=False,
                error=f"Not connected to {server} server",
                server=server
            )
        
        start_time = time.time()
        
        try:
            client = self.clients[server]
            async with client:
                result = await client.call_tool(tool_name, arguments)
                
                execution_time = time.time() - start_time
                
                # Extract data from FastMCP result
                if hasattr(result, 'content') and result.content:
                    # Get the text content from the result
                    text_content = result.content[0].text if result.content else "{}"
                    try:
                        data = json.loads(text_content)
                    except json.JSONDecodeError:
                        data = text_content
                else:
                    data = str(result) if result else None
                
                return ToolResult(
                    success=True,
                    data=data,
                    server=server,
                    execution_time=execution_time
                )
        
        except Exception as e:
            execution_time = time.time() - start_time
            return ToolResult(
                success=False,
                error=str(e),
                server=server,
                execution_time=execution_time
            )
    
    # High-level security assessment methods
    async def comprehensive_security_scan(self, domain: str) -> Dict[str, ToolResult]:
        """Perform comprehensive security assessment using multiple servers"""
        results = {}
        
        self.logger.info(f"Starting comprehensive security scan for {domain}")
        
        # Security server checks
        if 'security' in self.connected_clients:
            self.logger.info("Running security server checks...")
            results['ssl_check'] = await self.call_tool('security', 'check_ssl_certificate', {'domain': domain})
            results['security_headers'] = await self.call_tool('security', 'analyze_security_headers', {'url': f'https://{domain}'})
            results['dns_lookup'] = await self.call_tool('security', 'dns_lookup', {'domain': domain, 'record_type': 'A'})
            results['whois'] = await self.call_tool('security', 'whois_lookup', {'domain': domain})
        
        # ASM server checks  
        if 'asm' in self.connected_clients:
            self.logger.info("Running ASM server checks...")
            results['subdomains'] = await self.call_tool('asm', 'discover_subdomains', {'domain': domain})
            results['technologies'] = await self.call_tool('asm', 'identify_technologies', {'url': f'https://{domain}'})
            results['attack_surface'] = await self.call_tool('asm', 'map_attack_surface', {'domain': domain})
        
        # Pentest server checks
        if 'pentest' in self.connected_clients:
            self.logger.info("Running penetration testing checks...")
            results['vulnerability_scan'] = await self.call_tool('pentest', 'vulnerability_scan', {'target': domain, 'scan_type': 'basic'})
        
        self.logger.info("Comprehensive scan completed")
        return results
    
    async def batch_ssl_check(self, domains: List[str]) -> Dict[str, ToolResult]:
        """Check SSL certificates for multiple domains in parallel"""
        if 'security' not in self.connected_clients:
            return {domain: ToolResult(success=False, error="Security server not connected") for domain in domains}
        
        self.logger.info(f"Checking SSL certificates for {len(domains)} domains")
        
        tasks = []
        for domain in domains:
            task = self.call_tool('security', 'check_ssl_certificate', {'domain': domain})
            tasks.append((domain, task))
        
        results = {}
        for domain, task in tasks:
            results[domain] = await task
        
        return results
    
    async def red_team_simulation(self, scenario: str) -> Dict[str, ToolResult]:
        """Run red team simulation scenario"""
        if 'redteam' not in self.connected_clients:
            return {"error": ToolResult(success=False, error="Red team server not connected")}
        
        results = {}
        
        if scenario == "phishing":
            results['phishing_campaign'] = await self.call_tool('redteam', 'phishing_campaign', {
                'campaign_type': 'credential_harvesting',
                'template': 'generic'
            })
        elif scenario == "apt":
            results['apt_simulation'] = await self.call_tool('redteam', 'mitre_attack_simulation', {
                'tactic': 'RECONNAISSANCE'
            })
        elif scenario == "purple_team":
            results['purple_exercise'] = await self.call_tool('redteam', 'purple_team_exercise', {
                'scenario': 'ransomware',
                'blue_team_ready': True
            })
        
        return results

# Demo and testing functions
async def demo_advanced_client():
    """Demonstrate advanced client capabilities"""
    print("🚀 Advanced MCP Security Client Demo")
    print("="*60)
    
    client = AdvancedSecurityClient()
    
    try:
        # Connect to servers
        print("🔌 Connecting to MCP servers...")
        await client.connect(['security', 'asm'])
        
        if not client.connected_clients:
            print("❌ No servers connected. Exiting.")
            return
        
        # List all tools
        print("\n📋 Listing available tools...")
        all_tools = await client.list_all_tools()
        for server, tools in all_tools.items():
            print(f"  {server}: {len(tools)} tools")
        
        # Single tool test
        print("\n🔍 Testing SSL certificate check...")
        ssl_result = await client.call_tool('security', 'check_ssl_certificate', {'domain': 'github.com'})
        if ssl_result.success:
            print(f"  ✅ SSL check successful ({ssl_result.execution_time:.2f}s)")
            issuer = ssl_result.data.get('issuer', {}).get('organizationName', 'Unknown') if ssl_result.data else 'Unknown'
            print(f"  📋 Certificate issued by: {issuer}")
        else:
            print(f"  ❌ SSL check failed: {ssl_result.error}")
        
        # Batch processing test
        print("\n📦 Testing batch SSL checks...")
        domains = ['github.com', 'google.com', 'example.com']
        batch_results = await client.batch_ssl_check(domains)
        successful = sum(1 for result in batch_results.values() if result.success)
        print(f"  ✅ Batch completed: {successful}/{len(domains)} successful")
        
        # Comprehensive scan test
        print("\n🔬 Testing comprehensive security scan...")
        comp_results = await client.comprehensive_security_scan('example.com')
        successful_scans = sum(1 for result in comp_results.values() if result.success)
        print(f"  ✅ Comprehensive scan: {successful_scans}/{len(comp_results)} checks successful")
        
        print(f"\n🎉 Advanced client demo completed successfully!")
        
    except Exception as e:
        print(f"❌ Demo failed: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        await client.disconnect()

if __name__ == "__main__":
    asyncio.run(demo_advanced_client())