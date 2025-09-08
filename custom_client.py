#!/usr/bin/env python3
"""
Complete MCP Security Client
Production-ready client for all MCP security servers
"""

import subprocess
import json
import sys
import time
import logging
import threading
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass
from contextlib import contextmanager
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class ServerConfig:
    """Configuration for an MCP server"""
    name: str
    script_path: str
    description: str
    tools: List[str]

@dataclass
class ToolResult:
    """Standardized tool result"""
    success: bool
    data: Any
    error: Optional[str] = None
    server: Optional[str] = None
    tool: Optional[str] = None
    execution_time: Optional[float] = None

class MCPConnectionPool:
    """Simple connection pool for MCP servers"""
    
    def __init__(self):
        self._connections = {}
        self._lock = threading.Lock()
    
    def get_connection(self, server_script: str):
        """Get or create a connection to a server"""
        with self._lock:
            if server_script not in self._connections:
                self._connections[server_script] = self._create_connection(server_script)
            return self._connections[server_script]
    
    def _create_connection(self, server_script: str):
        """Create a new server connection"""
        try:
            process = subprocess.Popen(
                [sys.executable, server_script],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            
            # Initialize MCP connection with handshake
            if self._initialize_mcp_connection(process):
                return process
            else:
                process.terminate()
                return None
                
        except Exception as e:
            logger.error(f"Failed to start server {server_script}: {e}")
            return None
    
    def _initialize_mcp_connection(self, process) -> bool:
        """Initialize MCP connection with proper handshake"""
        try:
            # Send initialization request
            init_request = {
                "jsonrpc": "2.0",
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {}
                    },
                    "clientInfo": {
                        "name": "mcp-security-client",
                        "version": "1.0.0"
                    }
                },
                "id": 1
            }
            
            # Send initialization
            process.stdin.write(json.dumps(init_request) + '\n')
            process.stdin.flush()
            
            # Read initialization response
            response_line = process.stdout.readline()
            if response_line:
                response = json.loads(response_line.strip())
                if "result" in response:
                    # Send initialized notification
                    initialized_notification = {
                        "jsonrpc": "2.0",
                        "method": "notifications/initialized"
                    }
                    process.stdin.write(json.dumps(initialized_notification) + '\n')
                    process.stdin.flush()
                    
                    # Give server a moment to process
                    time.sleep(0.5)
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"MCP initialization failed: {e}")
            return False
    
    def close_all(self):
        """Close all connections"""
        with self._lock:
            for process in self._connections.values():
                if process:
                    try:
                        process.terminate()
                        process.wait(timeout=5)
                    except:
                        process.kill()
            self._connections.clear()

class SecurityToolsClient:
    """Complete MCP Security Tools Client"""
    
    def __init__(self, server_base_path: str = "."):
        """
        Initialize the security tools client
        
        Args:
            server_base_path: Base path where server scripts are located
        """
        self.server_base_path = server_base_path
        self.connection_pool = MCPConnectionPool()
        self.request_id = 0
        
        # Define available servers and their tools
        self.servers = {
            "security": ServerConfig(
                name="Security Tools",
                script_path=os.path.join(server_base_path, "security_server.py"),
                description="Core security assessment tools",
                tools=["check_ssl_certificate", "query_cve_database", "analyze_security_headers", 
                      "dns_lookup", "whois_lookup", "check_breach_database", "analyze_business_impact"]
            ),
            "asm": ServerConfig(
                name="Attack Surface Management", 
                script_path=os.path.join(server_base_path, "asm_server.py"),
                description="Attack surface management and reconnaissance",
                tools=["discover_subdomains", "map_attack_surface", "identify_technologies",
                      "find_exposed_services", "enumerate_api_endpoints", "analyze_business_impact"]
            ),
            "pentest": ServerConfig(
                name="Penetration Testing",
                script_path=os.path.join(server_base_path, "pentest_server.py"), 
                description="Penetration testing and vulnerability assessment",
                tools=["vulnerability_scan", "fuzzing_test", "password_audit", "exploit_framework",
                      "web_shell_detector", "privilege_escalation_check", "analyze_business_impact"]
            ),
            "redteam": ServerConfig(
                name="Red Team Operations",
                script_path=os.path.join(server_base_path, "redteam_server.py"),
                description="Red team simulation and adversary emulation", 
                tools=["phishing_campaign", "generate_payload", "c2_infrastructure", "lateral_movement",
                      "persistence_mechanism", "data_exfiltration", "defense_evasion", 
                      "mitre_attack_simulation", "purple_team_exercise", "analyze_business_impact"]
            )
        }
    
    def _get_next_id(self) -> int:
        """Get next request ID"""
        self.request_id += 1
        return self.request_id
    
    def _send_mcp_request(self, server_key: str, tool_name: str, arguments: Dict[str, Any], 
                         timeout: int = 30, retries: int = 2) -> ToolResult:
        """
        Send request to MCP server with retry logic
        
        Args:
            server_key: Key identifying the server (security, asm, pentest, redteam)
            tool_name: Name of the tool to call
            arguments: Tool arguments
            timeout: Request timeout in seconds
            retries: Number of retry attempts
            
        Returns:
            ToolResult with success/failure info
        """
        if server_key not in self.servers:
            return ToolResult(
                success=False,
                data=None,
                error=f"Unknown server: {server_key}",
                server=server_key,
                tool=tool_name
            )
        
        server_config = self.servers[server_key]
        start_time = time.time()
        
        for attempt in range(retries + 1):
            try:
                return self._attempt_request(server_config, tool_name, arguments, timeout)
            except Exception as e:
                if attempt == retries:  # Last attempt
                    execution_time = time.time() - start_time
                    logger.error(f"All retry attempts failed for {tool_name} on {server_key}: {e}")
                    return ToolResult(
                        success=False,
                        data=None,
                        error=f"Request failed after {retries + 1} attempts: {str(e)}",
                        server=server_key,
                        tool=tool_name,
                        execution_time=execution_time
                    )
                else:
                    logger.warning(f"Attempt {attempt + 1} failed for {tool_name}, retrying...")
                    time.sleep(1)  # Brief delay before retry
    
    def _attempt_request(self, server_config: ServerConfig, tool_name: str, 
                        arguments: Dict[str, Any], timeout: int) -> ToolResult:
        """Single request attempt"""
        start_time = time.time()
        
        # Get connection 
        process = self.connection_pool.get_connection(server_config.script_path)
        if not process:
            raise Exception(f"Could not connect to server {server_config.name}")
        
        # Create JSON-RPC request using correct MCP format
        request = {
            "jsonrpc": "2.0", 
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments
            },
            "id": self._get_next_id()
        }
        
        try:
            # Send request
            request_json = json.dumps(request) + '\n'
            process.stdin.write(request_json)
            process.stdin.flush()
            
            # Read response with timeout
            response_line = process.stdout.readline()
            execution_time = time.time() - start_time
            
            if response_line:
                response = json.loads(response_line.strip())
                
                # Handle JSON-RPC response format
                if "result" in response:
                    # Success response - MCP format: {"result": {"content": [{"type": "text", "text": "..."}], "isError": false}}
                    result_data = response["result"]
                    
                    # Check if it's an error result
                    if isinstance(result_data, dict) and result_data.get("isError", False):
                        return ToolResult(
                            success=False,
                            data=None,
                            error="Tool execution failed",
                            server=server_config.name,
                            tool=tool_name,
                            execution_time=execution_time
                        )
                    
                    # Extract data from MCP content format
                    if isinstance(result_data, dict) and "content" in result_data:
                        content_list = result_data["content"]
                        if isinstance(content_list, list) and len(content_list) > 0:
                            # Get the text from the first content item
                            text_content = content_list[0].get("text", "{}")
                            try:
                                # Try to parse as JSON
                                data = json.loads(text_content)
                            except json.JSONDecodeError:
                                # If not JSON, return as string
                                data = text_content
                        else:
                            data = result_data
                    else:
                        data = result_data
                    
                    return ToolResult(
                        success=True,
                        data=data,
                        error=None,
                        server=server_config.name,
                        tool=tool_name,
                        execution_time=execution_time
                    )
                elif "error" in response:
                    # Error response
                    return ToolResult(
                        success=False,
                        data=None,
                        error=response["error"].get("message", "Unknown error"),
                        server=server_config.name,
                        tool=tool_name,
                        execution_time=execution_time
                    )
            else:
                # No response, check stderr
                error_output = ""
                try:
                    # Non-blocking read of stderr
                    import select
                    if select.select([process.stderr], [], [], 0)[0]:
                        error_output = process.stderr.read()
                except:
                    pass
                
                raise Exception(f"No response from server. Error: {error_output}")
                
        except json.JSONDecodeError as e:
            raise Exception(f"Invalid JSON response: {e}")
        except Exception as e:
            raise Exception(f"Communication error: {e}")
    
    @contextmanager
    def connection(self):
        """Context manager for handling connections"""
        try:
            yield self
        finally:
            self.close()
    
    def close(self):
        """Close all server connections"""
        self.connection_pool.close_all()
        
    def list_servers(self) -> Dict[str, ServerConfig]:
        """Get available servers"""
        return self.servers.copy()
    
    def list_tools(self, server_key: Optional[str] = None) -> Dict[str, List[str]]:
        """List available tools for all servers or a specific server"""
        if server_key:
            if server_key in self.servers:
                return {server_key: self.servers[server_key].tools}
            else:
                return {}
        else:
            return {key: config.tools for key, config in self.servers.items()}
    
    # ===================
    # Security Server Tools
    # ===================
    
    def check_ssl_certificate(self, domain: str) -> ToolResult:
        """Check SSL certificate information for a domain"""
        return self._send_mcp_request("security", "check_ssl_certificate", {"domain": domain})
    
    def query_cve_database(self, cve_id: str = None, keyword: str = None, last_n_days: int = 7) -> ToolResult:
        """Query CVE database for vulnerability information"""
        args = {"last_n_days": last_n_days}
        if cve_id:
            args["cve_id"] = cve_id
        if keyword:
            args["keyword"] = keyword
        return self._send_mcp_request("security", "query_cve_database", args)
    
    def analyze_security_headers(self, url: str) -> ToolResult:
        """Analyze security headers for a given URL"""
        return self._send_mcp_request("security", "analyze_security_headers", {"url": url})
    
    def dns_lookup(self, domain: str, record_type: str = "A") -> ToolResult:
        """Perform DNS lookup for a domain"""
        return self._send_mcp_request("security", "dns_lookup", {
            "domain": domain, 
            "record_type": record_type
        })
    
    def whois_lookup(self, domain: str) -> ToolResult:
        """Perform WHOIS lookup for a domain"""
        return self._send_mcp_request("security", "whois_lookup", {"domain": domain})
    
    def check_breach_database(self, email: str = None, domain: str = None) -> ToolResult:
        """Check if email or domain appears in breach databases"""
        args = {}
        if email:
            args["email"] = email
        if domain:
            args["domain"] = domain
        return self._send_mcp_request("security", "check_breach_database", args)
    
    # ===================
    # ASM Server Tools  
    # ===================
    
    def discover_subdomains(self, domain: str, passive_only: bool = True, sources: List[str] = None) -> ToolResult:
        """Discover subdomains for a target domain"""
        args = {"domain": domain, "passive_only": passive_only}
        if sources:
            args["sources"] = sources
        return self._send_mcp_request("asm", "discover_subdomains", args)
    
    def map_attack_surface(self, domain: str, include_subdomains: bool = True, 
                          check_ports: bool = False, identify_tech: bool = True) -> ToolResult:
        """Create comprehensive attack surface map"""
        return self._send_mcp_request("asm", "map_attack_surface", {
            "domain": domain,
            "include_subdomains": include_subdomains,
            "check_ports": check_ports,
            "identify_tech": identify_tech
        })
    
    def identify_technologies(self, url: str) -> ToolResult:
        """Identify technologies used by a web application"""
        return self._send_mcp_request("asm", "identify_technologies", {"url": url})
    
    def find_exposed_services(self, ip_range: str = None, domain: str = None, 
                             services: List[str] = None) -> ToolResult:
        """Find exposed services (databases, admin panels, etc.)"""
        args = {}
        if ip_range:
            args["ip_range"] = ip_range
        if domain:
            args["domain"] = domain
        if services:
            args["services"] = services
        return self._send_mcp_request("asm", "find_exposed_services", args)
    
    def enumerate_api_endpoints(self, base_url: str, wordlist: List[str] = None) -> ToolResult:
        """Enumerate API endpoints (passive discovery)"""
        args = {"base_url": base_url}
        if wordlist:
            args["wordlist"] = wordlist
        return self._send_mcp_request("asm", "enumerate_api_endpoints", args)
    
    # ===================
    # Pentest Server Tools
    # ===================
    
    def vulnerability_scan(self, target: str, scan_type: str = "basic", 
                          check_auth: bool = True, check_injection: bool = True, 
                          check_xss: bool = True) -> ToolResult:
        """Perform vulnerability scanning on authorized target"""
        return self._send_mcp_request("pentest", "vulnerability_scan", {
            "target": target,
            "scan_type": scan_type,
            "check_auth": check_auth,
            "check_injection": check_injection,
            "check_xss": check_xss
        })
    
    def fuzzing_test(self, target_url: str, fuzz_type: str = "parameter", 
                    wordlist: List[str] = None, methods: List[str] = None) -> ToolResult:
        """Perform fuzzing tests on web applications"""
        args = {"target_url": target_url, "fuzz_type": fuzz_type}
        if wordlist:
            args["wordlist"] = wordlist
        if methods:
            args["methods"] = methods
        return self._send_mcp_request("pentest", "fuzzing_test", args)
    
    def password_audit(self, hash_list: List[str], hash_type: str = "auto", 
                      check_common: bool = True, check_leaked: bool = True) -> ToolResult:
        """Audit password hashes (for authorized testing only)"""
        return self._send_mcp_request("pentest", "password_audit", {
            "hash_list": hash_list,
            "hash_type": hash_type,
            "check_common": check_common,
            "check_leaked": check_leaked
        })
    
    def exploit_framework(self, vulnerability_type: str, target: str, 
                         payload_type: str = "test", verify_only: bool = True) -> ToolResult:
        """Exploit framework for testing verified vulnerabilities"""
        return self._send_mcp_request("pentest", "exploit_framework", {
            "vulnerability_type": vulnerability_type,
            "target": target,
            "payload_type": payload_type,
            "verify_only": verify_only
        })
    
    def web_shell_detector(self, target_directory: str, scan_depth: int = 3, 
                          check_patterns: bool = True, check_behaviors: bool = True) -> ToolResult:
        """Detect potential web shells in authorized systems"""
        return self._send_mcp_request("pentest", "web_shell_detector", {
            "target_directory": target_directory,
            "scan_depth": scan_depth,
            "check_patterns": check_patterns,
            "check_behaviors": check_behaviors
        })
    
    def privilege_escalation_check(self, target_os: str = "linux", check_type: str = "all", 
                                  user_context: str = None) -> ToolResult:
        """Check for privilege escalation vectors"""
        args = {"target_os": target_os, "check_type": check_type}
        if user_context:
            args["user_context"] = user_context
        return self._send_mcp_request("pentest", "privilege_escalation_check", args)
    
    # ===================
    # Red Team Server Tools
    # ===================
    
    def phishing_campaign(self, campaign_type: str = "credential_harvesting", 
                         target_list: List[str] = None, template: str = "generic", 
                         track_opens: bool = True) -> ToolResult:
        """Simulate phishing campaigns for security awareness"""
        args = {
            "campaign_type": campaign_type,
            "template": template,
            "track_opens": track_opens
        }
        if target_list:
            args["target_list"] = target_list
        return self._send_mcp_request("redteam", "phishing_campaign", args)
    
    def generate_payload(self, payload_type: str, target_os: str = "windows", 
                        callback_host: str = None, obfuscation_level: int = 5, 
                        sandbox_evasion: bool = True) -> ToolResult:
        """Generate red team payloads for testing"""
        args = {
            "payload_type": payload_type,
            "target_os": target_os,
            "obfuscation_level": obfuscation_level,
            "sandbox_evasion": sandbox_evasion
        }
        if callback_host:
            args["callback_host"] = callback_host
        return self._send_mcp_request("redteam", "generate_payload", args)
    
    def c2_infrastructure(self, infra_type: str = "http", domain_fronting: bool = False, 
                         redirectors: int = 0, persistence: bool = False) -> ToolResult:
        """Setup C2 infrastructure for operations"""
        return self._send_mcp_request("redteam", "c2_infrastructure", {
            "infra_type": infra_type,
            "domain_fronting": domain_fronting,
            "redirectors": redirectors,
            "persistence": persistence
        })
    
    def lateral_movement(self, technique: str, source_host: str, target_host: str, 
                        credential_type: str = "password") -> ToolResult:
        """Simulate lateral movement techniques"""
        return self._send_mcp_request("redteam", "lateral_movement", {
            "technique": technique,
            "source_host": source_host,
            "target_host": target_host,
            "credential_type": credential_type
        })
    
    def persistence_mechanism(self, technique: str, target_host: str, 
                             callback_interval: int = 3600, hidden: bool = True) -> ToolResult:
        """Establish persistence mechanisms"""
        return self._send_mcp_request("redteam", "persistence_mechanism", {
            "technique": technique,
            "target_host": target_host,
            "callback_interval": callback_interval,
            "hidden": hidden
        })
    
    def data_exfiltration(self, method: str, data_size_mb: int, 
                         encryption: bool = True, steganography: bool = False) -> ToolResult:
        """Simulate data exfiltration techniques"""
        return self._send_mcp_request("redteam", "data_exfiltration", {
            "method": method,
            "data_size_mb": data_size_mb,
            "encryption": encryption,
            "steganography": steganography
        })
    
    def defense_evasion(self, technique: str, target_process: str = None, 
                       detection_system: str = "edr") -> ToolResult:
        """Implement defense evasion techniques"""
        args = {"technique": technique, "detection_system": detection_system}
        if target_process:
            args["target_process"] = target_process
        return self._send_mcp_request("redteam", "defense_evasion", args)
    
    def mitre_attack_simulation(self, tactic: str, technique_id: str = None, 
                               target: str = None) -> ToolResult:
        """Simulate specific MITRE ATT&CK techniques"""
        args = {"tactic": tactic}
        if technique_id:
            args["technique_id"] = technique_id
        if target:
            args["target"] = target
        return self._send_mcp_request("redteam", "mitre_attack_simulation", args)
    
    def purple_team_exercise(self, scenario: str, blue_team_ready: bool = False, 
                            real_time: bool = False) -> ToolResult:
        """Coordinate purple team exercises"""
        return self._send_mcp_request("redteam", "purple_team_exercise", {
            "scenario": scenario,
            "blue_team_ready": blue_team_ready,
            "real_time": real_time
        })
    
    # ===================
    # Business Impact Analysis (Available on all servers)
    # ===================
    
    def analyze_business_impact(self, findings: List[Dict[str, Any]], 
                               asset_context: Dict[str, Any] = None, 
                               server: str = "security") -> ToolResult:
        """Analyze security findings for business impact and risk prioritization"""
        args = {"findings": findings}
        if asset_context:
            args["asset_context"] = asset_context
        return self._send_mcp_request(server, "analyze_business_impact", args)
    
    # ===================
    # Convenience Methods
    # ===================
    
    def comprehensive_domain_assessment(self, domain: str) -> Dict[str, ToolResult]:
        """Perform comprehensive assessment of a domain using multiple tools"""
        results = {}
        
        print(f"Starting comprehensive assessment of {domain}...")
        
        # Security checks
        print("• SSL certificate check...")
        results['ssl'] = self.check_ssl_certificate(domain)
        
        print("• DNS lookup...")
        results['dns'] = self.dns_lookup(domain)
        
        print("• WHOIS lookup...")
        results['whois'] = self.whois_lookup(domain)
        
        print(f"• Security headers check...")
        results['headers'] = self.analyze_security_headers(f"https://{domain}")
        
        # ASM checks
        print("• Subdomain discovery...")
        results['subdomains'] = self.discover_subdomains(domain)
        
        print("• Technology identification...")
        results['tech'] = self.identify_technologies(f"https://{domain}")
        
        print("• Attack surface mapping...")
        results['attack_surface'] = self.map_attack_surface(domain)
        
        print("Assessment complete!")
        return results
    
    def quick_security_check(self, url: str) -> Dict[str, ToolResult]:
        """Quick security assessment of a URL"""
        results = {}
        
        print(f"Quick security check of {url}...")
        
        # Extract domain from URL
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = parsed.hostname
        
        results['ssl'] = self.check_ssl_certificate(domain)
        results['headers'] = self.analyze_security_headers(url)
        results['dns'] = self.dns_lookup(domain)
        
        return results

def print_result(tool_name: str, result: ToolResult):
    """Pretty print tool result"""
    print(f"\n{'='*60}")
    print(f"🔧 {tool_name}")
    print(f"{'='*60}")
    print(f"Server: {result.server}")
    print(f"Success: {'✅' if result.success else '❌'}")
    print(f"Execution Time: {result.execution_time:.2f}s" if result.execution_time else "N/A")
    
    if result.success:
        print("📊 Results:")
        if isinstance(result.data, dict):
            for key, value in result.data.items():
                if isinstance(value, (list, dict)):
                    print(f"  {key}: {len(value) if isinstance(value, list) else 'Object'}")
                else:
                    print(f"  {key}: {value}")
        else:
            print(f"  {result.data}")
    else:
        print(f"❌ Error: {result.error}")

def interactive_menu():
    """Interactive menu for testing tools"""
    client = SecurityToolsClient()
    
    while True:
        print("\n" + "="*60)
        print("🛡️  MCP Security Tools Client - Interactive Mode")
        print("="*60)
        print("1. Security Tools")
        print("2. Attack Surface Management")
        print("3. Penetration Testing")
        print("4. Red Team Operations")
        print("5. Comprehensive Domain Assessment")
        print("6. Quick Security Check")
        print("7. List Available Tools")
        print("8. Exit")
        print("-"*60)
        
        choice = input("Select option (1-8): ").strip()
        
        try:
            if choice == "1":
                security_menu(client)
            elif choice == "2":
                asm_menu(client)
            elif choice == "3":
                pentest_menu(client)
            elif choice == "4":
                redteam_menu(client)
            elif choice == "5":
                domain = input("Enter domain to assess: ").strip()
                if domain:
                    results = client.comprehensive_domain_assessment(domain)
                    print(f"\nAssessment completed! Found {len([r for r in results.values() if r.success])} successful checks.")
            elif choice == "6":
                url = input("Enter URL to check: ").strip()
                if url:
                    results = client.quick_security_check(url)
                    for name, result in results.items():
                        print_result(name, result)
            elif choice == "7":
                tools = client.list_tools()
                for server, tool_list in tools.items():
                    print(f"\n{server.upper()} ({len(tool_list)} tools):")
                    for tool in tool_list:
                        print(f"  • {tool}")
            elif choice == "8":
                print("Closing connections...")
                client.close()
                print("Goodbye!")
                break
            else:
                print("Invalid choice. Please select 1-8.")
        except KeyboardInterrupt:
            print("\nOperation cancelled.")
        except Exception as e:
            print(f"Error: {e}")

def security_menu(client: SecurityToolsClient):
    """Security tools submenu"""
    print("\n🔒 Security Tools:")
    print("1. SSL Certificate Check")
    print("2. CVE Database Query") 
    print("3. Security Headers Analysis")
    print("4. DNS Lookup")
    print("5. WHOIS Lookup")
    print("6. Breach Database Check")
    
    choice = input("Select (1-6): ").strip()
    
    if choice == "1":
        domain = input("Enter domain: ").strip()
        if domain:
            result = client.check_ssl_certificate(domain)
            print_result("SSL Certificate Check", result)
    elif choice == "2":
        keyword = input("Enter CVE ID or keyword (or press Enter for recent): ").strip()
        if keyword:
            result = client.query_cve_database(keyword=keyword if not keyword.startswith("CVE-") else None,
                                             cve_id=keyword if keyword.startswith("CVE-") else None)
        else:
            result = client.query_cve_database(last_n_days=7)
        print_result("CVE Database Query", result)
    elif choice == "3":
        url = input("Enter URL: ").strip()
        if url:
            result = client.analyze_security_headers(url)
            print_result("Security Headers Analysis", result)
    elif choice == "4":
        domain = input("Enter domain: ").strip()
        record_type = input("Record type (A, AAAA, MX, TXT) [A]: ").strip() or "A"
        if domain:
            result = client.dns_lookup(domain, record_type)
            print_result("DNS Lookup", result)
    elif choice == "5":
        domain = input("Enter domain: ").strip()
        if domain:
            result = client.whois_lookup(domain)
            print_result("WHOIS Lookup", result)
    elif choice == "6":
        email = input("Enter email (optional): ").strip() or None
        domain = input("Enter domain (optional): ").strip() or None
        if email or domain:
            result = client.check_breach_database(email=email, domain=domain)
            print_result("Breach Database Check", result)

def asm_menu(client: SecurityToolsClient):
    """ASM tools submenu"""
    print("\n🔍 Attack Surface Management:")
    print("1. Subdomain Discovery")
    print("2. Attack Surface Mapping")
    print("3. Technology Identification")
    print("4. Exposed Services Detection")
    print("5. API Endpoint Enumeration")
    
    choice = input("Select (1-5): ").strip()
    
    if choice == "1":
        domain = input("Enter domain: ").strip()
        if domain:
            result = client.discover_subdomains(domain)
            print_result("Subdomain Discovery", result)
    elif choice == "2":
        domain = input("Enter domain: ").strip()
        if domain:
            result = client.map_attack_surface(domain)
            print_result("Attack Surface Mapping", result)
    elif choice == "3":
        url = input("Enter URL: ").strip()
        if url:
            result = client.identify_technologies(url)
            print_result("Technology Identification", result)
    elif choice == "4":
        domain = input("Enter domain: ").strip()
        if domain:
            result = client.find_exposed_services(domain=domain)
            print_result("Exposed Services Detection", result)
    elif choice == "5":
        base_url = input("Enter base URL: ").strip()
        if base_url:
            result = client.enumerate_api_endpoints(base_url)
            print_result("API Endpoint Enumeration", result)

def pentest_menu(client: SecurityToolsClient):
    """Pentest tools submenu"""
    print("\n🔓 Penetration Testing:")
    print("1. Vulnerability Scan")
    print("2. Fuzzing Test")
    print("3. Web Shell Detection")
    print("4. Privilege Escalation Check")
    
    choice = input("Select (1-4): ").strip()
    
    if choice == "1":
        target = input("Enter target: ").strip()
        if target:
            result = client.vulnerability_scan(target)
            print_result("Vulnerability Scan", result)
    elif choice == "2":
        target_url = input("Enter target URL: ").strip()
        if target_url:
            result = client.fuzzing_test(target_url)
            print_result("Fuzzing Test", result)
    elif choice == "3":
        target_dir = input("Enter target directory: ").strip()
        if target_dir:
            result = client.web_shell_detector(target_dir)
            print_result("Web Shell Detection", result)
    elif choice == "4":
        target_os = input("Target OS (linux/windows) [linux]: ").strip() or "linux"
        result = client.privilege_escalation_check(target_os)
        print_result("Privilege Escalation Check", result)

def redteam_menu(client: SecurityToolsClient):
    """Red team tools submenu"""
    print("\n🎯 Red Team Operations:")
    print("1. Phishing Campaign Simulation")
    print("2. Payload Generation")
    print("3. C2 Infrastructure Setup")
    print("4. MITRE ATT&CK Simulation")
    print("5. Purple Team Exercise")
    
    choice = input("Select (1-5): ").strip()
    
    if choice == "1":
        campaign_type = input("Campaign type (credential_harvesting/malware_delivery) [credential_harvesting]: ").strip() or "credential_harvesting"
        result = client.phishing_campaign(campaign_type=campaign_type)
        print_result("Phishing Campaign Simulation", result)
    elif choice == "2":
        payload_type = input("Payload type (reverse_shell/beacon/implant): ").strip()
        if payload_type:
            result = client.generate_payload(payload_type)
            print_result("Payload Generation", result)
    elif choice == "3":
        infra_type = input("Infrastructure type (http/https/dns) [http]: ").strip() or "http"
        result = client.c2_infrastructure(infra_type)
        print_result("C2 Infrastructure Setup", result)
    elif choice == "4":
        tactic = input("Enter MITRE ATT&CK tactic: ").strip()
        if tactic:
            technique_id = input("Enter technique ID (optional): ").strip() or None
            result = client.mitre_attack_simulation(tactic, technique_id)
            print_result("MITRE ATT&CK Simulation", result)
    elif choice == "5":
        scenario = input("Exercise scenario (ransomware/apt): ").strip()
        if scenario:
            result = client.purple_team_exercise(scenario)
            print_result("Purple Team Exercise", result)

def main():
    """Main function - choose between examples or interactive mode"""
    print("🛡️ MCP Security Tools Client")
    print("="*50)
    print("1. Run Examples")
    print("2. Interactive Mode")
    print("3. Exit")
    
    choice = input("Select mode (1-3): ").strip()
    
    if choice == "1":
        run_examples()
    elif choice == "2":
        interactive_menu()
    elif choice == "3":
        print("Goodbye!")
    else:
        print("Invalid choice")

def run_examples():
    """Run example demonstrations"""
    print("\n🛡️ MCP Security Tools Client - Examples")
    print("="*60)
    
    # Initialize client
    client = SecurityToolsClient()
    
    try:
        # Example 1: Basic Security Check
        print("\n📋 Example 1: Basic Security Checks")
        print("-"*40)
        
        domain = "github.com"
        print(f"Checking SSL certificate for {domain}...")
        ssl_result = client.check_ssl_certificate(domain)
        print_result("SSL Certificate Check", ssl_result)
        
        print(f"\nAnalyzing security headers for https://{domain}...")
        headers_result = client.analyze_security_headers(f"https://{domain}")
        print_result("Security Headers Analysis", headers_result)
        
        # Example 2: DNS Analysis
        print(f"\n📋 Example 2: DNS Analysis")
        print("-"*40)
        
        dns_result = client.dns_lookup(domain, "A")
        print_result("DNS A Record Lookup", dns_result)
        
        whois_result = client.whois_lookup(domain)
        print_result("WHOIS Lookup", whois_result)
        
        # Example 3: Attack Surface Management
        print(f"\n📋 Example 3: Attack Surface Discovery") 
        print("-"*40)
        
        subdomain_result = client.discover_subdomains("example.com")
        print_result("Subdomain Discovery", subdomain_result)
        
        tech_result = client.identify_technologies("https://example.com")
        print_result("Technology Identification", tech_result)
        
        # Example 4: Comprehensive Assessment
        print(f"\n📋 Example 4: Comprehensive Assessment")
        print("-"*40)
        
        assessment_results = client.quick_security_check("https://example.com")
        print(f"\nQuick Security Assessment Results:")
        for check_name, result in assessment_results.items():
            status = "✅ Pass" if result.success else "❌ Fail"
            print(f"  {check_name}: {status}")
        
        print("\n✅ Examples completed successfully!")
        
    except Exception as e:
        print(f"\n❌ Error running examples: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Always close connections
        client.close()

if __name__ == "__main__":
    # For testing purposes, run examples if no interactive terminal
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "examples":
        run_examples()
    elif len(sys.argv) > 1 and sys.argv[1] == "test":
        # Quick test mode
        print("🧪 Testing basic client functionality...")
        client = SecurityToolsClient()
        print(f"✅ Client initialized successfully")
        print(f"📋 Available servers: {list(client.servers.keys())}")
        print(f"🔧 Total tools: {sum(len(tools) for tools in client.list_tools().values())}")
        client.close()
        print("✅ Test completed successfully!")
    else:
        main()
