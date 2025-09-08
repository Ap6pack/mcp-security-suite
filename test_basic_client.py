#!/usr/bin/env python3
"""
Basic MCP client for security tools
Based on MCP Integration Guide examples
"""

import json
import subprocess
import asyncio
from typing import Dict, Any

class MCPSecurityClient:
    def __init__(self, server_path: str):
        self.server_path = server_path
        self.process = None
        self._request_id = 0
        
    def _get_next_id(self):
        self._request_id += 1
        return self._request_id
        
    async def start(self):
        """Start the MCP server process"""
        self.process = await asyncio.create_subprocess_exec(
            'python', self.server_path,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        # Initialize connection
        init_response = await self._send_request({
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {}
                },
                "clientInfo": {
                    "name": "mcp-security-basic-client",
                    "version": "1.0.0"
                }
            },
            "id": self._get_next_id()
        })
        
        if init_response.get("result"):
            # Send initialized notification
            await self._send_notification({
                "jsonrpc": "2.0",
                "method": "notifications/initialized"
            })
            return True
        return False
        
    async def _send_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Send JSON-RPC request and get response"""
        request_str = json.dumps(request) + '\n'
        self.process.stdin.write(request_str.encode())
        await self.process.stdin.drain()
        
        response_line = await self.process.stdout.readline()
        return json.loads(response_line.decode())
    
    async def _send_notification(self, notification: Dict[str, Any]):
        """Send JSON-RPC notification (no response expected)"""
        notification_str = json.dumps(notification) + '\n'
        self.process.stdin.write(notification_str.encode())
        await self.process.stdin.drain()
    
    async def list_tools(self) -> list:
        """Get available tools from the server"""
        response = await self._send_request({
            "jsonrpc": "2.0",
            "method": "tools/list",
            "id": self._get_next_id()
        })
        return response.get("result", [])
    
    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Call a specific tool with arguments"""
        response = await self._send_request({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments
            },
            "id": self._get_next_id()
        })
        
        if "result" in response:
            result_data = response["result"]
            # Extract content from MCP format
            if isinstance(result_data, dict) and "content" in result_data:
                content_list = result_data["content"]
                if content_list and len(content_list) > 0:
                    text_content = content_list[0].get("text", "{}")
                    try:
                        return json.loads(text_content)
                    except json.JSONDecodeError:
                        return {"raw_response": text_content}
            return result_data
        elif "error" in response:
            return {"error": response["error"]}
        return {"error": "Unknown response format"}
    
    async def close(self):
        """Close the MCP server process"""
        if self.process:
            self.process.terminate()
            await self.process.wait()

# Example usage functions
async def check_ssl_certificate(client: MCPSecurityClient, domain: str):
    """Example: Check SSL certificate for a domain"""
    return await client.call_tool("check_ssl_certificate", {"domain": domain})

async def dns_lookup(client: MCPSecurityClient, domain: str, record_type: str = "A"):
    """Example: Perform DNS lookup"""
    return await client.call_tool("dns_lookup", {"domain": domain, "record_type": record_type})

async def discover_subdomains(client: MCPSecurityClient, domain: str):
    """Example: Discover subdomains"""
    return await client.call_tool("discover_subdomains", {"domain": domain})

# Demo function
async def demo_basic_client():
    """Demonstrate basic client usage"""
    print("🔍 Basic MCP Security Client Demo")
    print("="*50)
    
    # Test with security server
    client = MCPSecurityClient("security_server.py")
    
    try:
        print("Starting MCP server...")
        if await client.start():
            print("✅ Connected successfully")
            
            # List available tools
            tools = await client.list_tools()
            print(f"📋 Available tools: {len(tools)}")
            
            # Test SSL certificate check
            print("\n🔒 Testing SSL certificate check...")
            ssl_result = await check_ssl_certificate(client, "github.com")
            if "error" not in ssl_result:
                print(f"✅ SSL check successful: {ssl_result.get('domain', 'Unknown')}")
            else:
                print(f"❌ SSL check failed: {ssl_result['error']}")
            
            # Test DNS lookup
            print("\n🌐 Testing DNS lookup...")
            dns_result = await dns_lookup(client, "github.com")
            if "error" not in dns_result:
                print(f"✅ DNS lookup successful: Found {len(dns_result.get('records', []))} records")
            else:
                print(f"❌ DNS lookup failed: {dns_result['error']}")
        else:
            print("❌ Failed to connect to MCP server")
    
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        await client.close()
        print("🔒 Connection closed")

if __name__ == "__main__":
    asyncio.run(demo_basic_client())