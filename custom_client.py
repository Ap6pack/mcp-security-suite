#!/usr/bin/env python3
"""
Custom MCP Client Example
Shows how to interact with MCP servers programmatically
"""

import subprocess
import json
import sys
import time

def send_mcp_request(server_script, method, tool_name, arguments):
    """
    Send a request to an MCP server and get the response
    
    Args:
        server_script: Path to the MCP server script
        method: MCP method (e.g., "tools/call")
        tool_name: Name of the tool to call
        arguments: Dictionary of arguments for the tool
    
    Returns:
        Response from the MCP server
    """
    # Start MCP server
    process = subprocess.Popen(
        ["python", server_script],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    # Create JSON-RPC request
    request = {
        "jsonrpc": "2.0",
        "method": method,
        "params": {
            "name": tool_name,
            "arguments": arguments
        },
        "id": 1
    }
    
    try:
        # Send request
        process.stdin.write(json.dumps(request) + '\n')
        process.stdin.flush()
        
        # Read response
        response_line = process.stdout.readline()
        if response_line:
            response = json.loads(response_line)
            return response
        else:
            # Check for errors
            error = process.stderr.read()
            if error:
                return {"error": f"Server error: {error}"}
            return {"error": "No response from server"}
            
    except Exception as e:
        return {"error": f"Client error: {str(e)}"}
    finally:
        # Clean up
        process.terminate()
        process.wait()

def main():
    """Example usage of the MCP client"""
    
    print("MCP Security Tools Client Example\n")
    
    # Example 1: Check SSL Certificate
    print("1. Checking SSL certificate for github.com...")
    response = send_mcp_request(
        "security_server.py",
        "tools/call",
        "check_ssl_certificate",
        {"domain": "github.com"}
    )
    print(f"Response: {json.dumps(response, indent=2)}\n")
    
    # Example 2: DNS Lookup
    print("2. Performing DNS lookup for example.com...")
    response = send_mcp_request(
        "security_server.py",
        "tools/call",
        "dns_lookup",
        {"domain": "example.com", "record_type": "A"}
    )
    print(f"Response: {json.dumps(response, indent=2)}\n")
    
    # Example 3: Security Headers Analysis
    print("3. Analyzing security headers for https://example.com...")
    response = send_mcp_request(
        "security_server.py",
        "tools/call",
        "analyze_security_headers",
        {"url": "https://example.com"}
    )
    print(f"Response: {json.dumps(response, indent=2)}\n")

if __name__ == "__main__":
    main()
