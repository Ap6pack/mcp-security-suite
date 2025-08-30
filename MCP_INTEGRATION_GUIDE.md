# 🔌 MCP Security Suite - Integration Guide

This guide shows how to integrate the MCP Security Suite with various clients and platforms beyond Claude Desktop.

## Table of Contents
- [Understanding MCP](#understanding-mcp)
- [Client Options](#client-options)
- [Custom Python Client](#custom-python-client)
- [Web-Based Interface](#web-based-interface)
- [REST API Gateway](#rest-api-gateway)
- [CI/CD Integration](#cicd-integration)
- [Remote Deployment](#remote-deployment)
- [Protocol Reference](#protocol-reference)
- [Troubleshooting](#troubleshooting)

## Understanding MCP

The Model Context Protocol (MCP) is a standardized protocol for communication between AI applications and external tools. Key features:

- **Language agnostic**: Clients can be written in any language
- **Transport flexible**: Works over stdio, HTTP, WebSocket
- **Tool discovery**: Clients can dynamically discover available tools
- **Type safe**: Tools define input/output schemas

## Client Options

### 1. Claude Desktop (Primary)
- Built-in MCP support
- See [GETTING_STARTED.md](GETTING_STARTED.md) for setup

### 2. Custom Python Client
- Use the included `custom_client.py`
- Build your own using the examples below

### 3. VS Code Extensions
- **Cline**: Full MCP support
- **Continue**: MCP integration available

### 4. Web Interfaces
- Build browser-based dashboards
- WebSocket or HTTP transport

### 5. Mobile Apps
- iOS/Android apps can connect via HTTP
- Real-time security monitoring

## Custom Python Client

### Basic Example

```python
#!/usr/bin/env python3
"""
Basic MCP client for security tools
"""

import json
import subprocess
import asyncio
from typing import Dict, Any

class MCPSecurityClient:
    def __init__(self, server_path: str):
        self.server_path = server_path
        self.process = None
        
    async def start(self):
        """Start the MCP server process"""
        self.process = await asyncio.create_subprocess_exec(
            'python', self.server_path,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        # Initialize connection
        await self._send_request({
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {
                "protocolVersion": "0.1.0",
                "capabilities": {}
            },
            "id": 1
        })
        
    async def _send_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Send JSON-RPC request and get response"""
        request_str = json.dumps(request) + '\n'
        self.process.stdin.write(request_str.encode())
        await self.process.stdin.drain()
        
        response_line = await self.process.stdout.readline()
        return json.loads(response_line.decode())
    
    async def list_tools(self) -> list:
        """Get available tools from the server"""
        response = await self._send_request({
            "jsonrpc": "2.0",
            "method": "tools/list",
            "params": {},
            "id": 2
        })
        return response.get('result', {}).get('tools', [])
    
    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        """Call a specific tool"""
        response = await self._send_request({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments
            },
            "id": 3
        })
        return response.get('result')
    
    async def close(self):
        """Close the connection"""
        if self.process:
            self.process.terminate()
            await self.process.wait()

# Example usage
async def main():
    # Create client
    client = MCPSecurityClient('security_server.py')
    await client.start()
    
    # List available tools
    tools = await client.list_tools()
    print("Available tools:")
    for tool in tools:
        print(f"  - {tool['name']}: {tool['description']}")
    
    # Check SSL certificate
    result = await client.call_tool(
        "check_ssl_certificate",
        {"domain": "github.com"}
    )
    print(f"\nSSL Certificate for github.com:")
    print(json.dumps(result, indent=2))
    
    # Query CVE database
    result = await client.call_tool(
        "query_cve_database",
        {"keyword": "apache", "last_n_days": 30}
    )
    print(f"\nRecent Apache CVEs:")
    print(json.dumps(result, indent=2))
    
    await client.close()

if __name__ == "__main__":
    asyncio.run(main())
```

### Advanced Client with Error Handling

```python
import asyncio
import json
import logging
from typing import Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum

class ToolError(Exception):
    """Tool execution error"""
    pass

class ConnectionError(Exception):
    """MCP connection error"""
    pass

@dataclass
class ToolResult:
    """Structured tool result"""
    success: bool
    data: Any
    error: Optional[str] = None
    
class SecurityToolsClient:
    """Advanced MCP client with error handling and retries"""
    
    def __init__(self, server_path: str, timeout: int = 30):
        self.server_path = server_path
        self.timeout = timeout
        self.process = None
        self.logger = logging.getLogger(__name__)
        self._request_id = 0
        
    async def connect(self, max_retries: int = 3):
        """Connect with retry logic"""
        for attempt in range(max_retries):
            try:
                await self._start_server()
                await self._initialize()
                self.logger.info("Connected to MCP server")
                return
            except Exception as e:
                self.logger.warning(f"Connection attempt {attempt + 1} failed: {e}")
                if attempt < max_retries - 1:
                    await asyncio.sleep(2 ** attempt)  # Exponential backoff
                else:
                    raise ConnectionError(f"Failed to connect after {max_retries} attempts")
    
    async def _start_server(self):
        """Start the server process"""
        self.process = await asyncio.create_subprocess_exec(
            'python', self.server_path,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
    async def _initialize(self):
        """Initialize MCP connection"""
        response = await self._request("initialize", {
            "protocolVersion": "0.1.0",
            "capabilities": {
                "tools": {"listChanged": True}
            }
        })
        
        if "error" in response:
            raise ConnectionError(f"Initialization failed: {response['error']}")
            
    async def _request(self, method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Send request with timeout"""
        self._request_id += 1
        request = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": self._request_id
        }
        
        try:
            # Send request
            request_str = json.dumps(request) + '\n'
            self.process.stdin.write(request_str.encode())
            await self.process.stdin.drain()
            
            # Read response with timeout
            response_line = await asyncio.wait_for(
                self.process.stdout.readline(),
                timeout=self.timeout
            )
            
            return json.loads(response_line.decode())
            
        except asyncio.TimeoutError:
            raise ConnectionError(f"Request timeout for method: {method}")
        except Exception as e:
            raise ConnectionError(f"Request failed: {e}")
    
    async def check_ssl(self, domain: str) -> ToolResult:
        """Check SSL certificate with structured result"""
        try:
            response = await self._request("tools/call", {
                "name": "check_ssl_certificate",
                "arguments": {"domain": domain}
            })
            
            if "error" in response:
                return ToolResult(False, None, response["error"]["message"])
                
            result = response.get("result", [])
            if result and len(result) > 0:
                data = json.loads(result[0]["text"])
                return ToolResult(True, data)
            else:
                return ToolResult(False, None, "No result returned")
                
        except Exception as e:
            return ToolResult(False, None, str(e))
    
    async def scan_attack_surface(self, domain: str, options: Dict[str, Any] = None) -> ToolResult:
        """Comprehensive attack surface scan"""
        default_options = {
            "include_subdomains": True,
            "check_ports": False,
            "identify_tech": True
        }
        
        if options:
            default_options.update(options)
            
        try:
            response = await self._request("tools/call", {
                "name": "map_attack_surface",
                "arguments": {
                    "domain": domain,
                    **default_options
                }
            })
            
            if "error" in response:
                return ToolResult(False, None, response["error"]["message"])
                
            result = response.get("result", [])
            if result and len(result) > 0:
                data = json.loads(result[0]["text"])
                return ToolResult(True, data)
            else:
                return ToolResult(False, None, "No result returned")
                
        except Exception as e:
            return ToolResult(False, None, str(e))
    
    async def batch_operations(self, operations: list) -> list:
        """Execute multiple operations concurrently"""
        tasks = []
        for op in operations:
            if op["type"] == "ssl_check":
                task = self.check_ssl(op["domain"])
            elif op["type"] == "attack_surface":
                task = self.scan_attack_surface(op["domain"], op.get("options"))
            else:
                continue
            tasks.append(task)
            
        return await asyncio.gather(*tasks)
    
    async def close(self):
        """Gracefully close connection"""
        if self.process:
            self.process.terminate()
            await self.process.wait()

# Example: Security Dashboard
async def security_dashboard():
    """Run a security dashboard with multiple checks"""
    client = SecurityToolsClient('security_server.py')
    
    try:
        await client.connect()
        
        # Define targets
        targets = [
            {"type": "ssl_check", "domain": "github.com"},
            {"type": "ssl_check", "domain": "google.com"},
            {"type": "attack_surface", "domain": "example.com", "options": {"check_ports": False}}
        ]
        
        # Run batch operations
        print("🔍 Running security checks...")
        results = await client.batch_operations(targets)
        
        # Display results
        for target, result in zip(targets, results):
            if result.success:
                print(f"\n✅ {target['domain']} - Success")
                if target["type"] == "ssl_check":
                    cert_data = result.data
                    print(f"   Issuer: {cert_data.get('issuer', {}).get('organizationName', 'Unknown')}")
                    print(f"   Expires: {cert_data.get('not_after', 'Unknown')}")
            else:
                print(f"\n❌ {target['domain']} - Failed: {result.error}")
                
    finally:
        await client.close()

if __name__ == "__main__":
    asyncio.run(security_dashboard())
```

## Web-Based Interface

### Flask Web Server Example

```python
from flask import Flask, jsonify, request, render_template_string
import asyncio
import json
from concurrent.futures import ThreadPoolExecutor

app = Flask(__name__)
executor = ThreadPoolExecutor(max_workers=5)

# HTML template
DASHBOARD_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>MCP Security Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .result { margin: 20px 0; padding: 10px; border: 1px solid #ddd; }
        .success { background-color: #d4edda; }
        .error { background-color: #f8d7da; }
        button { padding: 10px 20px; margin: 5px; }
    </style>
</head>
<body>
    <h1>🛡️ MCP Security Dashboard</h1>
    
    <div>
        <h2>SSL Certificate Check</h2>
        <input type="text" id="ssl-domain" placeholder="example.com" />
        <button onclick="checkSSL()">Check SSL</button>
        <div id="ssl-result"></div>
    </div>
    
    <div>
        <h2>CVE Search</h2>
        <input type="text" id="cve-keyword" placeholder="apache" />
        <button onclick="searchCVE()">Search CVEs</button>
        <div id="cve-result"></div>
    </div>
    
    <script>
        async function checkSSL() {
            const domain = document.getElementById('ssl-domain').value;
            const resultDiv = document.getElementById('ssl-result');
            
            resultDiv.innerHTML = 'Loading...';
            
            try {
                const response = await fetch('/api/ssl-check', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({domain: domain})
                });
                
                const data = await response.json();
                
                if (data.success) {
                    resultDiv.innerHTML = `
                        <div class="result success">
                            <h3>✅ SSL Certificate Valid</h3>
                            <p><strong>Domain:</strong> ${data.data.domain}</p>
                            <p><strong>Issuer:</strong> ${JSON.stringify(data.data.issuer)}</p>
                            <p><strong>Expires:</strong> ${data.data.not_after}</p>
                        </div>
                    `;
                } else {
                    resultDiv.innerHTML = `<div class="result error">❌ Error: ${data.error}</div>`;
                }
            } catch (error) {
                resultDiv.innerHTML = `<div class="result error">❌ Error: ${error.message}</div>`;
            }
        }
        
        async function searchCVE() {
            const keyword = document.getElementById('cve-keyword').value;
            const resultDiv = document.getElementById('cve-result');
            
            resultDiv.innerHTML = 'Loading...';
            
            try {
                const response = await fetch('/api/cve-search', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({keyword: keyword})
                });
                
                const data = await response.json();
                
                if (data.success) {
                    let html = '<div class="result success"><h3>CVE Results</h3>';
                    data.data.cves.forEach(cve => {
                        html += `
                            <div style="margin: 10px 0;">
                                <strong>${cve.id}</strong><br>
                                ${cve.description}<br>
                                <small>Severity: ${cve.cvss?.severity || 'Unknown'}</small>
                            </div>
                        `;
                    });
                    html += '</div>';
                    resultDiv.innerHTML = html;
                } else {
                    resultDiv.innerHTML = `<div class="result error">❌ Error: ${data.error}</div>`;
                }
            } catch (error) {
                resultDiv.innerHTML = `<div class="result error">❌ Error: ${error.message}</div>`;
            }
        }
    </script>
</body>
</html>
'''

# MCP client instance
mcp_client = None

async def get_mcp_client():
    """Get or create MCP client"""
    global mcp_client
    if not mcp_client:
        from custom_client import MCPSecurityClient
        mcp_client = MCPSecurityClient('security_server.py')
        await mcp_client.start()
    return mcp_client

@app.route('/')
def dashboard():
    """Serve the dashboard"""
    return render_template_string(DASHBOARD_TEMPLATE)

@app.route('/api/ssl-check', methods=['POST'])
def ssl_check():
    """API endpoint for SSL checking"""
    domain = request.json.get('domain')
    
    async def check():
        client = await get_mcp_client()
        result = await client.call_tool('check_ssl_certificate', {'domain': domain})
        return result
    
    try:
        loop = asyncio.new_event_loop()
        result = loop.run_until_complete(check())
        return jsonify({'success': True, 'data': json.loads(result[0]['text'])})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/cve-search', methods=['POST'])
def cve_search():
    """API endpoint for CVE search"""
    keyword = request.json.get('keyword')
    
    async def search():
        client = await get_mcp_client()
        result = await client.call_tool('query_cve_database', {
            'keyword': keyword,
            'last_n_days': 30
        })
        return result
    
    try:
        loop = asyncio.new_event_loop()
        result = loop.run_until_complete(search())
        return jsonify({'success': True, 'data': json.loads(result[0]['text'])})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

if __name__ == '__main__':
    app.run(debug=True, port=5000)
```

## REST API Gateway

### FastAPI Gateway Example

```python
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import asyncio
from typing import Optional, Dict, Any
import uvicorn

app = FastAPI(title="MCP Security API Gateway")

# Request models
class SSLCheckRequest(BaseModel):
    domain: str

class CVESearchRequest(BaseModel):
    keyword: Optional[str] = None
    cve_id: Optional[str] = None
    last_n_days: Optional[int] = 7

class AttackSurfaceRequest(BaseModel):
    domain: str
    include_subdomains: bool = True
    check_ports: bool = False
    identify_tech: bool = True

# Global MCP client
mcp_client = None

@app.on_event("startup")
async def startup_event():
    """Initialize MCP client on startup"""
    global mcp_client
    from custom_client import MCPSecurityClient
    mcp_client = MCPSecurityClient('security_server.py')
    await mcp_client.start()

@app.on_event("shutdown")
async def shutdown_event():
    """Clean up on shutdown"""
    if mcp_client:
        await mcp_client.close()

@app.get("/")
async def root():
    """API information"""
    return {
        "name": "MCP Security API Gateway",
        "version": "1.0.0",
        "endpoints": [
            "/ssl-check",
            "/cve-search",
            "/attack-surface",
            "/docs"
        ]
    }

@app.post("/ssl-check")
async def check_ssl(request: SSLCheckRequest):
    """Check SSL certificate for a domain"""
    try:
        result = await mcp_client.call_tool(
            "check_ssl_certificate",
            {"domain": request.domain}
        )
        return {"success": True, "data": json.loads(result[0]['text'])}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/cve-search")
async def search_cves(request: CVESearchRequest):
    """Search CVE database"""
    try:
        params = {}
        if request.keyword:
            params["keyword"] = request.keyword
        if request.cve_id:
            params["cve_id"] = request.cve_id
        if request.last_n_days:
            params["last_n_days"] = request.last_n_days
            
        result = await mcp_client.call_tool("query_cve_database", params)
        return {"success": True, "data": json.loads(result[0]['text'])}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/attack-surface")
async def map_attack_surface(request: AttackSurfaceRequest):
    """Map attack surface for a domain"""
    try:
        result = await mcp_client.call_tool(
            "map_attack_surface",
            {
                "domain": request.domain,
                "include_subdomains": request.include_subdomains,
                "check_ports": request.check_ports,
                "identify_tech": request.identify_tech
            }
        )
        return {"success": True, "data": json.loads(result[0]['text'])}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Run with: uvicorn api_gateway:app --reload
```

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Security Scan

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]
  schedule:
    - cron: '0 0 * * 0'  # Weekly scan

jobs:
  security-scan:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.10'
    
    - name: Install MCP Security Suite
      run: |
        git clone https://github.com/Ap6pack/mcp-security-suite.git
        cd mcp-security-suite
        pip install -r requirements.txt
    
    - name: Run Security Scan
      run: |
        python - <<EOF
        import asyncio
        import json
        import sys
        from custom_client import MCPSecurityClient
        
        async def run_scan():
            client = MCPSecurityClient('security_server.py')
            await client.start()
            
            # Check SSL certificates
            domains = ['${{ github.event.repository.homepage }}', 'api.example.com']
            
            for domain in domains:
                if domain:
                    result = await client.call_tool(
                        'check_ssl_certificate',
                        {'domain': domain}
                    )
                    data = json.loads(result[0]['text'])
                    
                    if 'error' in data:
                        print(f"::error::SSL check failed for {domain}: {data['error']}")
                        sys.exit(1)
                    else:
                        print(f"✅ SSL valid for {domain}")
            
            # Search for CVEs related to dependencies
            result = await client.call_tool(
                'query_cve_database',
                {'keyword': 'python', 'last_n_days': 7}
            )
            
            cve_data = json.loads(result[0]['text'])
            if cve_data.get('total_results', 0) > 0:
                print(f"::warning::Found {cve_data['total_results']} recent Python CVEs")
            
            await client.close()
        
        asyncio.run(run_scan())
        EOF
    
    - name: Upload scan results
      uses: actions/upload-artifact@v3
      with:
        name: security-scan-results
        path: scan-results.json
```

### Jenkins Pipeline Example

```groovy
pipeline {
    agent any
    
    stages {
        stage('Setup') {
            steps {
                sh '''
                    python -m venv venv
                    . venv/bin/activate
                    git clone https://github.com/Ap6pack/mcp-security-suite.git
                    cd mcp-security-suite
                    pip install -r requirements.txt
                '''
            }
        }
        
        stage('Security Scan') {
            steps {
                script {
                    def scanScript = '''
                    import asyncio
                    import json
                    from custom_client import MCPSecurityClient
                    
                    async def scan():
                        client = MCPSecurityClient('security_server.py')
                        await client.start()
                        
                        # Your security checks here
                        result = await client.call_tool(
                            'map_attack_surface',
                            {'domain': 'example.com'}
                        )
                        
                        with open('scan-results.json', 'w') as f:
                            json.dump(result, f)
                        
                        await client.close()
                    
                    asyncio.run(scan())
                    '''
                    
                    sh """
                        . venv/bin/activate
                        cd mcp-security-suite
                        python -c "${scanScript}"
                    """
                }
            }
        }
        
        stage('Analyze Results') {
            steps {
                script {
                    def results = readJSON file: 'mcp-security-suite/scan-results.json'
                    
                    if (results.vulnerabilities?.size() > 0) {
                        currentBuild.result = 'UNSTABLE'
                        echo "Found ${results.vulnerabilities.size()} vulnerabilities"
                    }
                }
            }
        }
    }
    
    post {
        always {
            archiveArtifacts artifacts: '**/scan-results.json', fingerprint: true
        }
    }
}
```

## Remote Deployment

### Docker Deployment

```dockerfile
# Dockerfile
FROM python:3.10-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy MCP servers
COPY *.py .

# Expose port for API gateway
EXPOSE 8000

# Run API gateway by default
CMD ["uvicorn", "api_gateway:app", "--host", "0.0.0.0", "--port", "8000"]
```

### Docker Compose

```yaml
version: '3.8'

services:
  mcp-security:
    build: .
    ports:
      - "8000:8000"
    environment:
      - HIBP_API_KEY=${HIBP_API_KEY}
      - SHODAN_API_KEY=${SHODAN_API_KEY}
      - VT_API_KEY=${VT_API_KEY}
    volumes:
      - ./logs:/app/logs
    restart: unless-stopped
    
  nginx:
    image: nginx:alpine
    ports:
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./certs:/etc/nginx/certs
    depends_on:
      - mcp-security
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mcp-security-suite
spec:
  replicas: 3
  selector:
    matchLabels:
      app: mcp-security
  template:
    metadata:
      labels:
        app: mcp-security
    spec:
      containers:
      - name: mcp-security
        image: your-registry/mcp-security:latest
        ports:
        - containerPort: 8000
        env:
        - name: HIBP_API_KEY
          valueFrom:
            secretKeyRef:
              name: mcp-secrets
              key: hibp-api-key
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
---
apiVersion: v1
kind: Service
metadata:
  name: mcp-security-service
spec:
  selector:
    app: mcp-security
  ports:
    - protocol: TCP
      port: 80
      targetPort: 8000
  type: LoadBalancer
```

## Protocol Reference

### JSON-RPC Messages

#### Initialize
```json
{
  "jsonrpc": "2.0",
  "method": "initialize",
  "params": {
    "protocolVersion": "0.1.0",
    "capabilities": {
      "tools": {"listChanged": true}
    }
  },
  "id": 1
}
```

#### List Tools
```json
{
  "jsonrpc": "2.0",
  "method": "tools/list",
  "params": {},
  "id": 2
}
```

#### Call Tool
```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "check_ssl_certificate",
    "arguments": {
      "domain": "example.com"
    }
  },
  "id": 3
}
```

### Response Format
```json
{
  "jsonrpc": "2.0",
  "result": [
    {
      "type": "text",
      "text": "{\"domain\": \"example.com\", \"issuer\": {...}}"
    }
  ],
  "id": 3
}
```

## Troubleshooting

### Common Issues

#### 1. Connection Timeouts
```python
# Increase timeout in client
client = MCPSecurityClient('security_server.py', timeout=60)
```

#### 2. Process Management
```python
# Ensure proper cleanup
try:
    await client.start()
    # ... operations ...
finally:
    await client.close()
```

#### 3. Debugging
```python
# Enable debug logging
import logging
logging.basicConfig(level=logging.DEBUG)

# Log all JSON-RPC messages
class DebugClient(MCPSecurityClient):
    async def _send_request(self, request):
        self.logger.debug(f"Request: {json.dumps(request)}")
        response = await super()._send_request(request)
        self.logger.debug(f"Response: {json.dumps(response)}")
        return response
```

#### 4. Error Handling
```python
# Comprehensive error handling
try:
    result = await client.call_tool("check_ssl_certificate", {"domain": domain})
except ConnectionError as e:
    print(f"Connection error: {e}")
    # Retry logic
except ToolError as e:
    print(f"Tool error: {e}")
    # Handle tool-specific errors
except Exception as e:
    print(f"Unexpected error: {e}")
    # Generic error handling
```

## Best Practices

1. **Connection Management**
   - Reuse connections when possible
   - Implement connection pooling for high-traffic applications
   - Always close connections properly

2. **Error Handling**
   - Implement retry logic with exponential backoff
   - Log errors for debugging
   - Provide meaningful error messages to users

3. **Security**
   - Never expose MCP servers directly to the internet
   - Use API gateways with authentication
   - Implement rate limiting to prevent abuse
   - Use TLS for network transport
   - Validate all inputs before passing to tools

4. **Performance**
   - Use async operations for concurrent requests
   - Implement caching for frequently accessed data
   - Monitor resource usage and scale accordingly

5. **Monitoring**
   - Log all tool invocations for audit trails
   - Track performance metrics
   - Set up alerts for failures

## Example: Production-Ready Client

```python
import asyncio
import json
import logging
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
import aioredis
from prometheus_client import Counter, Histogram, start_http_server

# Metrics
TOOL_CALLS = Counter('mcp_tool_calls_total', 'Total MCP tool calls', ['tool', 'status'])
TOOL_DURATION = Histogram('mcp_tool_duration_seconds', 'MCP tool call duration', ['tool'])

class ProductionMCPClient:
    """Production-ready MCP client with caching, metrics, and error handling"""
    
    def __init__(self, server_path: str, redis_url: str = None):
        self.server_path = server_path
        self.redis_url = redis_url
        self.redis = None
        self.process = None
        self.logger = logging.getLogger(__name__)
        
    async def initialize(self):
        """Initialize client with all dependencies"""
        # Start metrics server
        start_http_server(8000)
        
        # Connect to Redis for caching
        if self.redis_url:
            self.redis = await aioredis.create_redis_pool(self.redis_url)
        
        # Start MCP server
        await self.connect()
        
    async def call_tool_with_cache(
        self, 
        tool_name: str, 
        arguments: Dict[str, Any],
        cache_ttl: int = 300
    ) -> Any:
        """Call tool with caching support"""
        # Generate cache key
        cache_key = f"mcp:{tool_name}:{json.dumps(arguments, sort_keys=True)}"
        
        # Check cache
        if self.redis:
            cached = await self.redis.get(cache_key)
            if cached:
                self.logger.info(f"Cache hit for {tool_name}")
                return json.loads(cached)
        
        # Call tool with metrics
        with TOOL_DURATION.labels(tool=tool_name).time():
            try:
                result = await self.call_tool(tool_name, arguments)
                TOOL_CALLS.labels(tool=tool_name, status='success').inc()
                
                # Cache result
                if self.redis and result:
                    await self.redis.setex(
                        cache_key, 
                        cache_ttl, 
                        json.dumps(result)
                    )
                
                return result
                
            except Exception as e:
                TOOL_CALLS.labels(tool=tool_name, status='error').inc()
                self.logger.error(f"Tool call failed: {tool_name} - {e}")
                raise
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check"""
        health = {
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'checks': {}
        }
        
        # Check MCP server
        try:
            tools = await self.list_tools()
            health['checks']['mcp_server'] = {
                'status': 'up',
                'tools_count': len(tools)
            }
        except Exception as e:
            health['status'] = 'unhealthy'
            health['checks']['mcp_server'] = {
                'status': 'down',
                'error': str(e)
            }
        
        # Check Redis
        if self.redis:
            try:
                await self.redis.ping()
                health['checks']['redis'] = {'status': 'up'}
            except Exception as e:
                health['checks']['redis'] = {
                    'status': 'down',
                    'error': str(e)
                }
        
        return health
```

## Conclusion

The MCP Security Suite is designed to be flexible and integrate with any MCP-compatible client. Whether you're using:

- **Claude Desktop** for interactive security analysis
- **Custom Python clients** for automation
- **Web dashboards** for team collaboration
- **CI/CD pipelines** for continuous security monitoring
- **REST APIs** for enterprise integration

The standardized MCP protocol ensures your security tools work consistently across all platforms.

### Next Steps

1. **Start Simple**: Use the basic Python client examples to understand MCP
2. **Build Custom Integrations**: Create clients tailored to your workflow
3. **Deploy at Scale**: Use the Docker/Kubernetes examples for production
4. **Contribute**: Share your integrations with the community

### Resources

- [MCP Specification](https://modelcontextprotocol.io/docs)
- [MCP Security Suite GitHub](https://github.com/Ap6pack/mcp-security-suite)
- [Example Integrations](https://github.com/Ap6pack/mcp-security-suite/examples)

Remember: The power of MCP is in its flexibility. These security tools can be integrated into any workflow or platform that speaks the Model Context Protocol!
