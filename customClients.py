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