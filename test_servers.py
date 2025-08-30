#!/usr/bin/env python3
"""
Test script to verify MCP servers can start properly
"""

import subprocess
import time
import sys

def test_server(server_name, server_file):
    """Test if a server can start without errors"""
    print(f"\nTesting {server_name}...")
    
    try:
        # Start the server process
        process = subprocess.Popen(
            [sys.executable, server_file],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Give it a moment to start
        time.sleep(2)
        
        # Check if process is still running
        if process.poll() is None:
            print(f"✓ {server_name} started successfully")
            # Terminate the process
            process.terminate()
            process.wait()
            return True
        else:
            # Process ended, check for errors
            stdout, stderr = process.communicate()
            print(f"✗ {server_name} failed to start")
            if stderr:
                print(f"  Error: {stderr}")
            return False
            
    except Exception as e:
        print(f"✗ {server_name} failed with exception: {e}")
        return False

def main():
    """Test all MCP servers"""
    servers = [
        ("Security Server", "security_server.py"),
        ("ASM Server", "asm_server.py"),
        ("Pentest Server", "pentest_server.py"),
        ("Red Team Server", "redteam_server.py")
    ]
    
    print("MCP Security Tools - Server Test")
    print("=" * 40)
    
    results = []
    for server_name, server_file in servers:
        result = test_server(server_name, server_file)
        results.append((server_name, result))
    
    print("\n" + "=" * 40)
    print("Test Summary:")
    print("-" * 40)
    
    passed = 0
    for server_name, result in results:
        status = "PASS" if result else "FAIL"
        print(f"{server_name}: {status}")
        if result:
            passed += 1
    
    print("-" * 40)
    print(f"Total: {passed}/{len(servers)} servers passed")
    
    if passed == len(servers):
        print("\n✓ All servers are working properly!")
        print("\nYou can now:")
        print("1. Move claude_desktop_config.json to the appropriate Claude config directory")
        print("2. Use custom_client.py to interact with the servers programmatically")
        print("3. Or use the servers directly with Claude Desktop")
    else:
        print("\n✗ Some servers failed. Please check the errors above.")

if __name__ == "__main__":
    main()
