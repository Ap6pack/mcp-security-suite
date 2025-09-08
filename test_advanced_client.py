#!/usr/bin/env python3
"""
Test script for the advanced MCP client using FastMCP
Based on MCP Integration Guide examples
"""

import asyncio
from advanced_client import AdvancedSecurityClient

async def test_advanced_client():
    """Test the advanced FastMCP-based client"""
    print("🧪 Testing Advanced MCP Client (FastMCP)")
    print("="*50)
    
    client = AdvancedSecurityClient()
    
    try:
        # Test connection to security server
        print("🔌 Connecting to security server...")
        await client.connect(['security'])
        
        if 'security' not in client.connected_clients:
            print("❌ Failed to connect to security server")
            return False
        
        print("✅ Connected successfully to security server")
        
        # Test tool listing
        print("\n📋 Listing available tools...")
        tools = await client.list_all_tools()
        security_tools = tools.get('security', [])
        print(f"✅ Found {len(security_tools)} security tools")
        
        # Test SSL certificate check
        print("\n🔍 Testing SSL certificate check...")
        ssl_result = await client.call_tool('security', 'check_ssl_certificate', {'domain': 'github.com'})
        
        if ssl_result.success:
            print(f"✅ SSL check successful")
            print(f"   Execution time: {ssl_result.execution_time:.2f}s")
            if ssl_result.data:
                domain = ssl_result.data.get('domain', 'Unknown')
                issuer = ssl_result.data.get('issuer', {})
                org_name = issuer.get('organizationName', 'Unknown') if isinstance(issuer, dict) else 'Unknown'
                print(f"   Domain: {domain}")
                print(f"   Issuer: {org_name}")
        else:
            print(f"❌ SSL check failed: {ssl_result.error}")
            return False
        
        # Test batch processing
        print("\n📦 Testing batch SSL checks...")
        domains = ['github.com', 'google.com']
        batch_results = await client.batch_ssl_check(domains)
        
        successful = 0
        for domain, result in batch_results.items():
            if result.success:
                successful += 1
                print(f"   ✅ {domain}: Success ({result.execution_time:.2f}s)")
            else:
                print(f"   ❌ {domain}: Failed - {result.error}")
        
        print(f"📊 Batch results: {successful}/{len(domains)} successful")
        
        print(f"\n🎉 Advanced client test completed successfully!")
        return True
        
    except Exception as e:
        print(f"❌ Test failed with exception: {e}")
        import traceback
        traceback.print_exc()
        return False
        
    finally:
        await client.disconnect()
        print("🔒 Disconnected from all servers")

async def test_basic_vs_advanced():
    """Compare basic vs advanced client approaches"""
    print("\n" + "="*60)
    print("🏁 BASIC vs ADVANCED CLIENT COMPARISON")
    print("="*60)
    
    # Test advanced client
    print("\n🚀 Testing Advanced Client (FastMCP)...")
    advanced_success = await test_advanced_client()
    
    if advanced_success:
        print("✅ Advanced client: WORKING")
    else:
        print("❌ Advanced client: FAILED")
    
    # Note about basic client
    print(f"\n📝 Note: Basic client (basic_client.py) available for simpler use cases")
    print(f"📝 Custom client (custom_client.py) provides full production features")

if __name__ == "__main__":
    asyncio.run(test_basic_vs_advanced())