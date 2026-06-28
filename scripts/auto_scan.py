#!/usr/bin/env python3
# ── Auto Scan Script ──
# Run: python scripts/auto_scan.py

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import asyncio
from datetime import datetime
from app.automation import run_automated_scan, send_scan_report

async def main():
    # ── URLs to scan ──
    urls = ['axiler.com', 'polysignals.app']
    
    print(f"\n🚀 Auto Scan Started: {datetime.now()}")
    print("=" * 50)
    
    for url in urls:
        print(f"\n🔍 Scanning: {url}")
        print("-" * 30)
        
        result = await run_automated_scan(url)
        
        if result.get('success'):
            print(f"✅ Scan complete: {url}")
            print(f"📊 Scan ID: {result.get('scan_id')}")
            
            # Send notification
            await send_scan_report(url, result)
        else:
            print(f"❌ Scan failed: {result.get('error')}")
    
    print("\n" + "=" * 50)
    print("✅ Auto Scan Complete!")
    print("=" * 50)

if __name__ == "__main__":
    asyncio.run(main())
