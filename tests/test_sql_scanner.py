#!/usr/bin/env python3
import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.sql_injection import SQLInjectionScanner
from utils.http_client import HTTPClient

def test_sql_scanner():
    """Test the enhanced SQL injection scanner"""
    http_client = HTTPClient()
    scanner = SQLInjectionScanner(http_client)
    
    # Test with a safe URL
    test_url = "https://httpbin.org/html"
    
    print("Testing SQL Injection Scanner with:", test_url)
    vulnerabilities = scanner.scan(test_url)
    
    print(f"\nFound {len(vulnerabilities)} SQL injection vulnerabilities:")
    for vuln in vulnerabilities:
        print(f" - {vuln['point']}")
        print(f"   Payload: {vuln['payload']}")

if __name__ == "__main__":
    test_sql_scanner()
