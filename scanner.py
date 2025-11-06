#!/usr/bin/env python3
import argparse
import sys
from core.sql_injection import SQLInjectionScanner
from core.xss_scanner import XSSScanner
from core.csrf_detector import CSRFDetector
from core.security_headers import SecurityHeadersScanner
from utils.http_client import HTTPClient
from utils.report_generator import ReportGenerator

class WebSecurityScanner:
    def __init__(self):
        self.sql_scanner = SQLInjectionScanner()
        self.xss_scanner = XSSScanner()
        self.csrf_detector = CSRFDetector()
        self.headers_scanner = SecurityHeadersScanner()
        self.http_client = HTTPClient()
        self.report_generator = ReportGenerator()
    
    def scan_url(self, url):
        print(f"Scanning: {url}")
        vulnerabilities = []
        
        # Perform scans
        try:
            response = self.http_client.get(url)
            
            # SQL Injection Scan
            sql_vulns = self.sql_scanner.scan(url)
            vulnerabilities.extend(sql_vulns)
            
            # XSS Scan
            xss_vulns = self.xss_scanner.scan(url, response.text)
            vulnerabilities.extend(xss_vulns)
            
            # CSRF Detection
            csrf_vulns = self.csrf_detector.scan(url, response.text)
            vulnerabilities.extend(csrf_vulns)
            
            # Security Headers Scan
            headers_vulns = self.headers_scanner.scan(response.headers)
            vulnerabilities.extend(headers_vulns)
            
        except Exception as e:
            print(f"Error scanning {url}: {e}")
        
        return vulnerabilities

def main():
    parser = argparse.ArgumentParser(description='Web Security Scanner')
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('-o', '--output', help='Output report file')
    parser.add_argument('--format', choices=['html', 'json', 'txt'], 
                       default='html', help='Report format')
    
    args = parser.parse_args()
    
    scanner = WebSecurityScanner()
    vulnerabilities = scanner.scan_url(args.url)
    
    # Generate report
    if args.output:
        scanner.report_generator.generate_report(
            vulnerabilities, args.output, args.format
        )
        print(f"Report saved to: {args.output}")
    else:
        for vuln in vulnerabilities:
            print(f"[{vuln['severity'].upper()}] {vuln['name']} - {vuln['url']}")

if __name__ == "__main__":
    main()
