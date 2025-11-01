#!/usr/bin/env python3
"""
Web Security Scanner - Automated vulnerability scanner for web applications
"""

import argparse
import sys
import time
from colorama import Fore, Style, init
from core.sql_injection import SQLInjectionScanner
from core.xss_scanner import XSSScanner
from core.security_headers import SecurityHeadersScanner
from core.csrf_detector import CSRFDetector
from utils.report_generator import ReportGenerator
from utils.http_client import HTTPClient

init(autoreset=True)

class WebSecurityScanner:
    def __init__(self, target_url, output_file=None):
        self.target_url = target_url
        self.output_file = output_file
        self.http_client = HTTPClient()
        self.vulnerabilities = []
        self.scan_results = {}
        
        # Initialize scanners
        self.scanners = {
            'sql_injection': SQLInjectionScanner(self.http_client),
            'xss': XSSScanner(self.http_client),
            'security_headers': SecurityHeadersScanner(self.http_client),
            'csrf': CSRFDetector(self.http_client)
        }
    
    def scan(self):
        """Perform comprehensive security scan"""
        print(f"\n{Fore.CYAN}🔍 Starting Web Security Scan")
        print(f"{Fore.CYAN}{'='*60}")
        print(f"{Fore.WHITE}Target: {Fore.YELLOW}{self.target_url}")
        print(f"{Fore.CYAN}{'-'*60}")
        
        start_time = time.time()
        
        try:
            # Test if target is accessible
            if not self.http_client.test_connection(self.target_url):
                print(f"{Fore.RED}❌ Target is not accessible: {self.target_url}")
                return False
            
            # Run all security scans
            self.scan_results['sql_injection'] = self.scanners['sql_injection'].scan(self.target_url)
            self.scan_results['xss'] = self.scanners['xss'].scan(self.target_url)
            self.scan_results['security_headers'] = self.scanners['security_headers'].scan(self.target_url)
            self.scan_results['csrf'] = self.scanners['csrf'].scan(self.target_url)
            
            # Generate report
            self.generate_report(start_time)
            
            return True
            
        except Exception as e:
            print(f"{Fore.RED}❌ Scan failed: {e}")
            return False
    
    def generate_report(self, start_time):
        """Generate comprehensive scan report"""
        elapsed_time = time.time() - start_time
        
        report_generator = ReportGenerator(
            self.target_url,
            self.scan_results,
            elapsed_time
        )
        
        # Console report
        console_report = report_generator.generate_console_report()
        print(console_report)
        
        # File report
        if self.output_file:
            if self.output_file.endswith('.html'):
                html_report = report_generator.generate_html_report()
                with open(self.output_file, 'w', encoding='utf-8') as f:
                    f.write(html_report)
                print(f"{Fore.GREEN}✅ HTML report saved: {self.output_file}")
            else:
                json_report = report_generator.generate_json_report()
                with open(self.output_file, 'w', encoding='utf-8') as f:
                    f.write(json_report)
                print(f"{Fore.GREEN}✅ JSON report saved: {self.output_file}")

def main():
    parser = argparse.ArgumentParser(description='Web Security Scanner')
    parser.add_argument('target', help='Target URL to scan')
    parser.add_argument('-o', '--output', help='Output file for report (JSON or HTML)')
    parser.add_argument('--sql-only', action='store_true', help='Only perform SQL injection scan')
    parser.add_argument('--xss-only', action='store_true', help='Only perform XSS scan')
    parser.add_argument('--headers-only', action='store_true', help='Only check security headers')
    
    args = parser.parse_args()
    
    scanner = WebSecurityScanner(args.target, args.output)
    scanner.scan()

if __name__ == "__main__":
    main()
