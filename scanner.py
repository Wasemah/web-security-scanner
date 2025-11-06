#!/usr/bin/env python3
"""
Web Security Scanner - Automated vulnerability scanner for web applications
"""

import argparse
import sys
import time
import json
from colorama import Fore, Style, init
from core.sql_injection import SQLInjectionScanner
from core.xss_scanner import XSSScanner
from core.security_headers import SecurityHeadersScanner
from core.csrf_detector import CSRFDetector
from utils.report_generator import ReportGenerator
from utils.http_client import HTTPClient

init(autoreset=True)

class WebSecurityScanner:
    def __init__(self, target_url, output_file=None, verbose=False):
        self.target_url = target_url.rstrip('/')
        self.output_file = output_file
        self.verbose = verbose
        self.http_client = HTTPClient(verbose=verbose)
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
            print(f"\n{Fore.BLUE}[1/4] Scanning for SQL Injection...")
            self.scan_results['sql_injection'] = self.scanners['sql_injection'].scan(self.target_url)
            
            print(f"\n{Fore.BLUE}[2/4] Scanning for XSS Vulnerabilities...")
            self.scan_results['xss'] = self.scanners['xss'].scan(self.target_url)
            
            print(f"\n{Fore.BLUE}[3/4] Checking Security Headers...")
            self.scan_results['security_headers'] = self.scanners['security_headers'].scan(self.target_url)
            
            print(f"\n{Fore.BLUE}[4/4] Checking CSRF Protection...")
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
        
        # Console report
        self.generate_console_report(elapsed_time)
        
        # File report
        if self.output_file:
            self.generate_file_report(elapsed_time)
    
    def generate_console_report(self, elapsed_time):
        """Generate console-friendly report"""
        print(f"\n{Fore.CYAN}📊 SCAN REPORT")
        print(f"{Fore.CYAN}{'='*50}")
        print(f"{Fore.WHITE}Target: {Fore.YELLOW}{self.target_url}")
        print(f"{Fore.WHITE}Scan Time: {Fore.YELLOW}{elapsed_time:.2f} seconds")
        print(f"{Fore.WHITE}Date: {Fore.YELLOW}{time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{Fore.CYAN}{'-'*50}")
        
        total_vulnerabilities = 0
        for scan_type, results in self.scan_results.items():
            count = len(results)
            total_vulnerabilities += count
            
            status_color = Fore.RED if count > 0 else Fore.GREEN
            status_icon = "❌" if count > 0 else "✅"
            
            scan_name = scan_type.replace('_', ' ').title()
            print(f"{Fore.WHITE}{scan_name}: {status_color}{count} vulnerabilities {status_icon}")
        
        print(f"{Fore.CYAN}{'-'*50}")
        print(f"{Fore.WHITE}Total Vulnerabilities: {Fore.RED if total_vulnerabilities > 0 else Fore.GREEN}{total_vulnerabilities}")
        
        # Detailed findings
        if total_vulnerabilities > 0:
            print(f"\n{Fore.RED}🔍 DETAILED FINDINGS:")
            for scan_type, results in self.scan_results.items():
                for vuln in results:
                    param = vuln.get('parameter', vuln.get('header', 'N/A'))
                    print(f"{Fore.RED}• {vuln['type']}: {param}")

    def generate_file_report(self, elapsed_time):
        """Generate file report (JSON)"""
        report = {
            'scan_metadata': {
                'target': self.target_url,
                'scan_date': time.strftime('%Y-%m-%d %H:%M:%S'),
                'scan_duration': elapsed_time,
                'scanner_version': '1.0.0'
            },
            'results': self.scan_results,
            'summary': {
                'total_vulnerabilities': sum(len(results) for results in self.scan_results.values())
            }
        }
        
        with open(self.output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
        print(f"{Fore.GREEN}✅ JSON report saved: {self.output_file}")

def main():
    parser = argparse.ArgumentParser(description='Web Security Scanner')
    parser.add_argument('target', help='Target URL to scan')
    parser.add_argument('-o', '--output', help='Output file for report (JSON)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    scanner = WebSecurityScanner(args.target, args.output, args.verbose)
    scanner.scan()

if __name__ == "__main__":
    main()
