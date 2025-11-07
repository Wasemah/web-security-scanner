#!/usr/bin/env python3
import argparse
import sys
import os
from colorama import Fore, Style, init

# Add the current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.sql_injection import SQLInjectionScanner
from core.xss_scanner import XSSScanner
from core.csrf_detector import CSRFDetector
from core.security_headers import SecurityHeadersScanner
from utils.http_client import HTTPClient
from utils.report_generator import ReportGenerator

# Initialize colorama
init(autoreset=True)

class WebSecurityScanner:
    def __init__(self):
        self.http_client = HTTPClient()
        self.sql_scanner = SQLInjectionScanner(self.http_client)
        self.xss_scanner = XSSScanner(self.http_client)
        self.csrf_detector = CSRFDetector()
        self.headers_scanner = SecurityHeadersScanner()
        self.report_generator = ReportGenerator()
    
    def scan_url(self, url):
        """Scan a single URL for vulnerabilities"""
        print(f"\n{Fore.BLUE}🔍 Scanning: {url}{Style.RESET_ALL}")
        
        vulnerabilities = []
        
        # Test connection first
        if not self.http_client.test_connection(url):
            print(f"{Fore.RED}❌ Cannot connect to {url}{Style.RESET_ALL}")
            return vulnerabilities
        
        response = self.http_client.get(url)
        if not response:
            return vulnerabilities
        
        # Perform security scans
        print(f"{Fore.GREEN}🚀 Starting comprehensive security scans...{Style.RESET_ALL}")
        
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
        
        print(f"\n{Fore.GREEN}✅ Scan completed. Found {len(vulnerabilities)} potential vulnerabilities{Style.RESET_ALL}")
        return vulnerabilities
    
    def scan_multiple_urls(self, urls):
        """Scan multiple URLs"""
        all_vulnerabilities = []
        for url in urls:
            url = url.strip()
            if url and not url.startswith('#'):
                vulns = self.scan_url(url)
                all_vulnerabilities.extend(vulns)
                print()  # Empty line between scans
        return all_vulnerabilities

def main():
    banner = f"""
    {Fore.CYAN}🛡️  Web Security Scanner{Style.RESET_ALL}
    {Fore.WHITE}-----------------------------{Style.RESET_ALL}
    A comprehensive web application security scanner
    """
    print(banner)
    
    parser = argparse.ArgumentParser(description='Web Security Scanner')
    parser.add_argument('url', nargs='?', help='Target URL to scan')
    parser.add_argument('-i', '--input', help='Input file with list of URLs to scan')
    parser.add_argument('-o', '--output', help='Output report file')
    parser.add_argument('--format', choices=['html', 'json', 'txt'], 
                       default='html', help='Report format (default: html)')
    
    args = parser.parse_args()
    
    if not args.url and not args.input:
        parser.print_help()
        print(f"\n{Fore.RED}❌ Error: Please provide a URL or input file{Style.RESET_ALL}")
        sys.exit(1)
    
    scanner = WebSecurityScanner()
    vulnerabilities = []
    target_url = ""
    
    try:
        if args.url:
            target_url = args.url
            vulnerabilities = scanner.scan_url(args.url)
        elif args.input:
            with open(args.input, 'r') as f:
                urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            target_url = f"Multiple URLs from {args.input}"
            vulnerabilities = scanner.scan_multiple_urls(urls)
        
        # Display summary
        print(f"\n{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}📋 SCAN SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
        
        severity_count = {}
        for vuln in vulnerabilities:
            severity = vuln['severity']
            severity_count[severity] = severity_count.get(severity, 0) + 1
        
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            count = severity_count.get(severity, 0)
            if count > 0:
                print(f"  {severity.upper()}: {count}")
        
        print(f"  TOTAL: {len(vulnerabilities)}")
        
        # Generate report if output specified
        if args.output:
            scanner.report_generator.generate_report(
                vulnerabilities, args.output, args.format, target_url
            )
            print(f"\n{Fore.GREEN}📄 Report saved to: {args.output}{Style.RESET_ALL}")
        
        # Show a few vulnerabilities in console
        if vulnerabilities:
            print(f"\n{Fore.YELLOW}🔍 Top vulnerabilities found:{Style.RESET_ALL}")
            for i, vuln in enumerate(vulnerabilities[:5], 1):
                print(f"  {i}. [{vuln['severity'].upper()}] {vuln['type']}")
        
        if not vulnerabilities:
            print(f"{Fore.GREEN}🎉 No vulnerabilities found!{Style.RESET_ALL}")
            
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}⏹️  Scan interrupted by user{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}❌ Error during scan: {e}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    main()
