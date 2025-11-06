"""CSRF Detector Module"""

import re
from urllib.parse import urlparse
from colorama import Fore, Style

class CSRFDetector:
    def __init__(self):
        self.vulnerable_forms = []
        
        # CSRF token patterns
        self.csrf_patterns = [
            r'<input[^>]*name=[\"\']csrf[\"\'][^>]*>',
            r'<input[^>]*name=[\"\']csrf_token[\"\'][^>]*>',
            r'<input[^>]*name=[\"\']_token[\"\'][^>]*>',
            r'<input[^>]*name=[\"\']authenticity_token[\"\'][^>]*>',
            r'<input[^>]*name=[\"\']csrfmiddlewaretoken[\"\'][^>]*>',
            r'<input[^>]*name=[\"\']_csrf[\"\'][^>]*>',
            r'<meta[^>]*name=[\"\']csrf-token[\"\'][^>]*>',
        ]

    def scan(self, url, html_content):
        """Scan for CSRF vulnerabilities with detailed reporting"""
        print(f"\n{Fore.BLUE}[CSRF Analysis]{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Target: {url}{Style.RESET_ALL}")
        
        vulnerabilities = []
        
        forms = self.extract_forms(html_content)
        
        if not forms:
            print(f"{Fore.YELLOW}No forms found on the page{Style.RESET_ALL}")
            return vulnerabilities
        
        print(f"{Fore.YELLOW}Found {len(forms)} forms to analyze...{Style.RESET_ALL}")
        
        for i, form in enumerate(forms, 1):
            form_info = self.analyze_form(form, url, i)
            
            if not form_info['has_csrf_protection']:
                vulnerability = {
                    'type': 'Cross-Site Request Forgery (CSRF)',
                    'severity': 'medium',
                    'url': url,
                    'form_action': form_info['action'],
                    'form_method': form_info['method'],
                    'description': f'Form {i} missing CSRF protection token',
                    'recommendation': 'Implement CSRF tokens, validate Origin/Referer headers, and use SameSite cookies'
                }
                vulnerabilities.append(vulnerability)
                print(f"{Fore.RED}❌ Form {i} vulnerable to CSRF{Style.RESET_ALL}")
            else:
                print(f"{Fore.GREEN}✅ Form {i} has CSRF protection{Style.RESET_ALL}")
        
        return vulnerabilities

    def extract_forms(self, html_content):
        """Extract forms from HTML content with enhanced parsing"""
        if not html_content:
            return []
            
        forms = []
        
        # Improved form extraction with better pattern matching
        form_pattern = r'<form[^>]*>(.*?)</form>'
        form_matches = re.finditer(form_pattern, html_content, re.IGNORECASE | re.DOTALL)
        
        for form_match in form_matches:
            forms.append(form_match.group())
        
        return forms

    def analyze_form(self, form_html, base_url, form_number):
        """Analyze a single form for CSRF protection"""
        form_info = {
            'number': form_number,
            'action': self.get_form_action(form_html, base_url),
            'method': self.get_form_method(form_html),
            'has_csrf_protection': False,
            'input_count': len(self.get_form_inputs(form_html))
        }
        
        # Check for CSRF tokens
        if self.has_csrf_protection(form_html):
            form_info['has_csrf_protection'] = True
        
        # Additional security checks
        form_info['is_same_origin'] = self.is_same_origin(form_info['action'], base_url)
        form_info['has_dangerous_method'] = form_info['method'].upper() in ['POST', 'PUT', 'DELETE']
        
        return form_info

    def has_csrf_protection(self, form_html):
        """Check if form has CSRF protection"""
        for pattern in self.csrf_patterns:
            if re.search(pattern, form_html, re.IGNORECASE):
                return True
        
        return False

    def get_form_action(self, form_html, base_url):
        """Extract form action URL with fallback"""
        action_pattern = r'action=[\"\']([^\"\']*)[\"\']'
        match = re.search(action_pattern, form_html, re.IGNORECASE)
        
        if match:
            action_url = match.group(1)
            if action_url.startswith(('http://', 'https://')):
                return action_url
            else:
                # Convert relative URL to absolute
                base = urlparse(base_url)
                if action_url.startswith('/'):
                    return f"{base.scheme}://{base.netloc}{action_url}"
                else:
                    return f"{base.scheme}://{base.netloc}/{action_url}"
        
        return base_url  # Default to current URL if no action specified

    def get_form_method(self, form_html):
        """Extract form method with default to GET"""
        method_pattern = r'method=[\"\']([^\"\']*)[\"\']'
        match = re.search(method_pattern, form_html, re.IGNORECASE)
        
        if match:
            return match.group(1).upper()
        
        return 'GET'  # Default method

    def get_form_inputs(self, form_html):
        """Extract all input fields from form"""
        inputs = []
        input_pattern = r'<input[^>]*>'
        input_matches = re.finditer(input_pattern, form_html, re.IGNORECASE)
        
        for input_match in input_matches:
            inputs.append(input_match.group())
        
        return inputs

    def is_same_origin(self, action_url, base_url):
        """Check if form action is same origin"""
        try:
            action_domain = urlparse(action_url).netloc
            base_domain = urlparse(base_url).netloc
            return action_domain == base_domain
        except:
            return False

    def generate_report(self, vulnerabilities):
        """Generate a detailed report of CSRF findings"""
        if not vulnerabilities:
            return f"{Fore.GREEN}No CSRF vulnerabilities found{Style.RESET_ALL}"
        
        report = [f"{Fore.RED}CSRF Vulnerabilities Found:{Style.RESET_ALL}"]
        
        for i, vuln in enumerate(vulnerabilities, 1):
            report.append(f"\n{Fore.YELLOW}{i}. {vuln['type']}{Style.RESET_ALL}")
            report.append(f"   {Fore.CYAN}URL: {vuln['url']}{Style.RESET_ALL}")
            report.append(f"   {Fore.MAGENTA}Form Action: {vuln['form_action']}{Style.RESET_ALL}")
            report.append(f"   {Fore.MAGENTA}Method: {vuln['form_method']}{Style.RESET_ALL}")
            report.append(f"   {Fore.WHITE}Description: {vuln['description']}{Style.RESET_ALL}")
            report.append(f"   {Fore.GREEN}Recommendation: {vuln['recommendation']}{Style.RESET_ALL}")
        
        return "\n".join(report)
