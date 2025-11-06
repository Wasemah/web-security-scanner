"""Security Headers Scanner Module"""

from colorama import Fore, Style

class SecurityHeadersScanner:
    def __init__(self):
        self.important_headers = {
            'Content-Security-Policy': {
                'severity': 'high',
                'description': 'Prevents XSS and other code injection attacks',
                'recommendation': 'Implement a strong Content Security Policy with strict directives'
            },
            'X-Frame-Options': {
                'severity': 'medium', 
                'description': 'Prevents clickjacking attacks',
                'recommendation': 'Set X-Frame-Options to DENY or SAMEORIGIN'
            },
            'X-Content-Type-Options': {
                'severity': 'medium',
                'description': 'Prevents MIME type sniffing',
                'recommendation': 'Set X-Content-Type-Options to nosniff'
            },
            'Strict-Transport-Security': {
                'severity': 'high',
                'description': 'Enforces HTTPS connections',
                'recommendation': 'Implement HSTS with max-age of at least 31536000 and includeSubDomains'
            },
            'X-XSS-Protection': {
                'severity': 'low',
                'description': 'Enables XSS protection in older browsers',
                'recommendation': 'Set X-XSS-Protection: 1; mode=block'
            },
            'Referrer-Policy': {
                'severity': 'low',
                'description': 'Controls referrer information',
                'recommendation': 'Set appropriate Referrer-Policy like strict-origin-when-cross-origin'
            },
            'Permissions-Policy': {
                'severity': 'medium',
                'description': 'Controls browser features and APIs',
                'recommendation': 'Implement Permissions-Policy to restrict unnecessary features'
            }
        }

    def scan(self, headers):
        """Comprehensive security headers analysis"""
        print(f"\n{Fore.BLUE}[Security Headers Analysis]{Style.RESET_ALL}")
        
        vulnerabilities = []
        found_headers = []
        
        for header, info in self.important_headers.items():
            if header not in headers:
                vulnerability = {
                    'type': 'Security Headers',
                    'severity': info['severity'],
                    'header': header,
                    'description': f'Missing {header} header - {info["description"]}',
                    'recommendation': info['recommendation']
                }
                vulnerabilities.append(vulnerability)
                print(f"{Fore.RED}❌ Missing: {header}{Style.RESET_ALL}")
            else:
                # Validate header values
                header_vulns = self.validate_header_value(header, headers[header])
                vulnerabilities.extend(header_vulns)
                found_headers.append(header)
                print(f"{Fore.GREEN}✅ Found: {header}{Style.RESET_ALL}")
        
        # Additional security checks
        cookie_vulns = self.check_cookie_security(headers)
        vulnerabilities.extend(cookie_vulns)
        
        # Report summary
        total_headers = len(self.important_headers)
        missing_headers = total_headers - len(found_headers)
        security_score = (len(found_headers) / total_headers) * 100
        
        print(f"\n{Fore.CYAN}Security Headers Score: {security_score:.1f}% ({len(found_headers)}/{total_headers}){Style.RESET_ALL}")
        
        return vulnerabilities

    def validate_header_value(self, header_name, header_value):
        """Validate specific header values for security"""
        vulnerabilities = []
        
        if header_name == 'Content-Security-Policy':
            if not self.is_strong_csp(header_value):
                vulnerabilities.append({
                    'type': 'Security Headers',
                    'severity': 'medium',
                    'header': header_name,
                    'description': f'Weak Content-Security-Policy: {header_value}',
                    'recommendation': 'Implement a stronger CSP with default-src, script-src, and object-src directives'
                })
        
        elif header_name == 'X-Frame-Options':
            if header_value.upper() not in ['DENY', 'SAMEORIGIN']:
                vulnerabilities.append({
                    'type': 'Security Headers',
                    'severity': 'medium',
                    'header': header_name,
                    'description': f'Weak X-Frame-Options value: {header_value}',
                    'recommendation': 'Set X-Frame-Options to DENY or SAMEORIGIN'
                })
        
        elif header_name == 'X-Content-Type-Options':
            if header_value.lower() != 'nosniff':
                vulnerabilities.append({
                    'type': 'Security Headers',
                    'severity': 'medium',
                    'header': header_name,
                    'description': f'Invalid X-Content-Type-Options value: {header_value}',
                    'recommendation': 'Set X-Content-Type-Options to nosniff'
                })
        
        elif header_name == 'Strict-Transport-Security':
            if not self.is_strong_hsts(header_value):
                vulnerabilities.append({
                    'type': 'Security Headers',
                    'severity': 'medium',
                    'header': header_name,
                    'description': f'Weak HSTS configuration: {header_value}',
                    'recommendation': 'Set HSTS with max-age=31536000 and includeSubDomains'
                })
        
        elif header_name == 'X-XSS-Protection':
            if header_value != '1; mode=block':
                vulnerabilities.append({
                    'type': 'Security Headers',
                    'severity': 'low',
                    'header': header_name,
                    'description': f'Non-optimal X-XSS-Protection: {header_value}',
                    'recommendation': 'Set X-XSS-Protection: 1; mode=block'
                })
        
        return vulnerabilities

    def is_strong_csp(self, csp_value):
        """Check if CSP is strong enough"""
        # Basic checks for strong CSP
        weak_directives = ["default-src *", "script-src *", "unsafe-inline", "unsafe-eval"]
        return not any(weak in csp_value for weak in weak_directives)

    def is_strong_hsts(self, hsts_value):
        """Check if HSTS is properly configured"""
        return 'max-age=31536000' in hsts_value

    def check_cookie_security(self, headers):
        """Check Set-Cookie headers for security attributes"""
        vulnerabilities = []
        
        if 'Set-Cookie' in headers:
            cookies = headers['Set-Cookie'] if isinstance(headers['Set-Cookie'], list) else [headers['Set-Cookie']]
            
            for i, cookie in enumerate(cookies):
                cookie_vulns = self.analyze_cookie_security(cookie, i)
                vulnerabilities.extend(cookie_vulns)
        
        return vulnerabilities

    def analyze_cookie_security(self, cookie_header, cookie_index):
        """Analyze individual cookie for security attributes"""
        vulnerabilities = []
        
        # Check for missing Secure flag
        if 'Secure' not in cookie_header:
            vulnerabilities.append({
                'type': 'Cookie Security',
                'severity': 'high',
                'header': f'Set-Cookie #{cookie_index + 1}',
                'description': 'Cookie missing Secure flag - transmitted over HTTP',
                'recommendation': 'Add Secure flag to all cookies'
            })
        
        # Check for missing HttpOnly flag
        if 'HttpOnly' not in cookie_header:
            vulnerabilities.append({
                'type': 'Cookie Security',
                'severity': 'medium',
                'header': f'Set-Cookie #{cookie_index + 1}',
                'description': 'Cookie missing HttpOnly flag - accessible via JavaScript',
                'recommendation': 'Add HttpOnly flag to sensitive cookies'
            })
        
        # Check for SameSite attribute
        if 'SameSite' not in cookie_header:
            vulnerabilities.append({
                'type': 'Cookie Security',
                'severity': 'medium',
                'header': f'Set-Cookie #{cookie_index + 1}',
                'description': 'Cookie missing SameSite attribute - vulnerable to CSRF',
                'recommendation': 'Add SameSite=Lax or SameSite=Strict to cookies'
            })
        
        return vulnerabilities

    def generate_report(self, vulnerabilities):
        """Generate a detailed report of security headers findings"""
        if not vulnerabilities:
            return f"{Fore.GREEN}All security headers are properly configured{Style.RESET_ALL}"
        
        report = [f"{Fore.RED}Security Header Issues Found:{Style.RESET_ALL}"]
        
        for i, vuln in enumerate(vulnerabilities, 1):
            report.append(f"\n{Fore.YELLOW}{i}. {vuln['type']}{Style.RESET_ALL}")
            report.append(f"   {Fore.CYAN}Header: {vuln['header']}{Style.RESET_ALL}")
            report.append(f"   {Fore.WHITE}Description: {vuln['description']}{Style.RESET_ALL}")
            report.append(f"   {Fore.GREEN}Recommendation: {vuln['recommendation']}{Style.RESET_ALL}")
        
        return "\n".join(report)
