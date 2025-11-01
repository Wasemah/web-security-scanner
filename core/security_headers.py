"""Security Headers Scanner"""

from colorama import Fore

class SecurityHeadersScanner:
    def __init__(self, http_client):
        self.http_client = http_client
        self.important_headers = {
            'Content-Security-Policy': 'Prevents XSS attacks',
            'X-Frame-Options': 'Prevents clickjacking',
            'X-Content-Type-Options': 'Prevents MIME sniffing',
            'Strict-Transport-Security': 'Enforces HTTPS',
            'X-XSS-Protection': 'Browser XSS protection',
            'Referrer-Policy': 'Controls referrer information'
        }
    
    def scan(self, target_url):
        """Check for missing security headers"""
        print(f"\n{Fore.BLUE}[3/4] Checking Security Headers...")
        
        vulnerabilities = []
        
        try:
            response = self.http_client.get(target_url)
            headers = response.headers
            
            for header, description in self.important_headers.items():
                if header not in headers:
                    vulnerability = {
                        'type': 'Missing Security Header',
                        'header': header,
                        'description': description,
                        'severity': 'Medium',
                        'recommendation': f'Implement {header} header'
                    }
                    vulnerabilities.append(vulnerability)
                    print(f"{Fore.YELLOW}⚠️  Missing security header: {header}")
                else:
                    print(f"{Fore.GREEN}✅ Header present: {header}")
                    
        except Exception as e:
            print(f"{Fore.RED}❌ Error checking headers: {e}")
        
        return vulnerabilities
