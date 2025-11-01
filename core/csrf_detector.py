"""CSRF Vulnerability Detector"""

from colorama import Fore
from bs4 import BeautifulSoup

class CSRFDetector:
    def __init__(self, http_client):
        self.http_client = http_client
    
    def scan(self, target_url):
        """Check for CSRF protection"""
        print(f"\n{Fore.BLUE}[4/4] Checking CSRF Protection...")
        
        vulnerabilities = []
        
        try:
            response = self.http_client.get(target_url)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            forms = soup.find_all('form')
            forms_without_csrf = []
            
            for form in forms:
                # Check for CSRF token
                csrf_tokens = form.find_all('input', {
                    'name': ['csrf', 'csrf_token', '_token', 'authenticity_token']
                })
                
                if not csrf_tokens and form.get('method', '').lower() == 'post':
                    forms_without_csrf.append(form)
            
            if forms_without_csrf:
                vulnerability = {
                    'type': 'Missing CSRF Protection',
                    'forms_affected': len(forms_without_csrf),
                    'severity': 'Medium',
                    'recommendation': 'Add CSRF tokens to all forms'
                }
                vulnerabilities.append(vulnerability)
                print(f"{Fore.YELLOW}⚠️  {len(forms_without_csrf)} forms without CSRF protection")
            else:
                print(f"{Fore.GREEN}✅ CSRF protection appears to be implemented")
                
        except Exception as e:
            print(f"{Fore.RED}❌ Error checking CSRF: {e}")
        
        return vulnerabilities
