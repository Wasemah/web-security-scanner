"""XSS Scanner Module"""

from tqdm import tqdm
from colorama import Fore
from bs4 import BeautifulSoup
from utils.http_client import HTTPClient

class XSSScanner:
    def __init__(self, http_client):
        self.http_client = http_client
        self.payloads = self.load_xss_payloads()
    
    def load_xss_payloads(self):
        """Load XSS test payloads"""
        return [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '<svg onload=alert("XSS")>',
            '"><script>alert("XSS")</script>',
            'javascript:alert("XSS")',
            '<body onload=alert("XSS")>',
            '<iframe src="javascript:alert(`XSS`)">',
            '<input onfocus=alert("XSS") autofocus>'
        ]
    
    def scan(self, target_url):
        """Scan for XSS vulnerabilities"""
        print(f"\n{Fore.BLUE}[2/4] Scanning for XSS Vulnerabilities...")
        
        vulnerabilities = []
        test_params = {'q': 'test', 'search': 'query', 'name': 'user'}
        
        for param, value in test_params.items():
            for payload in tqdm(self.payloads, desc=f"Testing {param}"):
                test_data = {param: payload}
                
                try:
                    # Test GET request
                    response = self.http_client.get(target_url, params=test_data)
                    if self.detect_xss(response, payload):
                        vulnerability = {
                            'type': 'Cross-Site Scripting (XSS)',
                            'parameter': param,
                            'payload': payload,
                            'confidence': 'Medium',
                            'evidence': 'Payload reflected without sanitization'
                        }
                        vulnerabilities.append(vulnerability)
                        print(f"{Fore.RED}❌ XSS vulnerability found in parameter: {param}")
                        break
                    
                    # Test POST request
                    response = self.http_client.post(target_url, data=test_data)
                    if self.detect_xss(response, payload):
                        vulnerability = {
                            'type': 'Cross-Site Scripting (XSS)',
                            'parameter': param,
                            'payload': payload,
                            'confidence': 'Medium', 
                            'evidence': 'Payload reflected without sanitization'
                        }
                        vulnerabilities.append(vulnerability)
                        print(f"{Fore.RED}❌ XSS vulnerability found in parameter: {param}")
                        break
                        
                except Exception as e:
                    continue
        
        return vulnerabilities
    
    def detect_xss(self, response, payload):
        """Detect if XSS payload is reflected in response"""
        soup = BeautifulSoup(response.text, 'html.parser')
        text_content = soup.get_text()
        
        # Check if payload is reflected without encoding
        return payload in response.text
