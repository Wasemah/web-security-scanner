"""SQL Injection Scanner Module"""

import time
from tqdm import tqdm
from colorama import Fore, Style
from utils.http_client import HTTPClient

class SQLInjectionScanner:
    def __init__(self, http_client):
        self.http_client = http_client
        self.payloads = self.load_sql_payloads()
        self.vulnerable_params = []
    
    def load_sql_payloads(self):
        """Load SQL injection payloads"""
        base_payloads = [
            "'",
            "';",
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT 1,2,3--",
            "' AND 1=1--",
            "' AND 1=2--",
            "'; DROP TABLE users--",
            "' WAITFOR DELAY '00:00:10'--",
            "' OR SLEEP(5)--"
        ]
        return base_payloads
    
    def scan(self, target_url):
        """Scan for SQL injection vulnerabilities"""
        print(f"\n{Fore.BLUE}[1/4] Scanning for SQL Injection...")
        
        # Test in URL parameters
        test_params = {'id': '1', 'user': 'test', 'category': '1'}
        vulnerabilities = []
        
        for param, value in test_params.items():
            for payload in tqdm(self.payloads, desc=f"Testing {param}"):
                test_url = f"{target_url}?{param}={value}{payload}"
                
                try:
                    response = self.http_client.get(test_url, timeout=10)
                    
                    # Detection heuristics
                    if self.detect_sql_injection(response):
                        vulnerability = {
                            'type': 'SQL Injection',
                            'parameter': param,
                            'payload': payload,
                            'confidence': 'High',
                            'evidence': 'Error-based SQL injection detected'
                        }
                        vulnerabilities.append(vulnerability)
                        print(f"{Fore.RED}❌ SQL Injection found in parameter: {param}")
                        break
                        
                except Exception as e:
                    continue
        
        return vulnerabilities
    
    def detect_sql_injection(self, response):
        """Detect SQL injection based on response"""
        sql_errors = [
            'sql syntax',
            'mysql_fetch',
            'ora-',
            'microsoft odbc',
            'postgresql',
            'syntax error',
            'mysql error',
            'warning: mysql',
            'unclosed quotation',
            'you have an error in your sql'
        ]
        
        response_text = response.text.lower()
        return any(error in response_text for error in sql_errors)
