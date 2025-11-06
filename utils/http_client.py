"""HTTP Client with security scanning features"""

import requests
import time
from urllib3.exceptions import InsecureRequestWarning

# Suppress only the single warning from urllib3 needed.
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

class HTTPClient:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'WebSecurityScanner/1.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        })
    
    def get(self, url, params=None, **kwargs):
        """HTTP GET request"""
        return self.session.get(url, params=params, verify=False, **kwargs)
    
    def post(self, url, data=None, **kwargs):
        """HTTP POST request"""
        return self.session.post(url, data=data, verify=False, **kwargs)
    
    def test_connection(self, url):
        """Test if target is accessible"""
        try:
            response = self.get(url, timeout=10)
            return response.status_code < 500
        except:
            return False
