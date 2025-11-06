import unittest
import sys
import os

# Add the parent directory to path to import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.sql_injection import SQLInjectionScanner

class TestSQLInjection(unittest.TestCase):
    def setUp(self):
        self.scanner = SQLInjectionScanner()
    
    def test_sql_injection_detection(self):
        """Test SQL injection pattern detection"""
        malicious_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users--",
            "' UNION SELECT 1,2,3--",
            "1' AND 1=1--"
        ]
        
        for payload in malicious_payloads:
            with self.subTest(payload=payload):
                self.assertTrue(
                    self.scanner.is_sql_injection(payload),
                    f"Failed to detect SQLi: {payload}"
                )
    
    def test_safe_input(self):
        """Test that safe inputs are not flagged as SQL injection"""
        safe_inputs = [
            "normal text",
            "user@example.com",
            "12345",
            "hello world"
        ]
        
        for safe_input in safe_inputs:
            with self.subTest(input=safe_input):
                self.assertFalse(
                    self.scanner.is_sql_injection(safe_input),
                    f"False positive for: {safe_input}"
                )

if __name__ == '__main__':
    unittest.main()
