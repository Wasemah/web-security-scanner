import unittest
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.xss_scanner import XSSScanner

class TestXSSScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = XSSScanner()
    
    def test_xss_detection(self):
        """Test XSS pattern detection"""
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "\"><script>alert('XSS')</script>"
        ]
        
        for payload in xss_payloads:
            with self.subTest(payload=payload):
                self.assertTrue(
                    self.scanner.is_xss_payload(payload),
                    f"Failed to detect XSS: {payload}"
                )
    
    def test_safe_content(self):
        """Test that safe content is not flagged as XSS"""
        safe_content = [
            "<div>Hello World</div>",
            "<p>Normal paragraph</p>",
            "<a href='/page'>Link</a>",
            "Just plain text"
        ]
        
        for content in safe_content:
            with self.subTest(content=content):
                self.assertFalse(
                    self.scanner.is_xss_payload(content),
                    f"False positive for: {content}"
                )

if __name__ == '__main__':
    unittest.main()
