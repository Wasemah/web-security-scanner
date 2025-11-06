import unittest
from core.sql_injection import SQLInjectionScanner

class TestSQLInjection(unittest.TestCase):
    def setUp(self):
        self.scanner = SQLInjectionScanner()
    
    def test_detection_logic(self):
        # Test SQL injection detection
        test_payload = "' OR '1'='1"
        self.assertTrue(self.scanner.is_sql_injection(test_payload))
    
    def test_safe_input(self):
        safe_input = "normal text"
        self.assertFalse(self.scanner.is_sql_injection(safe_input))

if __name__ == '__main__':
    unittest.main()
