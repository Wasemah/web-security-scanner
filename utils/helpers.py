import re
import random
import string
from urllib.parse import urlparse, urljoin

def is_valid_url(url):
    """Validate URL format"""
    try:
        result = urlparse(url)
        return all([result.scheme in ['http', 'https'], result.netloc])
    except:
        return False

def extract_forms(html):
    """Extract forms from HTML content"""
    forms = []
    form_pattern = r'<form[^>]*>(.*?)</form>'
    form_matches = re.finditer(form_pattern, html, re.IGNORECASE | re.DOTALL)
    
    for form_match in form_matches:
        forms.append(form_match.group())
    
    return forms

def extract_input_fields(html):
    """Extract input fields from HTML"""
    inputs = []
    input_pattern = r'<input[^>]*>'
    input_matches = re.finditer(input_pattern, html, re.IGNORECASE)
    
    for input_match in input_matches:
        inputs.append(input_match.group())
    
    return inputs

def sanitize_input(input_string):
    """Basic input sanitization"""
    return input_string.strip()

def generate_random_string(length=8):
    """Generate random string for testing"""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def get_domain_from_url(url):
    """Extract domain from URL"""
    try:
        return urlparse(url).netloc
    except:
        return ""

def build_full_url(base_url, relative_path):
    """Build full URL from base and relative path"""
    return urljoin(base_url, relative_path)
