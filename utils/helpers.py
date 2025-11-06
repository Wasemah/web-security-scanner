import re
from urllib.parse import urlparse

def is_valid_url(url):
    """Validate URL format"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def extract_forms(html):
    """Extract forms from HTML content"""
    forms = []
    pattern = r'<form[^>]*>(.*?)</form>'
    form_matches = re.finditer(pattern, html, re.IGNORECASE | re.DOTALL)
    
    for form_match in form_matches:
        forms.append(form_match.group())
    
    return forms

def sanitize_input(input_string):
    """Basic input sanitization"""
    return input_string.strip()

def generate_random_string(length=8):
    """Generate random string for testing"""
    import random
    import string
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))
