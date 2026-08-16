#!/usr/bin/env python3
"""
Log Analyzer Module
Detects attacks in Apache and Nginx log files
"""

import re
import os
from collections import Counter
from datetime import datetime
from colorama import Fore, Style
from typing import List, Dict, Tuple

class LogAnalyzer:
    def __init__(self, log_file: str, log_type: str = "apache"):
        self.log_file = log_file
        self.log_type = log_type
        self.entries = []
        self.attacks = []
        
        # الگوهای حملات
        self.attack_patterns = {
            'SQL Injection': re.compile(r'(\%27)|(\')|(\%22)|(\")|(union.*select)|(or.*=.*)|(and.*=)', re.IGNORECASE),
            'XSS': re.compile(r'(<script)|(onerror)|(onload)|(alert\()|(javascript:)', re.IGNORECASE),
            'Directory Traversal': re.compile(r'(\.\./)|(\.\.\\)|(%2e%2e/)', re.IGNORECASE),
            'Command Injection': re.compile(r'(;.*\$)|(\|.*\$)|(&.*\$)|(&&.*\$)', re.IGNORECASE),
            'Path Traversal': re.compile(r'(/etc/passwd)|(/etc/shadow)|(/proc/self/environ)', re.IGNORECASE),
            'File Inclusion': re.compile(r'(include.*\.\.)|(require.*\.\.)', re.IGNORECASE),
            'User Agent Attack': re.compile(r'(sqlmap)|(nmap)|(nikto)|(wget)|(curl)|(python-requests)', re.IGNORECASE),
        }
        
        # الگوی خطوط لاگ آپاچی
        self.apache_pattern = re.compile(
            r'(?P<ip>[\d\.]+) - - \[(?P<time>[^\]]+)\] "(?P<method>[A-Z]+) (?P<url>[^ ]+) (?P<protocol>[^"]+)" (?P<status>\d{3}) (?P<size>\d+) "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
        )
    
    def parse_logs(self) -> List[Dict]:
        """پارس خطوط لاگ"""
        if not os.path.exists(self.log_file):
            print(f"{Fore.RED}[!] Log file not found: {self.log_file}{Style.RESET_ALL}")
            return []
        
        with open(self.log_file, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        
        parsed = []
        for line in lines:
            if self.log_type == "apache":
                match = self.apache_pattern.match(line.strip())
                if match:
                    entry = match.groupdict()
                    parsed.append(entry)
                    self.entries.append(entry)
        
        return parsed
    
    def detect_attacks(self) -> List[Dict]:
        """تشخیص حملات از لاگ"""
        print(f"{Fore.CYAN}[*] Analyzing {len(self.entries)} log entries...{Style.RESET_ALL}")
        
        for entry in self.entries:
            attacks_found = []
            
            # بررسی URL
            url = entry.get('url', '')
            for attack_name, pattern in self.attack_patterns.items():
                if pattern.search(url):
                    attacks_found.append(attack_name)
            
            # بررسی User-Agent
            user_agent = entry.get('user_agent', '')
            if 'sqlmap' in user_agent.lower() or 'nmap' in user_agent.lower():
                attacks_found.append('Automated Tool')
            
            # بررسی پاسخ‌های ۴۰۳ (خطاها)
            status = entry.get('status', '')
            if status == '403':
                if url and any(p in url.lower() for p in ['admin', 'config', 'backup', '.sql', '.env']):
                    attacks_found.append('Sensitive File Access')
            
            if attacks_found:
                entry['attacks'] = attacks_found
                self.attacks.append(entry)
        
        return self.attacks
    
    def report(self):
        """گزارش نهایی"""
        print("\n" + "="*60)
        print(f"{Fore.YELLOW}📊 LOG ANALYSIS REPORT{Style.RESET_ALL}")
        print("="*60)
        
        print(f"{Fore.CYAN}Log file: {self.log_file}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Total entries: {len(self.entries)}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Attacks detected: {len(self.attacks)}{Style.RESET_ALL}\n")
        
        if not self.attacks:
            print(f"{Fore.GREEN}✅ No attacks detected!{Style.RESET_ALL}")
            return
        
        # آماری از نوع حملات
        attack_types = Counter()
        for entry in self.attacks:
            for attack in entry.get('attacks', []):
                attack_types[attack] += 1
        
        print(f"{Fore.RED}🚨 Attack Types Detected:{Style.RESET_ALL}")
        for attack_type, count in attack_types.most_common(5):
            print(f"    {Fore.YELLOW}{attack_type}{Style.RESET_ALL}: {count} times")
        
        print(f"\n{Fore.RED}⚠️  Suspicious Entries (First 5):{Style.RESET_ALL}")
        for i, entry in enumerate(self.attacks[:5], 1):
            print(f"\n{Fore.YELLOW}[{i}]{Style.RESET_ALL}")
            print(f"    IP: {entry.get('ip', 'N/A')}")
            print(f"    URL: {entry.get('url', 'N/A')[:80]}...")
            print(f"    Status: {entry.get('status', 'N/A')}")
            print(f"    User-Agent: {entry.get('user_agent', 'N/A')[:60]}...")
            print(f"    Attacks: {', '.join(entry.get('attacks', []))}")


def analyze_log(log_file: str, log_type: str = "apache"):
    """تابع اصلی برای صدا زدن از main.py"""
    analyzer = LogAnalyzer(log_file, log_type)
    analyzer.parse_logs()
    analyzer.detect_attacks()
    analyzer.report()
    return analyzer.attacks


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
        log_type = sys.argv[2] if len(sys.argv) > 2 else "apache"
        analyze_log(log_file, log_type)
    else:
        print("Usage: python3 monitor/log_analyzer.py <log_file> [apache|nginx]")
        print("Example: python3 monitor/log_analyzer.py /var/log/apache2/access.log")

