#!/usr/bin/env python3
"""
Password Tools Module
Password strength analyzer and hash cracker
"""

import hashlib
import re
import time
from colorama import Fore, Style
from typing import Optional

class PasswordTools:
    @staticmethod
    def calculate_entropy(password: str) -> float:
        """محاسبه آنتروپی پسورد (پیچیدگی)"""
        charset_size = 0
        if re.search(r'[a-z]', password):
            charset_size += 26
        if re.search(r'[A-Z]', password):
            charset_size += 26
        if re.search(r'[0-9]', password):
            charset_size += 10
        if re.search(r'[^a-zA-Z0-9]', password):
            charset_size += 33
        
        if charset_size == 0:
            return 0
        
        entropy = len(password) * (charset_size.bit_length() - 1)
        return entropy
    
    @staticmethod
    def analyze_password(password: str) -> dict:
        """تحلیل کامل یک پسورد"""
        length = len(password)
        has_lower = bool(re.search(r'[a-z]', password))
        has_upper = bool(re.search(r'[A-Z]', password))
        has_digit = bool(re.search(r'[0-9]', password))
        has_special = bool(re.search(r'[^a-zA-Z0-9]', password))
        entropy = PasswordTools.calculate_entropy(password)
        
        # تعیین قدرت
        if entropy < 30:
            strength = "Very Weak 🔴"
            color = Fore.RED
        elif entropy < 50:
            strength = "Weak 🟡"
            color = Fore.YELLOW
        elif entropy < 70:
            strength = "Medium 🟠"
            color = Fore.YELLOW
        elif entropy < 90:
            strength = "Strong 🟢"
            color = Fore.GREEN
        else:
            strength = "Very Strong 💪"
            color = Fore.GREEN
        
        return {
            'length': length,
            'has_lower': has_lower,
            'has_upper': has_upper,
            'has_digit': has_digit,
            'has_special': has_special,
            'entropy': entropy,
            'strength': strength,
            'color': color
        }
    
    @staticmethod
    def crack_hash(target_hash: str, wordlist_path: str, hash_type: str = "md5") -> Optional[str]:
        """کرک هش با دیکشنری"""
        hash_func = getattr(hashlib, hash_type.lower(), None)
        if not hash_func:
            print(f"{Fore.RED}[!] Invalid hash type: {hash_type}{Style.RESET_ALL}")
            return None
        
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                words = f.readlines()
        except FileNotFoundError:
            print(f"{Fore.RED}[!] Wordlist not found: {wordlist_path}{Style.RESET_ALL}")
            return None
        
        print(f"{Fore.CYAN}[*] Loaded {len(words)} words from wordlist{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Cracking {hash_type} hash: {target_hash}{Style.RESET_ALL}\n")
        
        start_time = time.time()
        found = None
        
        for i, word in enumerate(words):
            word = word.strip()
            if not word:
                continue
            
            # نمایش پیشرفت هر ۱۰۰۰ کلمه
            if i % 1000 == 0:
                print(f"{Fore.BLUE}[{i}/{len(words)}] Testing: {word[:30]}...{Style.RESET_ALL}", end='\r')
            
            # هش کردن کلمه
            hashed = hash_func(word.encode()).hexdigest()
            
            if hashed == target_hash:
                found = word
                break
        
        elapsed = time.time() - start_time
        
        if found:
            print(f"\n{Fore.GREEN}✅ Password found: {found}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Time taken: {elapsed:.2f}s{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.RED}❌ Password not found in wordlist{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Time taken: {elapsed:.2f}s{Style.RESET_ALL}")
        
        return found


def analyze_password(password: str):
    """تابع تحلیل پسورد برای main.py"""
    tools = PasswordTools()
    result = tools.analyze_password(password)
    
    print(f"\n{Fore.CYAN}📊 Password Analysis{Style.RESET_ALL}")
    print("="*40)
    print(f"Password: {Fore.YELLOW}{password}{Style.RESET_ALL}")
    print(f"Length: {result['length']}")
    print(f"Has Lowercase: {result['has_lower']}")
    print(f"Has Uppercase: {result['has_upper']}")
    print(f"Has Digit: {result['has_digit']}")
    print(f"Has Special: {result['has_special']}")
    print(f"Entropy: {result['entropy']:.2f} bits")
    print(f"Strength: {result['color']}{result['strength']}{Style.RESET_ALL}")
    print()


def crack_hash(hash_value: str, wordlist: str, hash_type: str = "md5"):
    """تابع کرک هش برای main.py"""
    tools = PasswordTools()
    result = tools.crack_hash(hash_value, wordlist, hash_type)
    return result


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python3 crypto/password_tools.py analyze <password>")
        print("  python3 crypto/password_tools.py crack <hash> <wordlist> [hash_type]")
        sys.exit(1)
    
    if sys.argv[1] == "analyze":
        if len(sys.argv) < 3:
            print("[!] Password required")
            sys.exit(1)
        analyze_password(sys.argv[2])
    
    elif sys.argv[1] == "crack":
        if len(sys.argv) < 4:
            print("[!] Hash and wordlist required")
            sys.exit(1)
        hash_type = sys.argv[4] if len(sys.argv) > 4 else "md5"
        crack_hash(sys.argv[2], sys.argv[3], hash_type)
