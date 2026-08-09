#!/usr/bin/env python3
# main.py

import sys
import argparse
from colorama import init, Fore, Style

init(autoreset=True)

BANNER = f"""
{Fore.CYAN}╔═══════════════════════════════════════════╗
║   {Fore.YELLOW}🔒 SecToolKit v1.0{Fore.CYAN}                 ║
║   {Fore.GREEN}"Ethical Hacking Toolbox"{Fore.CYAN}        ║
╚═══════════════════════════════════════════╝{Style.RESET_ALL}
"""

def main():
    print(BANNER)
    
    parser = argparse.ArgumentParser(description="SecToolKit - Ethical Hacking Tools")
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    web_parser = subparsers.add_parser("web", help="Web vulnerability scanner")
    web_parser.add_argument("--url", required=True, help="Target URL")
    
    port_parser = subparsers.add_parser("port", help="Port scanner")
    port_parser.add_argument("--host", required=True, help="Target host")
    port_parser.add_argument("--ports", default="1-1024", help="Port range (e.g., 1-1000)")
    
    crack_parser = subparsers.add_parser("crack", help="Password cracker")
    crack_parser.add_argument("--hash", required=True, help="Hash to crack")
    crack_parser.add_argument("--wordlist", required=True, help="Wordlist file")
    
    log_parser = subparsers.add_parser("log", help="Analyze log files")
    log_parser.add_argument("--file", required=True, help="Log file path")
    
    args = parser.parse_args()
    
    if args.command == "web":
        print(f"{Fore.GREEN}[+] Scanning: {args.url}")
        
    elif args.command == "port":
        print(f"{Fore.GREEN}[+] Scanning host: {args.host}, ports: {args.ports}")
        
    elif args.command == "crack":
        print(f"{Fore.GREEN}[+] Cracking hash: {args.hash}")
        
    elif args.command == "log":
        print(f"{Fore.GREEN}[+] Analyzing: {args.file}")
        
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
