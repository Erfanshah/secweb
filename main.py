#!/usr/bin/env python3
"""
SecToolKit - Ethical Hacking Toolbox
Main entry point for all security tools
"""

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
    
    parser = argparse.ArgumentParser(
        description="SecToolKit - Collection of ethical hacking tools",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py web --url "http://testphp.vulnweb.com/artists.php?artist=1"
  python main.py port --host 192.168.1.1 --ports 1-1000
  python main.py crack --hash 5f4dcc3b5aa765d61d8327deb882cf99 --wordlist rockyou.txt
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # ====================
    web_parser = subparsers.add_parser("web", help="Web vulnerability scanner (XSS, SQLi, etc)")
    web_parser.add_argument("--url", required=True, help="Target URL to scan")
    web_parser.add_argument("--type", default="xss", choices=["xss", "sqli", "all"], 
                           help="Type of scan (default: xss)")
    
    # ==================== 
    port_parser = subparsers.add_parser("port", help="Advanced port scanner")
    port_parser.add_argument("--host", required=True, help="Target host (IP or domain)")
    port_parser.add_argument("--ports", default="1-1024", help="Port range (e.g., 1-1000 or 80,443,8080)")
    port_parser.add_argument("--threads", type=int, default=100, help="Number of threads (default: 100)")
    
    # ====================
    crack_parser = subparsers.add_parser("crack", help="Password hash cracker")
    crack_parser.add_argument("--hash", required=True, help="Hash to crack (MD5, SHA1, SHA256)")
    crack_parser.add_argument("--wordlist", required=True, help="Path to wordlist file")
    crack_parser.add_argument("--type", default="md5", choices=["md5", "sha1", "sha256"], 
                             help="Hash type (default: md5)")
    
    # ==================== 
    log_parser = subparsers.add_parser("log", help="Analyze log files for attacks")
    log_parser.add_argument("--file", required=True, help="Path to log file (Apache/Nginx format)")
    log_parser.add_argument("--type", default="apache", choices=["apache", "nginx"], 
                           help="Log format (default: apache)")
    
    # ==================== 
    monitor_parser = subparsers.add_parser("monitor", help="File integrity monitor")
    monitor_parser.add_argument("--dir", required=True, help="Directory to monitor")
    monitor_parser.add_argument("--init", action="store_true", help="Initialize baseline hashes")
    
    args = parser.parse_args()
    
    # ==================== 
    
    if args.command == "web":
        print(f"{Fore.GREEN}[+] Starting web scan on: {args.url}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Scan type: {args.type}{Style.RESET_ALL}\n")
        
        if args.type in ["xss", "all"]:
            from scanner.xss import scan_url
            scan_url(args.url)

    if args.type in ["sqli", "all"]:
            from scanner.sqli import scan_sqli
            scan_sqli(args.url)
        
    
    elif args.command == "port":
        print(f"{Fore.GREEN}[+] Starting port scan on: {args.host}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Ports: {args.ports}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Threads: {args.threads}{Style.RESET_ALL}\n")
        print(f"{Fore.YELLOW}[!] Port scanner coming soon...{Style.RESET_ALL}")
        # from network.port_scanner import scan_ports
        # scan_ports(args.host, args.ports, args.threads)
    
    elif args.command == "crack":
        print(f"{Fore.GREEN}[+] Starting password cracker{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Hash: {args.hash}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Wordlist: {args.wordlist}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Type: {args.type}{Style.RESET_ALL}\n")
        print(f"{Fore.YELLOW}[!] Password cracker coming soon...{Style.RESET_ALL}")
        # from crypto.password_tools import crack_hash
        # crack_hash(args.hash, args.wordlist, args.type)
    
    elif args.command == "log":
        print(f"{Fore.GREEN}[+] Analyzing log file: {args.file}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Format: {args.type}{Style.RESET_ALL}\n")
        print(f"{Fore.YELLOW}[!] Log analyzer coming soon...{Style.RESET_ALL}")
        # from monitor.log_analyzer import analyze_log
        # analyze_log(args.file, args.type)
    
    elif args.command == "monitor":
        print(f"{Fore.GREEN}[+] File integrity monitor{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Directory: {args.dir}{Style.RESET_ALL}")
        if args.init:
            print(f"{Fore.CYAN}[*] Initializing baseline...{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[!] Integrity monitor coming soon...{Style.RESET_ALL}")
        # from monitor.file_integrity import init_monitor, check_integrity
        # if args.init: init_monitor(args.dir)
        # else: check_integrity(args.dir)
    
    else:
        parser.print_help()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")
        sys.exit(1)
