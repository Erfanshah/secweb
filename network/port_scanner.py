#!/usr/bin/env python3
"""
Port Scanner Module
Fast asynchronous port scanner using asyncio
"""

import asyncio
import socket
from colorama import Fore, Style
import time
from datetime import datetime

# پورت‌های معروف
COMMON_PORTS = {
    20: 'FTP-data',
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    111: 'RPC',
    135: 'MSRPC',
    139: 'NetBIOS',
    143: 'IMAP',
    443: 'HTTPS',
    445: 'SMB',
    993: 'IMAPS',
    995: 'POP3S',
    1723: 'PPTP',
    3306: 'MySQL',
    3389: 'RDP',
    5432: 'PostgreSQL',
    5900: 'VNC',
    6379: 'Redis',
    8080: 'HTTP-Alt',
    8443: 'HTTPS-Alt',
    27017: 'MongoDB',
}

class PortScanner:
    def __init__(self, host, ports="1-1024", timeout=1, max_workers=100):
        self.host = host
        self.ports = self.parse_ports(ports)
        self.timeout = timeout
        self.max_workers = max_workers
        self.open_ports = []
        self.closed_ports = []
        self.filtered_ports = []
    
    def parse_ports(self, ports_str):
        """تبدیل رشته پورت‌ها به لیست"""
        if '-' in ports_str:
            start, end = map(int, ports_str.split('-'))
            return list(range(start, end + 1))
        elif ',' in ports_str:
            return [int(p.strip()) for p in ports_str.split(',')]
        else:
            return [int(ports_str)]
    
    def get_service_name(self, port):
        """دریافت نام سرویس از پورت"""
        return COMMON_PORTS.get(port, 'Unknown')
    
    async def scan_port(self, port, semaphore):
        """اسکن یک پورت به صورت async"""
        async with semaphore:
            try:
                # ایجاد connection با timeout
                loop = asyncio.get_event_loop()
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.host, port, loop=loop),
                    timeout=self.timeout
                )
                writer.close()
                await writer.wait_closed()
                return port, 'open'
            except asyncio.TimeoutError:
                return port, 'filtered'
            except ConnectionRefusedError:
                return port, 'closed'
            except Exception:
                return port, 'filtered'
    
    async def scan_all_ports(self):
        """اسکن همه پورت‌ها به صورت همزمان"""
        print(f"{Fore.CYAN}[*] Scanning {len(self.ports)} ports on {self.host}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Timeout: {self.timeout}s, Workers: {self.max_workers}{Style.RESET_ALL}\n")
        
        semaphore = asyncio.Semaphore(self.max_workers)
        tasks = [self.scan_port(port, semaphore) for port in self.ports]
        
        start_time = time.time()
        results = await asyncio.gather(*tasks)
        elapsed = time.time() - start_time
        
        # طبقه‌بندی نتایج
        for port, status in results:
            if status == 'open':
                self.open_ports.append(port)
            elif status == 'filtered':
                self.filtered_ports.append(port)
            else:
                self.closed_ports.append(port)
        
        print(f"{Fore.GREEN}[+] Scan completed in {elapsed:.2f}s{Style.RESET_ALL}\n")
        return results
    
    def report(self):
        """گزارش نهایی"""
        print("="*60)
        print(f"{Fore.YELLOW} PORT SCAN REPORT{Style.RESET_ALL}")
        print("="*60)
        print(f"{Fore.CYAN}Target: {self.host}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Total ports scanned: {len(self.ports)}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Open ports: {len(self.open_ports)}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Filtered ports: {len(self.filtered_ports)}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Closed ports: {len(self.closed_ports)}{Style.RESET_ALL}")
        print()
        
        if self.open_ports:
            print(f"{Fore.GREEN} Open Ports:{Style.RESET_ALL}")
            for port in sorted(self.open_ports):
                service = self.get_service_name(port)
                print(f"    {Fore.GREEN}{port}{Style.RESET_ALL} - {service}")
        else:
            print(f"{Fore.YELLOW}⚠️  No open ports found{Style.RESET_ALL}")


def scan_ports(host, ports="1-1024", threads=100):
    """تابع اصلی برای صدا زدن از main.py"""
    scanner = PortScanner(host, ports, timeout=1, max_workers=threads)
    
    try:
        # اجرای اسکن async
        asyncio.run(scanner.scan_all_ports())
        scanner.report()
        return scanner.open_ports
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
        return []


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        host = sys.argv[1]
        ports = sys.argv[2] if len(sys.argv) > 2 else "1-1024"
        threads = int(sys.argv[3]) if len(sys.argv) > 3 else 100
        scan_ports(host, ports, threads)
    else:
        print("Usage: python3 network/port_scanner.py <host> [ports] [threads]")
        print("Example: python3 network/port_scanner.py 192.168.1.1 1-1000 200")
