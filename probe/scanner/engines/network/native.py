"""
Pure-Python port scanner as fallback when Go isn't available.
Uses asyncio for high concurrency.
"""

import asyncio
import json
import socket
import time
from typing import Dict, List, Optional, Set


# Top 100 ports (same as Go scanner)
TOP_100_PORTS = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119,
    123, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515,
    543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028,
    1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000,
    3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432,
    5631, 5666, 5800, 5900, 6000, 6001, 6646, 7000, 7070, 8000, 8008, 8009, 8080,
    8081, 8443, 8888, 9100, 9200, 10000, 32768, 49152, 49153, 49154, 49155, 49156,
    49157, 50000,
]

# Common service mappings
COMMON_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
    139: "netbios-ssn", 143: "imap", 443: "https", 445: "microsoft-ds",
    993: "imaps", 995: "pop3s", 1723: "pptp", 3306: "mysql",
    3389: "ms-wbt-server", 5432: "postgresql", 5900: "vnc",
    6379: "redis", 8080: "http-proxy", 8443: "https-alt",
    9200: "elasticsearch", 27017: "mongodb",
}


class NativePortScanner:
    """High-performance async port scanner (pure Python)."""
    
    def __init__(
        self,
        timeout: float = 2.0,
        concurrency: int = 100,
        grab_banners: bool = False,
    ):
        self.timeout = timeout
        self.concurrency = concurrency
        self.grab_banners = grab_banners
        self.semaphore = asyncio.Semaphore(concurrency)
    
    async def scan_port(self, target: str, port: int) -> Optional[Dict]:
        """Scan a single port."""
        async with self.semaphore:
            start = time.time()
            result = {
                "port": port,
                "protocol": "tcp",
                "state": "closed",
                "service": COMMON_SERVICES.get(port, ""),
                "response_time_ms": 0.0,
            }
            
            try:
                # Use asyncio.open_connection for async TCP
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target, port),
                    timeout=self.timeout
                )
                
                result["state"] = "open"
                result["response_time_ms"] = round((time.time() - start) * 1000, 2)
                
                # Try to grab banner
                if self.grab_banners:
                    banner = await self._grab_banner(reader, writer)
                    if banner:
                        result["banner"] = banner[:200]  # Limit length
                
                writer.close()
                try:
                    await writer.wait_closed()
                except:
                    pass
                
                return result
                
            except asyncio.TimeoutError:
                result["state"] = "filtered"
                result["response_time_ms"] = round((time.time() - start) * 1000, 2)
                return result
            except (ConnectionRefusedError, OSError):
                result["response_time_ms"] = round((time.time() - start) * 1000, 2)
                return result
    
    async def _grab_banner(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter
    ) -> str:
        """Try to grab service banner."""
        try:
            # Some services send banner immediately
            data = await asyncio.wait_for(reader.read(1024), timeout=1.0)
            if data:
                return data.decode('utf-8', errors='ignore').strip()
            
            # Try HTTP probe
            writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
            await writer.drain()
            
            data = await asyncio.wait_for(reader.read(1024), timeout=1.0)
            if data:
                return data.decode('utf-8', errors='ignore').strip()
                
        except Exception:
            pass
        
        return ""
    
    async def scan(
        self,
        target: str,
        ports: List[int],
    ) -> Dict:
        """Scan multiple ports concurrently."""
        start_time = time.time()
        
        # Create tasks
        tasks = [self.scan_port(target, port) for port in ports]
        results = await asyncio.gather(*tasks)
        
        # Filter to only open ports
        open_results = [r for r in results if r and r.get("state") == "open"]
        
        # Sort by port number
        open_results.sort(key=lambda x: x["port"])
        
        end_time = time.time()
        
        return {
            "target": target,
            "scan_type": "connect",
            "start_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(start_time)),
            "end_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(end_time)),
            "duration_ms": round((end_time - start_time) * 1000, 2),
            "total_ports_scanned": len(ports),
            "open_count": len(open_results),
            "results": open_results,
        }


def resolve_ports(ports: str | List[int]) -> List[int]:
    if isinstance(ports, list):
        return sorted(set(ports))
    if ports in {"top100", "top1000"}:
        return TOP_100_PORTS

    resolved = set()
    for item in ports.split(","):
        if "-" in item:
            start, end = (int(value) for value in item.split("-", 1))
            resolved.update(range(start, end + 1))
        else:
            resolved.add(int(item))
    if not resolved or min(resolved) < 1 or max(resolved) > 65535:
        raise ValueError(f"Invalid port specification: {ports}")
    return sorted(resolved)


def scan_target(
    target: str,
    ports: str | List[int] = "top100",
    timeout_ms: int = 2000,
    concurrency: int = 100,
    grab_banners: bool = False,
) -> Dict:
    """
    Synchronous wrapper for native scanner.
    
    Args:
        target: Hostname or IP to scan
        ports: "top100" or list of port numbers
        timeout_ms: Connection timeout
        concurrency: Max concurrent connections
        grab_banners: Whether to grab service banners
    
    Returns:
        Dict with scan results
    """
    port_list = resolve_ports(ports)
    
    scanner = NativePortScanner(
        timeout=timeout_ms / 1000.0,
        concurrency=concurrency,
        grab_banners=grab_banners,
    )
    
    return asyncio.run(scanner.scan(target, port_list))


# Convenience function for quick scans
def quick_scan(target: str, ports: str = "top100") -> List[Dict]:
    """Quick port scan returning just open ports."""
    result = scan_target(target, ports)
    return result.get("results", [])


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "scanme.nmap.org"
    print(f"Scanning {target} (top 100 ports)...")
    result = scan_target(target)
    print(f"Found {result['open_count']} open ports in {result['duration_ms']:.0f}ms")
    for r in result["results"]:
        service = f" ({r.get('service', '')})" if r.get('service') else ""
        print(f"  {r['port']}/tcp{service}")
