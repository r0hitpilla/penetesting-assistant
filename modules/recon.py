"""
Recon Module — Port scan, service detection, banner grabbing, OS fingerprint.
Uses python-nmap when available, falls back to socket-based scanning.
"""
import socket
import concurrent.futures
import re

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995,
                1433, 1521, 2375, 3306, 3389, 4444, 5432, 5900, 6379, 8080, 8443,
                8888, 9200, 27017]

SERVICE_BANNERS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 2375: "Docker", 3306: "MySQL",
    3389: "RDP", 4444: "Metasploit", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "HTTP-Alt",
    9200: "Elasticsearch", 27017: "MongoDB",
}


def _grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        if port in (80, 8080, 8443, 443):
            s.send(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
        else:
            s.send(b"\r\n")
        banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
        s.close()
        return banner[:300] if banner else ""
    except Exception:
        return ""


def _scan_port(ip: str, port: int) -> dict | None:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.5)
        result = s.connect_ex((ip, port))
        s.close()
        if result == 0:
            banner = _grab_banner(ip, port)
            service = SERVICE_BANNERS.get(port, "unknown")
            # Try to detect service from banner
            if banner:
                bl = banner.lower()
                if "ssh" in bl:
                    service = "SSH"
                elif "ftp" in bl:
                    service = "FTP"
                elif "http" in bl or "html" in bl:
                    service = "HTTP"
                elif "smtp" in bl or "220" in banner[:3]:
                    service = "SMTP"
                elif "mysql" in bl:
                    service = "MySQL"
                elif "postgresql" in bl:
                    service = "PostgreSQL"
            return {"port": port, "state": "open", "service": service, "banner": banner}
        return None
    except Exception:
        return None


def run_recon(target: str, ports: list[int] | None = None, scan_type: str = "quick") -> dict:
    """
    Run reconnaissance on a target.
    scan_type: 'quick' (top ports), 'full' (all common), 'custom' (provided ports list)
    """
    results = {
        "target": target,
        "scan_type": scan_type,
        "open_ports": [],
        "os_hints": [],
        "hostname": "",
        "errors": [],
    }

    # Resolve hostname
    try:
        resolved = socket.gethostbyname(target)
        results["resolved_ip"] = resolved
        try:
            results["hostname"] = socket.gethostbyaddr(resolved)[0]
        except Exception:
            results["hostname"] = target
    except Exception as e:
        results["errors"].append(f"DNS resolution failed: {e}")
        return results

    ip = results["resolved_ip"]

    # Build port list
    if scan_type == "quick":
        port_list = [80, 443, 22, 21, 25, 8080, 8443, 3306, 5432, 3389, 445, 6379, 27017]
    elif scan_type == "full":
        port_list = COMMON_PORTS
    else:
        port_list = ports or COMMON_PORTS

    # Try nmap first
    try:
        import nmap
        nm = nmap.PortScanner()
        port_arg = ",".join(str(p) for p in port_list)
        nm.scan(ip, port_arg, arguments="-sV -O --script=banner -T4")
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                for port in nm[host][proto]:
                    port_info = nm[host][proto][port]
                    if port_info["state"] == "open":
                        results["open_ports"].append({
                            "port": port,
                            "state": "open",
                            "service": port_info.get("name", "unknown"),
                            "version": port_info.get("version", ""),
                            "product": port_info.get("product", ""),
                            "banner": port_info.get("script", {}).get("banner", ""),
                        })
            # OS detection
            if "osmatch" in nm[host]:
                for os_match in nm[host]["osmatch"][:3]:
                    results["os_hints"].append({
                        "name": os_match.get("name", ""),
                        "accuracy": os_match.get("accuracy", ""),
                    })
        return results
    except ImportError:
        pass
    except Exception as e:
        results["errors"].append(f"nmap failed, using socket scanner: {e}")

    # Socket-based fallback
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(_scan_port, ip, port): port for port in port_list}
        for future in concurrent.futures.as_completed(futures):
            r = future.result()
            if r:
                results["open_ports"].append(r)

    results["open_ports"].sort(key=lambda x: x["port"])

    # Guess OS from open ports
    open_set = {p["port"] for p in results["open_ports"]}
    if 445 in open_set or 135 in open_set or 3389 in open_set:
        results["os_hints"].append({"name": "Windows (likely)", "accuracy": "heuristic"})
    elif 22 in open_set and 80 in open_set:
        results["os_hints"].append({"name": "Linux/Unix (likely)", "accuracy": "heuristic"})

    return results
