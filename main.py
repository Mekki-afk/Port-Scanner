import argparse
import socket
from concurrent.futures import ThreadPoolExecutor

COMMON_PORTS = {
    22: "SSH",
    25: "SMTP",
    80: "HTTP",
    135: "Microsoft RPC",
    443: "HTTPS",
    445: "SMB",
    5040: "Windows Remote Management",
    3306: "MySQL",
    8000: "HTTP-Alt (common dev server)",
    27036: "Steam Remote Play",
    6463: "Discord"
}


def parse_args():
    parser = argparse.ArgumentParser(description="Simple TCP port scanner")
    parser.add_argument("target", help="IP address or hostname to scan")
    parser.add_argument("-p", "--ports", default="1-1024",
                         help="Port range, e.g. 1-1024 or 80,443,8080")
    parser.add_argument("-t", "--timeout", type=float, default=0.5,
                         help="Socket timeout in seconds")
    return parser.parse_args()


def parse_port_range(port_str):
    if "-" in port_str:
        start, end = port_str.split("-")
        return list(range(int(start), int(end) + 1))
    else:
        return [int(p) for p in port_str.split(",")]


def scan_port(target, port, timeout=0.5):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((target, port)) == 0
    except socket.gaierror:
        raise ValueError(f"Could not resolve host: {target}")


def scan_range(target, ports, timeout=0.5, max_workers=100):
    open_ports = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = executor.map(lambda p: (p, scan_port(target, p, timeout)), ports)
        for port, is_open in results:
            if is_open:
                open_ports.append(port)
    return sorted(open_ports)

def grab_banner(target, port, timeout=1.0):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((target, port))
            try:
                banner = s.recv(1024)
            except socket.timeout:
                banner = b""

            if not banner:
                try:
                    # Try a real HTTP request instead of a bare newline —
                    # most text-based services expect *something* resembling
                    # their actual protocol before they'll reply.
                    request = f"GET / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n".encode()
                    s.sendall(request)
                    banner = s.recv(1024)
                except (socket.timeout, OSError):
                    banner = b""

            text = banner.decode(errors="ignore").strip()
            return text if text else None
    except (socket.timeout, ConnectionResetError, OSError):
        return None

if __name__ == "__main__":
    args = parse_args()
    ports = parse_port_range(args.ports)

    print(f"Scanning {args.target} on {len(ports)} ports...")
    results = scan_range(args.target, ports, args.timeout)

    print("\nOpen ports found:")
    for port in results:
        service = COMMON_PORTS.get(port, "Unknown")
        banner = grab_banner(args.target, port)
        line = f"{port} -> {service}"
        if banner:
            first_line = banner.splitlines()[0][:80]
            line += f"  | banner: {first_line}"
        print(line)