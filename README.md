# TCP Port Scanner

A simple, threaded TCP connect-scanner built in Python for a cybersecurity
degree project. It checks a target host for open TCP ports, labels known
services, and attempts to grab a banner from each open port.

## ⚠️ Authorized Use Only

This tool is for **educational purposes** and should only be run against:
- Hosts you own (e.g. `127.0.0.1` / localhost)
- Systems you have **explicit written permission** to test

Scanning networks or hosts without authorization may be illegal under laws
such as the U.S. Computer Fraud and Abuse Act (or your local equivalent) and
similar legislation in other countries. All development and testing of this
tool was done exclusively against `127.0.0.1` (localhost).

## What it does

For each port in a given range, the scanner:
1. Attempts a full TCP handshake (`connect()`) — if it succeeds, the port is open
2. Looks up the port in a small dictionary of common services (SSH, HTTP, SMB, etc.)
3. If the port is open, tries to read a **banner** — the small identifying
   message some services send when you connect (e.g. an SSH server
   announcing its version)

It does **not** send exploit payloads, brute-force credentials, or perform
any vulnerability *exploitation* — it's purely a reconnaissance/discovery
tool, the first step in the classic recon phase of a security assessment.

## Requirements

- Python 3.8+
- No external dependencies (standard library only: `socket`, `argparse`,
  `concurrent.futures`)

## Usage

```bash
python3 main.py <target> -p <port_range> -t <timeout>
```

**Arguments:**
| Flag | Description | Default |
|------|-------------|---------|
| `target` | IP address or hostname to scan | *(required)* |
| `-p`, `--ports` | Port range (`1-1024`) or list (`22,80,443`) | `1-1024` |
| `-t`, `--timeout` | Socket timeout in seconds per port | `0.5` |

**Examples:**
```bash
# Scan the default range (1-1024) on localhost
python3 main.py 127.0.0.1

# Scan a wider custom range
python3 main.py 127.0.0.1 -p 1-9000

# Scan specific ports only
python3 main.py 127.0.0.1 -p 22,80,443,8000
```

## Verifying it works

Since a closed-port scan produces no visible output, the easiest way to
confirm the scanner is actually detecting live services is to create one
yourself:

```bash
# Terminal 1 — start a throwaway web server
python3 -m http.server 8000

# Terminal 2 — scan for it
python3 main.py 127.0.0.1 -p 1-9000
```

Port `8000` should appear in the results while the server is running, and
disappear once you stop it (`Ctrl+C` in Terminal 1) and re-scan.

## Sample output

```
Scanning 127.0.0.1 on 9000 ports...

Open ports found:
135 -> Microsoft RPC
445 -> SMB
5040 -> Windows Remote Management
8000 -> HTTP-Alt (common dev server)  | banner: HTTP/1.0 200 OK
```

## How it's built

- **`argparse`** — command-line interface, so target/ports/timeout don't
  need to be hardcoded
- **`ThreadPoolExecutor`** — scans ports concurrently (up to 100 at once)
  instead of one at a time, since each closed port otherwise costs a full
  timeout wait sequentially
- **`socket.connect_ex()`** — a TCP connect scan; considered the simplest,
  most reliable scan type (as opposed to SYN scans, which need raw socket
  privileges)
- **Banner grabbing** — after a port is confirmed open, a second short
  connection is made to read (or lightly prompt for) whatever text the
  service sends back, which can reveal the software/version running there

## Possible extensions

- JSON/CSV export for reporting
- UDP scanning
- Service/version fingerprinting beyond a raw banner read
- Rate limiting for scanning shared/external networks responsibly

---

# Findings — Localhost Port Scan

**Target:** `127.0.0.1` (localhost)
**Scan range:** 1–9000 (TCP), plus a targeted follow-up scan of Steam's known
Remote Play ports
**Tool:** Custom Python TCP connect-scanner (this project)

## Summary of Open Ports

| Port | Service | Banner Retrieved | Risk Notes |
|------|---------|-------------------|------------|
| 135 | Microsoft RPC | No (binary protocol) | Standard Windows service; expected on any Windows host. Not directly exposed to the internet by default, but historically a target for remote-code-execution exploits (e.g. Blaster worm, 2003) when exposed without a firewall. |
| 445 | SMB (file sharing) | No (binary protocol) | Standard Windows service for file/printer sharing. Notable for a severe historical vulnerability class — EternalBlue/MS17-010 (2017) — that enabled the WannaCry ransomware outbreak. Best practice: keep firewalled from any untrusted network; localhost exposure alone is low risk. |
| 5040 | Windows Remote Management (WSD/related) | No (binary protocol) | Windows-internal service tied to device discovery/connectivity features. Low risk on localhost; not typically internet-facing by default. |
| 27036 | Steam Remote Play | No (non-HTTP protocol) | Opened by the Steam client when Remote Play features are active. Identified via open-source research (Valve community/support references) and confirmed by correlating with Steam actively running during the scan. |

## Methodology Notes

- **Discovery:** Each port was identified as open via a TCP connect scan
  (`socket.connect_ex()`), confirming a completed three-way handshake.
- **Service identification:** Known ports were labeled using a static
  lookup table; the port 27036 finding specifically required external
  research to identify, since it isn't part of commonly published
  "well-known ports" lists (0–1023).
- **Banner grabbing limitation:** The scanner's banner-grabbing feature
  successfully retrieved a banner for HTTP-based services (see below) but
  returned nothing for 135, 445, and 27036. This is expected — these are
  binary protocols that require a protocol-specific handshake (e.g. an SMB
  negotiate request) rather than a plain-text probe. Retrieving banners
  from these services would require implementing protocol-aware probes,
  which is a natural extension of this project but outside its current
  scope.
- **Verification baseline:** Findings were cross-checked against a known
  service (`python3 -m http.server 8000`), which the scanner correctly
  detected while running and correctly stopped reporting once the service
  was shut down — confirming the scanner reflects live system state
  rather than false positives.

## Example: Verified HTTP Banner Grab

```
8000 -> HTTP-Alt (common dev server)  | banner: HTTP/1.0 200 OK
```

This confirms the banner-grabbing logic works correctly end-to-end for
text-based protocols, validating the approach even where it couldn't be
applied to the binary-protocol ports above.

## Conclusion

No unexpected or unauthorized services were found on the scanned host.
All open ports correspond to legitimate, explainable system or
application behavior (Windows core services and an actively running
Steam client). The exercise demonstrates the core reconnaissance
methodology used in real vulnerability assessments: enumerate open
ports, attempt service identification, cross-reference against known
CVEs/vulnerability history, and document findings with supporting
evidence rather than raw, unexplained output.
