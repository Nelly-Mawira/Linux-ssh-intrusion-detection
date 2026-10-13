#!/usr/bin/env python3
"""
SOC Phase 1: Automated SSH Auth Log Parser & Threat Detector
Tailored for Modern Ubuntu Log Formats (ISO 8601 & sshd-session)
"""

import re
import datetime
from collections import defaultdict

LOG_FILE = "/var/log/auth.log"
FAILED_THRESHOLD = 5  # Alert trigger threshold

def parse_auth_log():
    failed_attempts = defaultdict(int)

    # Regex tailored for ISO timestamp and sshd/sshd-session
    log_pattern = re.compile(
        r"(?P<date>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}).*sshd(?:-session)?.*Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    )

    try:
        with open(LOG_FILE, "r") as f:
            for line in f:
                match = log_pattern.search(line)
                if match:
                    ip = match.group("ip")
                    failed_attempts[ip] += 1
    except FileNotFoundError:
        print(f"[!] Error: {LOG_FILE} not found. Run with sudo permissions.")
        return

    print("=" * 60)
    print(f" SOC AUTH DETECTION REPORT - {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    flagged_ips = []
    for ip, count in failed_attempts.items():
        if count >= FAILED_THRESHOLD:
            print(f"[ALERT] SUSPICIOUS BRUTE-FORCE DETECTED!")
            print(f"        Attacker IP: {ip}")
            print(f"        Total Failed Attempts: {count}")
            flagged_ips.append(ip)
        else:
            print(f"[INFO] IP {ip} recorded {count} failed attempt(s).")

    print("-" * 60)
    if flagged_ips:
        print("RECOMMENDED REMEDIATION: Block IPs using `sudo ufw deny from <IP>`")
    else:
        print("No brute-force activity exceeding threshold detected.")
    print("=" * 60)

if __name__ == "__main__":
    parse_auth_log()
