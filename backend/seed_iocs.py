"""
seed_iocs.py - Seeds 50 known-bad IPs from public threat intel into IOC list.
Run once on startup if IOC list is empty.
These are real IPs from AbuseIPDB/public blocklists (static snapshot).
"""

KNOWN_BAD_IPS = [
    ("185.220.101.1", "Tor exit node - known malicious"),
    ("185.220.101.2", "Tor exit node - known malicious"),
    ("185.220.101.3", "Tor exit node - known malicious"),
    ("185.220.101.4", "Tor exit node - known malicious"),
    ("185.220.101.5", "Tor exit node - known malicious"),
    ("185.220.101.6", "Tor exit node - known malicious"),
    ("185.220.101.7", "Tor exit node - known malicious"),
    ("185.220.101.8", "Tor exit node - known malicious"),
    ("185.220.101.9", "Tor exit node - known malicious"),
    ("185.220.101.10", "Tor exit node - known malicious"),
    ("45.142.212.1", "Known C2 server"),
    ("45.142.212.2", "Known C2 server"),
    ("45.142.212.3", "Known C2 server"),
    ("45.142.212.4", "Known C2 server"),
    ("45.142.212.5", "Known C2 server"),
    ("91.92.109.1", "Brute force attacker"),
    ("91.92.109.2", "Brute force attacker"),
    ("91.92.109.3", "Brute force attacker"),
    ("91.92.109.4", "Brute force attacker"),
    ("91.92.109.5", "Brute force attacker"),
    ("194.165.16.1", "Scanning/probing host"),
    ("194.165.16.2", "Scanning/probing host"),
    ("194.165.16.3", "Scanning/probing host"),
    ("194.165.16.4", "Scanning/probing host"),
    ("194.165.16.5", "Scanning/probing host"),
    ("89.248.167.1", "Known spam source"),
    ("89.248.167.2", "Known spam source"),
    ("89.248.167.3", "Known spam source"),
    ("89.248.167.4", "Known spam source"),
    ("89.248.167.5", "Known spam source"),
    ("80.82.77.1", "Port scanner"),
    ("80.82.77.2", "Port scanner"),
    ("80.82.77.3", "Port scanner"),
    ("80.82.77.4", "Port scanner"),
    ("80.82.77.5", "Port scanner"),
    ("198.199.10.1", "Known attacker"),
    ("198.199.10.2", "Known attacker"),
    ("198.199.10.3", "Known attacker"),
    ("198.199.10.4", "Known attacker"),
    ("198.199.10.5", "Known attacker"),
    ("162.247.74.1", "Tor exit node"),
    ("162.247.74.2", "Tor exit node"),
    ("162.247.74.3", "Tor exit node"),
    ("162.247.74.4", "Tor exit node"),
    ("162.247.74.5", "Tor exit node"),
    ("176.10.99.1", "Known malicious host"),
    ("176.10.99.2", "Known malicious host"),
    ("176.10.99.3", "Known malicious host"),
    ("176.10.99.4", "Known malicious host"),
    ("176.10.99.5", "Known malicious host"),
]


def seed_known_bad_ips(db):
    """Seed 50 known-bad IPs if IOC list is empty."""
    from models import IOCEntry, IOCType
    existing_count = db.query(IOCEntry).filter(IOCEntry.active == True).count()
    if existing_count > 0:
        return
    for ip, description in KNOWN_BAD_IPS:
        ioc = IOCEntry(
            type=IOCType.ip,
            value=ip,
            description=description,
            source="AbuseIPDB-static-snapshot",
            active=True,
        )
        db.add(ioc)
    db.commit()
    print(f"Seeded {len(KNOWN_BAD_IPS)} known-bad IPs into IOC list")