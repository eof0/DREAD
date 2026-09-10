# scanner/analysis/attack_chains.py

ATTACK_CHAINS = [
    {
        "id": "chain_sensitive_files",
        "title": "Sensitive File Exposure → Credential Theft → System Compromise",
        "kill_chain_stage": "Initial Access",
        "indicator_keywords": [
            "Exposed Sensitive File",
            ".env",
            ".git",
            "backup",
            "database.sql",
            "dump.sql"
        ],
        "business_impact": (
            "Attackers may obtain database credentials, API keys, or internal code, "
            "leading to full system compromise or data breach."
        ),
    },
    {
        "id": "chain_tls_weakness",
        "title": "Weak TLS Configuration → MITM → Session Hijacking",
        "kill_chain_stage": "Credential Access",
        "indicator_keywords": [
            "TLS",
            "weak cipher",
            "expired certificate",
            "self-signed",
            "protocol downgrade"
        ],
        "business_impact": (
            "Weak or misconfigured TLS allows attackers to intercept or modify traffic, "
            "steal credentials, and impersonate users."
        ),
    },
    {
        "id": "chain_network_exposure",
        "title": "Open Ports → Attack Surface Expansion → Service Exploitation",
        "kill_chain_stage": "Reconnaissance",
        "indicator_keywords": [
            "Open Network Port",
            "Service Detected",
            "Port"
        ],
        "business_impact": (
            "Public-facing services expand the external attack surface and increase the risk "
            "of exploitation via exposed ports or outdated software."
        ),
    },
    {
        "id": "chain_cve_exploit",
        "title": "Known Vulnerable Software → CVE Exploitation → Remote Compromise",
        "kill_chain_stage": "Initial Access",
        "indicator_keywords": [
            "CVE",
            "vulnerable",
            "affected version",
            "known exploit"
        ],
        "business_impact": (
            "The presence of known CVEs may allow attackers to remotely exploit the target "
            "through publicly available or weaponized exploits."
        ),
    },
]
