#!/usr/bin/env python3
"""
PhishHunter - Recon and takedown tool for redirect chain phishing infrastructure
Built for defensive security research and abuse reporting
"""

import requests
import re
import json
import socket
import subprocess
import xml.etree.ElementTree as ET
from urllib.parse import urlparse, urljoin
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from typing import Optional
import ssl
import sys

# Disable SSL warnings for malicious sites with bad certs
requests.packages.urllib3.disable_warnings()

@dataclass
class DomainIntel:
    domain: str
    ips: list = field(default_factory=list)
    asn: str = ""
    org: str = ""
    location: str = ""
    registrar: str = ""
    created: str = ""
    nameservers: list = field(default_factory=list)
    abuse_contact: str = ""

@dataclass
class RedirectChain:
    source_file: str
    destination_domain: str
    full_redirect_code: str

@dataclass
class BucketIntel:
    bucket_name: str
    bucket_url: str
    files: list = field(default_factory=list)
    html_files: list = field(default_factory=list)
    image_files: list = field(default_factory=list)
    redirect_chains: list = field(default_factory=list)
    destination_domains: dict = field(default_factory=dict)


class PhishHunter:
    def __init__(self, verbose=True):
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        self.session.verify = False
        self.session.timeout = 10

    def log(self, msg, level="INFO"):
        if self.verbose:
            colors = {
                "INFO": "\033[94m",
                "SUCCESS": "\033[92m",
                "WARNING": "\033[93m",
                "ERROR": "\033[91m",
                "FOUND": "\033[95m"
            }
            reset = "\033[0m"
            print(f"{colors.get(level, '')}{level}{reset}: {msg}")

    def enumerate_gcs_bucket(self, bucket_name: str) -> Optional[BucketIntel]:
        """Enumerate a Google Cloud Storage bucket"""
        bucket_url = f"https://storage.googleapis.com/{bucket_name}/"
        self.log(f"Enumerating bucket: {bucket_name}")

        try:
            resp = self.session.get(bucket_url, timeout=15)
            if resp.status_code != 200:
                self.log(f"Bucket not listable (status {resp.status_code})", "WARNING")
                return None

            intel = BucketIntel(bucket_name=bucket_name, bucket_url=bucket_url)

            # Parse XML listing
            root = ET.fromstring(resp.content)
            ns = {'s3': 'http://doc.s3.amazonaws.com/2006-03-01'}

            for contents in root.findall('.//s3:Contents', ns):
                key = contents.find('s3:Key', ns)
                if key is not None:
                    filename = key.text
                    intel.files.append(filename)

                    if filename.endswith('.html'):
                        intel.html_files.append(filename)
                    elif filename.endswith(('.jpg', '.png', '.gif', '.jpeg')):
                        intel.image_files.append(filename)

            self.log(f"Found {len(intel.files)} files ({len(intel.html_files)} HTML, {len(intel.image_files)} images)", "SUCCESS")
            return intel

        except Exception as e:
            self.log(f"Error enumerating bucket: {e}", "ERROR")
            return None

    def extract_redirect_target(self, html_content: str) -> Optional[str]:
        """Extract redirect destination from HTML/JS"""
        patterns = [
            r"document\.location\.href\s*=\s*['\"]([^'\"]+)['\"]",
            r"window\.location\.href\s*=\s*['\"]([^'\"]+)['\"]",
            r"location\.replace\(['\"]([^'\"]+)['\"]\)",
            r"window\.location\s*=\s*['\"]([^'\"]+)['\"]",
            r"<meta[^>]+http-equiv=['\"]refresh['\"][^>]+content=['\"][^'\"]*url=([^'\"]+)['\"]",
        ]

        for pattern in patterns:
            match = re.search(pattern, html_content, re.IGNORECASE)
            if match:
                url = match.group(1)
                # Handle fragment concatenation patterns
                if "window.location.href.split('#')[1]" in html_content:
                    # It's a fragment redirector
                    return url.rstrip('/+ ')
                return url
        return None

    def analyze_redirectors(self, bucket_intel: BucketIntel) -> BucketIntel:
        """Fetch and analyze all HTML redirectors in a bucket"""
        self.log(f"Analyzing {len(bucket_intel.html_files)} HTML files...")

        def fetch_and_parse(filename):
            url = f"{bucket_intel.bucket_url}{filename}"
            try:
                resp = self.session.get(url, timeout=10)
                if resp.status_code == 200:
                    target = self.extract_redirect_target(resp.text)
                    if target:
                        parsed = urlparse(target)
                        domain = parsed.netloc or target.split('/')[0]
                        return RedirectChain(
                            source_file=filename,
                            destination_domain=domain,
                            full_redirect_code=resp.text.strip()[:500]
                        )
            except:
                pass
            return None

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(fetch_and_parse, f): f for f in bucket_intel.html_files}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    bucket_intel.redirect_chains.append(result)
                    domain = result.destination_domain
                    if domain not in bucket_intel.destination_domains:
                        bucket_intel.destination_domains[domain] = []
                    bucket_intel.destination_domains[domain].append(result.source_file)
                    self.log(f"{result.source_file} -> {domain}", "FOUND")

        return bucket_intel

    def dns_lookup(self, domain: str) -> list:
        """Get A records for domain"""
        try:
            return list(set(socket.gethostbyname_ex(domain)[2]))
        except:
            return []

    def whois_lookup(self, domain: str) -> dict:
        """Run whois and parse key fields"""
        info = {"registrar": "", "created": "", "abuse_contact": "", "nameservers": []}
        try:
            result = subprocess.run(['whois', domain], capture_output=True, text=True, timeout=15)
            output = result.stdout.lower()

            for line in result.stdout.split('\n'):
                line_lower = line.lower()
                if 'registrar:' in line_lower and not info['registrar']:
                    info['registrar'] = line.split(':', 1)[1].strip()
                elif 'creation date:' in line_lower and not info['created']:
                    info['created'] = line.split(':', 1)[1].strip()
                elif 'abuse' in line_lower and '@' in line:
                    match = re.search(r'[\w\.-]+@[\w\.-]+', line)
                    if match:
                        info['abuse_contact'] = match.group()
                elif 'name server:' in line_lower:
                    ns = line.split(':', 1)[1].strip()
                    if ns and ns not in info['nameservers']:
                        info['nameservers'].append(ns)
        except:
            pass
        return info

    def ip_info(self, ip: str) -> dict:
        """Get IP intelligence from ipinfo.io"""
        try:
            resp = self.session.get(f"https://ipinfo.io/{ip}/json", timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "asn": data.get("org", "").split()[0] if data.get("org") else "",
                    "org": " ".join(data.get("org", "").split()[1:]) if data.get("org") else "",
                    "location": f"{data.get('city', '')}, {data.get('region', '')}, {data.get('country', '')}"
                }
        except:
            pass
        return {"asn": "", "org": "", "location": ""}

    def gather_domain_intel(self, domain: str) -> DomainIntel:
        """Gather all intelligence on a domain"""
        self.log(f"Gathering intel on: {domain}")
        intel = DomainIntel(domain=domain)

        # DNS
        intel.ips = self.dns_lookup(domain)

        # Also check wildcard subdomain
        wildcard_ips = self.dns_lookup(f"randomtest123.{domain}")
        if wildcard_ips:
            self.log(f"Wildcard DNS detected on {domain}", "WARNING")

        # WHOIS
        whois_data = self.whois_lookup(domain)
        intel.registrar = whois_data['registrar']
        intel.created = whois_data['created']
        intel.abuse_contact = whois_data['abuse_contact']
        intel.nameservers = whois_data['nameservers']

        # IP info (use first IP)
        if intel.ips:
            ip_data = self.ip_info(intel.ips[0])
            intel.asn = ip_data['asn']
            intel.org = ip_data['org']
            intel.location = ip_data['location']

        return intel

    def generate_abuse_report(self, bucket_intel: BucketIntel, domain_intels: list) -> str:
        """Generate formatted abuse reports"""
        report = []
        report.append("=" * 70)
        report.append("PHISHING INFRASTRUCTURE ABUSE REPORT")
        report.append(f"Generated: {datetime.now().isoformat()}")
        report.append("=" * 70)

        # GCS Bucket section
        report.append("\n## GOOGLE CLOUD STORAGE BUCKET ABUSE")
        report.append(f"Bucket URL: {bucket_intel.bucket_url}")
        report.append(f"Total files: {len(bucket_intel.files)}")
        report.append(f"HTML redirectors: {len(bucket_intel.html_files)}")
        report.append(f"Image files (likely phishing lures): {len(bucket_intel.image_files)}")
        report.append("\nReport to: https://support.google.com/code/contact/cloud_platform_report")
        report.append("\nHTML files containing malicious redirects:")
        for chain in bucket_intel.redirect_chains:
            report.append(f"  - {chain.source_file} -> {chain.destination_domain}")

        # Destination domains section
        report.append("\n" + "=" * 70)
        report.append("## DESTINATION DOMAINS")
        report.append("=" * 70)

        for intel in domain_intels:
            report.append(f"\n### {intel.domain}")
            report.append(f"IPs: {', '.join(intel.ips) or 'N/A'}")
            report.append(f"ASN: {intel.asn or 'N/A'}")
            report.append(f"Org: {intel.org or 'N/A'}")
            report.append(f"Location: {intel.location or 'N/A'}")
            report.append(f"Registrar: {intel.registrar or 'N/A'}")
            report.append(f"Created: {intel.created or 'N/A'}")
            report.append(f"Abuse Contact: {intel.abuse_contact or 'N/A'}")
            report.append(f"Nameservers: {', '.join(intel.nameservers) or 'N/A'}")

            # Files pointing to this domain
            if intel.domain in bucket_intel.destination_domains:
                report.append(f"Redirectors pointing here: {bucket_intel.destination_domains[intel.domain]}")

        # Abuse email templates
        report.append("\n" + "=" * 70)
        report.append("## READY-TO-SEND ABUSE REPORTS")
        report.append("=" * 70)

        # Group by registrar/host
        abuse_contacts = {}
        for intel in domain_intels:
            if intel.abuse_contact:
                if intel.abuse_contact not in abuse_contacts:
                    abuse_contacts[intel.abuse_contact] = []
                abuse_contacts[intel.abuse_contact].append(intel)

        for contact, domains in abuse_contacts.items():
            report.append(f"\n--- TO: {contact} ---")
            report.append("Subject: Phishing Infrastructure Abuse Report")
            report.append("")
            report.append("Hello,")
            report.append("")
            report.append("I am reporting active phishing infrastructure hosted through your services:")
            report.append("")
            for intel in domains:
                report.append(f"Domain: {intel.domain}")
                report.append(f"IPs: {', '.join(intel.ips)}")
            report.append("")
            report.append("These domains are used in a redirect chain phishing attack:")
            report.append(f"1. Victim receives link to trusted Google Cloud Storage")
            report.append(f"2. GCS page redirects to your customer's domain")
            report.append(f"3. Final destination serves credential phishing")
            report.append("")
            report.append(f"Evidence: GCS bucket {bucket_intel.bucket_url}")
            report.append("")
            report.append("Please take immediate action to suspend these domains/IPs.")
            report.append("")
            report.append("Thank you.")
            report.append("-" * 40)

        return "\n".join(report)

    def hunt(self, bucket_name: str) -> str:
        """Main hunting workflow"""
        self.log("=" * 50)
        self.log("PHISHHUNTER - Starting reconnaissance")
        self.log("=" * 50)

        # Enumerate bucket
        bucket_intel = self.enumerate_gcs_bucket(bucket_name)
        if not bucket_intel:
            return "Failed to enumerate bucket"

        # Analyze redirectors
        bucket_intel = self.analyze_redirectors(bucket_intel)

        # Gather intel on all destination domains
        domain_intels = []
        for domain in bucket_intel.destination_domains.keys():
            intel = self.gather_domain_intel(domain)
            domain_intels.append(intel)

        # Generate report
        report = self.generate_abuse_report(bucket_intel, domain_intels)

        # Save report
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"phish_report_{timestamp}.txt"
        with open(report_file, 'w') as f:
            f.write(report)

        self.log(f"Report saved to: {report_file}", "SUCCESS")

        # Also save JSON intel for further processing
        json_file = f"phish_intel_{timestamp}.json"
        intel_data = {
            "bucket": asdict(bucket_intel),
            "domains": [asdict(d) for d in domain_intels]
        }
        # Convert dataclass instances in lists
        intel_data["bucket"]["redirect_chains"] = [asdict(r) for r in bucket_intel.redirect_chains]

        with open(json_file, 'w') as f:
            json.dump(intel_data, f, indent=2, default=str)

        self.log(f"JSON intel saved to: {json_file}", "SUCCESS")

        return report


def main():
    if len(sys.argv) < 2:
        print("Usage: phish_hunter.py <bucket_name_or_url>")
        print("Example: phish_hunter.py dfh7d89fh7df4j65djf4g65j4s6fg7jjj")
        print("Example: phish_hunter.py https://storage.googleapis.com/bucket123/file.html")
        sys.exit(1)

    target = sys.argv[1]

    # Extract bucket name from URL if needed
    if "storage.googleapis.com" in target:
        match = re.search(r'storage\.googleapis\.com/([^/]+)', target)
        if match:
            bucket_name = match.group(1)
        else:
            print("Could not parse bucket name from URL")
            sys.exit(1)
    else:
        bucket_name = target

    hunter = PhishHunter(verbose=True)
    report = hunter.hunt(bucket_name)
    print("\n" + report)


if __name__ == "__main__":
    main()
