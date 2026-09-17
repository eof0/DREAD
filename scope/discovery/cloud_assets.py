"""
Cloud asset discovery (S3, CloudFront, Azure Blob, etc.)
"""

import re
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Set, Tuple
import requests

try:
    from discovery.dns_utils import resolve_cname
except ImportError:  # pragma: no cover - exercised depending on which sys.path root is set up
    from scope.discovery.dns_utils import resolve_cname

PROBE_WORKERS = 10

# CloudFront distributions have no guessable bucket-style name (unlike S3/GCS), so the
# only passive signal is a CNAME pointing at *.cloudfront.net. Check the bare domain
# plus the handful of hostnames orgs commonly point at a CDN.
CLOUDFRONT_CNAME_SUFFIX = ".cloudfront.net"
CLOUDFRONT_CANDIDATE_PREFIXES = ("", "www.", "cdn.", "static.", "assets.", "media.", "images.")


class CloudDiscovery:
    """Discover cloud assets associated with a domain."""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Scope/1.0 (Security Research)"
        })
    
    def scan(self, domain: str) -> Dict[str, List[Dict]]:
        """Scan for all cloud asset types (each category is independent)."""
        checks = {
            "s3_buckets": self._find_s3_buckets,
            "cloudfront": self._find_cloudfront,
            "azure_blob": self._find_azure_blobs,
            "gcs": self._find_gcs_buckets,
        }
        with ThreadPoolExecutor(max_workers=len(checks)) as pool:
            futures = {key: pool.submit(fn, domain) for key, fn in checks.items()}
            return {key: future.result() for key, future in futures.items()}
    
    def _probe_s3_bucket(self, probe: Tuple[str, str]) -> Optional[Dict]:
        """Check one bucket-name/region combination."""
        bucket, region = probe
        url = f"https://{bucket}.s3.{region}.amazonaws.com"
        try:
            response = self.session.head(url, timeout=5)
        except Exception:
            return None
        if response.status_code == 200:
            return {"bucket": bucket, "region": region, "url": url, "state": "exists", "public": True}
        if response.status_code == 403:
            return {"bucket": bucket, "region": region, "url": url, "state": "exists", "public": False}
        return None

    def _find_s3_buckets(self, domain: str) -> List[Dict]:
        """Find potential S3 buckets from various sources."""
        base_name = domain.replace(".", "-").lower()

        # Common bucket naming patterns
        patterns = [
            base_name,
            f"{base_name}-assets",
            f"{base_name}-static",
            f"{base_name}-media",
            f"{base_name}-uploads",
            f"{base_name}-backup",
            f"{base_name}-data",
            domain.replace(".", "").lower(),
        ]
        regions = ["us-east-1", "us-west-2", "eu-west-1"]

        # A bucket name is globally unique to S3, so only one region should
        # ever actually match; probing bucket x region combinations in
        # parallel and keeping the first hit per bucket is safe.
        probes = [(bucket, region) for bucket in patterns for region in regions]
        with ThreadPoolExecutor(max_workers=PROBE_WORKERS) as pool:
            probe_results = list(pool.map(self._probe_s3_bucket, probes))

        found_by_bucket: Dict[str, Dict] = {}
        for (bucket, _region), result in zip(probes, probe_results):
            if result is not None and bucket not in found_by_bucket:
                found_by_bucket[bucket] = result

        return [found_by_bucket[bucket] for bucket in patterns if bucket in found_by_bucket]
    
    def _probe_cloudfront_candidate(self, host: str) -> Optional[Dict]:
        cname = resolve_cname(host)
        if cname and cname.lower().rstrip(".").endswith(CLOUDFRONT_CNAME_SUFFIX):
            return {"hostname": host, "cname": cname}
        return None

    def _find_cloudfront(self, domain: str) -> List[Dict]:
        """Find CloudFront distributions fronting this domain or a common CDN alias."""
        candidates = [f"{prefix}{domain}" for prefix in CLOUDFRONT_CANDIDATE_PREFIXES]

        with ThreadPoolExecutor(max_workers=PROBE_WORKERS) as pool:
            results = list(pool.map(self._probe_cloudfront_candidate, candidates))

        return [r for r in results if r is not None]
    
    def _probe_azure_blob(self, account: str) -> Optional[Dict]:
        url = f"https://{account}.blob.core.windows.net"
        try:
            response = self.session.head(url, timeout=5)
        except Exception:
            return None
        if response.status_code != 404:
            return {"account": account, "url": url, "exists": True}
        return None

    def _find_azure_blobs(self, domain: str) -> List[Dict]:
        """Find Azure Blob storage accounts."""
        base = domain.replace(".", "").replace("-", "").lower()[:24]

        patterns = [
            base,
            f"{base}storage",
            f"{base}data",
            f"{base}assets",
        ]

        with ThreadPoolExecutor(max_workers=PROBE_WORKERS) as pool:
            results = list(pool.map(self._probe_azure_blob, patterns))

        return [r for r in results if r is not None]
    
    def _probe_gcs_bucket(self, bucket: str) -> Optional[Dict]:
        url = f"https://storage.googleapis.com/{bucket}"
        try:
            response = self.session.head(url, timeout=5)
        except Exception:
            return None
        if response.status_code == 200:
            return {"bucket": bucket, "url": url, "public": True}
        return None

    def _find_gcs_buckets(self, domain: str) -> List[Dict]:
        """Find Google Cloud Storage buckets."""
        base_name = domain.replace(".", "-").lower()

        patterns = [
            base_name,
            f"{base_name}-assets",
        ]

        with ThreadPoolExecutor(max_workers=PROBE_WORKERS) as pool:
            results = list(pool.map(self._probe_gcs_bucket, patterns))

        return [r for r in results if r is not None]
