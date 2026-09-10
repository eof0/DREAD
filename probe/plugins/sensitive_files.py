from typing import List, Dict
from urllib.parse import urljoin, urlparse
import hashlib
import re

from plugins.base_plugin import BasePlugin, Finding


class SensitiveFilesPlugin(BasePlugin):
    """
    Checks for exposed sensitive files with improved accuracy.
    
    Improvements:
    - Better soft-404 detection
    - Checks for redirects
    - Validates content type mismatches
    - Content analysis to detect custom error pages
    """

    WARNING_PATHS = {"admin", "admin/"}

    SENSITIVE_PATHS = [
        (".env", "high"),
        (".git/config", "high"),
        (".git/HEAD", "high"),
        ("web.config", "medium"),
        (".htaccess", "medium"),
        ("composer.json", "low"),
        ("package.json", "low"),
        ("package-lock.json", "low"),
        ("yarn.lock", "low"),
        (".DS_Store", "low"),
        ("backup.zip", "high"),
        ("backup.sql", "high"),
        ("dump.sql", "high"),
        ("db.sql", "high"),
        ("database.sql", "high"),
        ("admin", "medium"),
        ("admin/", "medium"),
        ("phpinfo.php", "high"),
        ("info.php", "high"),
        ("test.php", "low"),
        ("config.php.bak", "high"),
        ("config.php~", "high"),
        ("wp-config.php.bak", "high"),
        (".env.local", "high"),
        (".env.production", "high"),
        (".aws/credentials", "critical"),
        ("id_rsa", "critical"),
        ("id_rsa.pub", "low"),
    ]

    # Patterns that indicate a soft 404 or redirect page
    SOFT_404_PATTERNS = [
        re.compile(r"404\s*not\s*found", re.I),
        re.compile(r"page\s*not\s*found", re.I),
        re.compile(r"error\s*page", re.I),
        re.compile(r"redirecting", re.I),
        re.compile(r"click\s*here\s*to\s*continue", re.I),
        re.compile(r"cloudflare", re.I),  # Cloudflare error pages
        re.compile(r"ray\s*id", re.I),    # Cloudflare Ray ID
    ]

    def get_name(self) -> str:
        return "sensitive_files"

    def get_description(self) -> str:
        return "Checks for exposed sensitive files with soft-404 detection"

    def _hash_body(self, content: bytes) -> str:
        return hashlib.md5(content).hexdigest()

    def _is_soft_404(self, response, baseline_content: bytes) -> bool:
        """Check if response is a soft 404 or error page."""
        content = response.content
        content_str = content.decode('utf-8', errors='ignore')[:2000]
        
        # Check for redirect status codes
        if response.status_code in [301, 302, 307, 308]:
            return True
            
        # Check for common soft 404 patterns
        for pattern in self.SOFT_404_PATTERNS:
            if pattern.search(content_str):
                return True
        
        # If content is very similar to baseline (same error page)
        if len(content) > 100:
            content_hash = self._hash_body(content)
            baseline_hash = self._hash_body(baseline_content)
            if content_hash == baseline_hash:
                return True
        
        # Check for Cloudflare-style responses
        cf_headers = ['cf-ray', 'cf-cache-status', 'cloudflare']
        for header in cf_headers:
            if header in response.headers.get('Server', '').lower():
                # Likely a Cloudflare block page
                if response.status_code in [403, 503]:
                    return True
        
        return False

    def _is_valid_sensitive_file(self, response, path: str) -> bool:
        """Validate that the response is actually the sensitive file."""
        content_type = response.headers.get('Content-Type', '').lower()
        
        # Check content type hints
        if path.endswith('.php'):
            # PHP files should return PHP or HTML, not be served as raw text
            if 'text/plain' in content_type and len(response.content) > 1000:
                # Large text response for PHP is likely source code (bad!)
                return True
        
        if path.endswith('.json'):
            # Should be application/json
            if 'json' in content_type or response.content.strip().startswith(b'{') or response.content.strip().startswith(b'['):
                try:
                    import json
                    json.loads(response.content)
                    return True
                except:
                    pass
        
        if path in ['.env', '.env.local', '.env.production']:
            # .env files should contain KEY=VALUE patterns
            content = response.content.decode('utf-8', errors='ignore')
            if '=' in content and any(line.strip().startswith(('DB_', 'APP_', 'API_', 'SECRET_', 'KEY=')) for line in content.split('\n')[:20]):
                return True
        
        if '.git/' in path:
            # Git files should have specific content
            content = response.content.decode('utf-8', errors='ignore')
            if 'ref:' in content or '[core]' in content:
                return True
        
        # Default: if status is 200 and content is reasonable, assume valid
        return response.status_code == 200 and len(response.content) > 10

    def scan(self, url_info: Dict, request_handler) -> List[Finding]:
        findings: List[Finding] = []
        verbose = getattr(request_handler, 'verbose', False)

        if url_info.get("depth", 0) > 0:
            return findings

        base_url = url_info["url"]
        parsed = urlparse(base_url)
        root_url = f"{parsed.scheme}://{parsed.netloc}/"

        if verbose:
            print(f"[VERBOSE] [sensitive_files] Starting scan on {root_url}")
            print(f"[VERBOSE] [sensitive_files] Checking {len(self.SENSITIVE_PATHS)} sensitive paths")

        # Get baseline (homepage) for comparison
        baseline = request_handler.get(root_url)
        if baseline is None:
            if verbose:
                print(f"[VERBOSE] [sensitive_files] Failed to get baseline from {root_url}")
            return findings

        baseline_hash = self._hash_body(baseline.content)
        baseline_len = len(baseline.content)

        checked = 0
        for path, severity in self.SENSITIVE_PATHS:
            test_url = urljoin(root_url, path)
            if verbose:
                print(f"[VERBOSE] [sensitive_files] Checking: {path} -> {test_url}")

            response = request_handler.get(test_url)
            checked += 1

            if response is None:
                if verbose:
                    print(f"[VERBOSE] [sensitive_files]   No response for {path}")
                continue

            if verbose:
                print(f"[VERBOSE] [sensitive_files]   Status: {response.status_code}, Size: {len(response.content)}")

            # Skip non-200 responses (unless it's a 200 that looks like a block)
            if response.status_code != 200:
                if verbose:
                    print(f"[VERBOSE] [sensitive_files]   Skipping {path}: non-200 status")
                continue

            # Check for soft 404 / error page
            if self._is_soft_404(response, baseline.content):
                if verbose:
                    print(f"[VERBOSE] [sensitive_files]   Skipping {path}: detected as soft 404/error page")
                continue

            # Hash comparison with baseline
            body_hash = self._hash_body(response.content)
            if body_hash == baseline_hash:
                if verbose:
                    print(f"[VERBOSE] [sensitive_files]   Skipping {path}: same content as baseline")
                continue

            # Size check - if very similar to baseline, likely same error page
            len_diff = abs(len(response.content) - baseline_len)
            if len_diff < 100:
                if verbose:
                    print(f"[VERBOSE] [sensitive_files]   Skipping {path}: size too similar to baseline")
                continue

            # Validate it's actually the sensitive file
            if not self._is_valid_sensitive_file(response, path):
                if verbose:
                    print(f"[VERBOSE] [sensitive_files]   Skipping {path}: failed validation")
                continue

            if verbose:
                print(f"[VERBOSE] [sensitive_files]   FOUND: {path} is exposed!")

            is_warning = path in self.WARNING_PATHS
            findings.append(
                Finding(
                    plugin_name=self.get_name(),
                    severity="info" if is_warning else severity,
                    title=(
                        f"Potential Sensitive Path: {path}"
                        if is_warning
                        else f"Exposed Sensitive File: {path}"
                    ),
                    description=(
                        f"The path '{path}' returned HTML. This is an observation only; "
                        "a route name alone does not prove sensitive data is exposed."
                        if is_warning
                        else f"The file '{path}' is publicly accessible and appears to contain legitimate sensitive data."
                    ),
                    url=test_url,
                    evidence={
                        "path": path,
                        "content_length": len(response.content),
                        "content_type": response.headers.get("Content-Type", ""),
                        "status_code": response.status_code,
                    },
                    remediation=(
                        "Review whether this route is intentional, such as an authenticated area or honeypot."
                        if is_warning
                        else f"Remove '{path}' from public access or restrict via authentication/authorization."
                    ),
                    metadata={"classification": "warning"} if is_warning else {},
                )
            )

        if verbose:
            print(f"[VERBOSE] [sensitive_files] Scan complete. Checked {checked} paths, found {len(findings)} issues.")

        return findings
