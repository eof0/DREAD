"""
Screenshot Evidence Capture (Async)

Captures visual evidence of security findings using Playwright.
Optimized for high/critical findings.

Optional dependency:
    pip install playwright
    playwright install chromium

Usage:
    from scanner.evidence.screenshotter import Screenshotter
    
    screenshotter = Screenshotter()
    path = await screenshotter.capture("https://example.com/admin")
"""

import asyncio
import os
from pathlib import Path
from typing import Optional, Dict
from datetime import datetime


class Screenshotter:
    """
    Async screenshot capture using Playwright.
    Falls back to sync methods if playwright not available.
    """
    
    def __init__(
        self,
        output_dir: str = "scan_results/evidence",
        viewport: Dict = None,
        timeout: int = 30000,
    ):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.viewport = viewport or {"width": 1920, "height": 1080}
        self.timeout = timeout
        self._playwright = None
        self._browser = None
    
    async def _ensure_browser(self):
        """Initialize Playwright browser."""
        if self._browser is None:
            try:
                from playwright.async_api import async_playwright
            except ImportError:
                raise ImportError(
                    "Playwright not installed. "
                    "Install with: pip install playwright && playwright install chromium"
                )
            
            self._playwright = await async_playwright().start()
            self._browser = await self._playwright.chromium.launch(headless=True)
    
    async def capture(
        self,
        url: str,
        output_path: Optional[str] = None,
        full_page: bool = True,
        wait_for_selector: Optional[str] = None,
    ) -> Optional[str]:
        """
        Capture screenshot of URL.
        
        Args:
            url: URL to screenshot
            output_path: Where to save (auto-generated if None)
            full_page: Capture full page or viewport only
            wait_for_selector: Wait for element before capture
        
        Returns:
            Path to screenshot or None if failed
        """
        await self._ensure_browser()
        
        # Generate output path if not provided
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            url_hash = hash(url) % 10000
            filename = f"evidence_{timestamp}_{url_hash:04d}.png"
            output_path = self.output_dir / filename
        else:
            output_path = Path(output_path)
        
        context = None
        page = None
        
        try:
            # Create context
            context = await self._browser.new_context(
                viewport=self.viewport,
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            )
            
            page = await context.new_page()
            
            # Navigate
            response = await page.goto(
                url,
                timeout=self.timeout,
                wait_until="networkidle"
            )
            
            if not response:
                print(f"[!] Failed to load: {url}")
                return None
            
            # Wait for specific element if requested
            if wait_for_selector:
                try:
                    await page.wait_for_selector(
                        wait_for_selector,
                        timeout=5000
                    )
                except:
                    pass  # Continue even if selector not found
            
            # Create parent directories
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Capture screenshot
            await page.screenshot(
                path=str(output_path),
                full_page=full_page,
                type="png"
            )
            
            return str(output_path)
            
        except Exception as e:
            print(f"[!] Screenshot failed for {url}: {e}")
            return None
            
        finally:
            if page:
                await page.close()
            if context:
                await context.close()
    
    async def capture_finding(
        self,
        finding: Dict,
        wait_for_selector: Optional[str] = None,
    ) -> Optional[str]:
        """
        Capture screenshot for a finding.
        
        Args:
            finding: Finding dict with 'url' key
            wait_for_selector: Optional CSS selector to wait for
        
        Returns:
            Path to screenshot
        """
        url = finding.get("url", "")
        if not url or not url.startswith(("http://", "https://")):
            return None
        
        # Generate meaningful filename
        plugin = finding.get("plugin_name", "unknown")
        severity = finding.get("severity", "info")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        filename = f"{severity}_{plugin}_{timestamp}.png"
        output_path = self.output_dir / filename
        
        return await self.capture(url, output_path, wait_for_selector=wait_for_selector)
    
    async def capture_many(
        self,
        urls: list,
        max_concurrent: int = 3,
    ) -> Dict[str, Optional[str]]:
        """
        Capture multiple screenshots concurrently.
        
        Args:
            urls: List of URLs to capture
            max_concurrent: Max concurrent captures
        
        Returns:
            Dict mapping URL to screenshot path (or None)
        """
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def capture_with_limit(url):
            async with semaphore:
                return url, await self.capture(url)
        
        tasks = [capture_with_limit(url) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        return {
            url: path if not isinstance(path, Exception) else None
            for url, path in results
        }
    
    async def close(self):
        """Clean up resources."""
        if self._browser:
            await self._browser.close()
        if self._playwright:
            await self._playwright.stop()
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()


class EvidenceCollector:
    """
    Collects evidence for findings during scans.
    Integrates with event bus.
    """
    
    def __init__(
        self,
        output_dir: str = "scan_results/evidence",
        min_severity: str = "high",
        capture_screenshots: bool = True,
    ):
        self.output_dir = Path(output_dir)
        self.min_severity = min_severity
        self.capture_screenshots = capture_screenshots
        self.screenshotter: Optional[Screenshotter] = None
        self.collected = []
        
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        self.min_level = severity_order.get(min_severity, 1)
    
    async def initialize(self):
        """Initialize screenshotter if enabled."""
        if self.capture_screenshots:
            try:
                self.screenshotter = Screenshotter(output_dir=self.output_dir)
            except ImportError:
                print("[!] Playwright not available, screenshots disabled")
                self.capture_screenshots = False
    
    def should_capture(self, finding: Dict) -> bool:
        """Check if finding warrants evidence collection."""
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        finding_level = severity_order.get(finding.get("severity", "info"), 4)
        
        # Always capture for high/critical
        if finding_level <= self.min_level:
            return True
        
        # Check for visual evidence indicators
        title = finding.get("title", "").lower()
        visual_indicators = [
            "admin", "panel", "dashboard", "console",
            "directory", "listing", "exposed", "backup"
        ]
        
        return any(ind in title for ind in visual_indicators)
    
    async def collect(self, finding: Dict) -> Dict:
        """
        Collect all evidence types for a finding.
        
        Returns:
            Dict with evidence paths/info
        """
        if not self.should_capture(finding):
            return {}
        
        evidence = {
            "timestamp": datetime.now().isoformat(),
            "finding_title": finding.get("title"),
        }
        
        # Screenshot
        if self.capture_screenshots and self.screenshotter:
            screenshot_path = await self.screenshotter.capture_finding(finding)
            if screenshot_path:
                evidence["screenshot"] = screenshot_path
        
        # Store HTTP response (if available)
        # This could be extended to save full HTTP exchange
        
        self.collected.append(evidence)
        return evidence
    
    async def collect_many(
        self,
        findings: list,
        max_concurrent: int = 3,
    ) -> list:
        """Collect evidence for multiple findings."""
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def collect_with_limit(finding):
            async with semaphore:
                return await self.collect(finding)
        
        tasks = [collect_with_limit(f) for f in findings if self.should_capture(f)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        return [
            r for r in results
            if not isinstance(r, Exception) and r
        ]
    
    def get_summary(self) -> Dict:
        """Get summary of collected evidence."""
        return {
            "total_collected": len(self.collected),
            "screenshots": sum(1 for e in self.collected if "screenshot" in e),
            "output_directory": str(self.output_dir),
        }
    
    async def close(self):
        """Clean up."""
        if self.screenshotter:
            await self.screenshotter.close()


# Sync wrapper for convenience
def capture_screenshot_sync(
    url: str,
    output_path: Optional[str] = None,
    **kwargs
) -> Optional[str]:
    """Synchronous wrapper for screenshot capture."""
    async def _capture():
        async with Screenshotter() as screenshotter:
            return await screenshotter.capture(url, output_path, **kwargs)
    
    try:
        return asyncio.run(_capture())
    except Exception as e:
        print(f"[!] Screenshot failed: {e}")
        return None
