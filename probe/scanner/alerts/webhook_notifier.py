"""
Webhook Alert System (Async)

Sends security findings to external systems via webhooks.
Supports Slack, Discord, Microsoft Teams, and generic webhooks.

Usage:
    from scanner.alerts.webhook_notifier import WebhookNotifier
    
    notifier = WebhookNotifier("https://hooks.slack.com/...", mode="batch")
    await notifier.notify(finding)
    await notifier.flush()  # Send batch
"""

import asyncio
import json
from enum import Enum
from typing import Optional, List, Dict, Callable
from datetime import datetime


class WebhookMode(Enum):
    IMMEDIATE = "immediate"
    BATCH = "batch"


class SeverityLevel:
    CRITICAL = 0
    HIGH = 1
    MEDIUM = 2
    LOW = 3
    INFO = 4


class WebhookNotifier:
    """
    Async webhook notifier with batch and immediate modes.
    Platform-specific formatting for Slack, Discord, Teams.
    """
    
    PLATFORM_PATTERNS = {
        "slack": "hooks.slack.com",
        "discord": "discord.com/api/webhooks",
        "teams": "office.com/webhook",
    }
    
    def __init__(
        self,
        webhook_url: str,
        mode: str = "batch",
        min_severity: str = "high",
        platform: Optional[str] = None,
        max_retries: int = 3,
    ):
        self.webhook_url = webhook_url
        self.mode = WebhookMode(mode)
        self.min_severity = self._severity_to_level(min_severity)
        self.max_retries = max_retries
        
        # Auto-detect platform from URL if not specified
        self.platform = platform or self._detect_platform(webhook_url)
        
        # Batch storage
        self._batch: List[Dict] = []
        self._lock = asyncio.Lock()
    
    def _severity_to_level(self, severity: str) -> int:
        """Convert severity string to numeric level."""
        levels = {
            "critical": SeverityLevel.CRITICAL,
            "high": SeverityLevel.HIGH,
            "medium": SeverityLevel.MEDIUM,
            "low": SeverityLevel.LOW,
            "info": SeverityLevel.INFO,
        }
        return levels.get(severity.lower(), SeverityLevel.INFO)
    
    def _detect_platform(self, url: str) -> str:
        """Detect webhook platform from URL."""
        url_lower = url.lower()
        for platform, pattern in self.PLATFORM_PATTERNS.items():
            if pattern in url_lower:
                return platform
        return "generic"
    
    def _should_notify(self, finding: Dict) -> bool:
        """Check if finding meets severity threshold."""
        severity = finding.get("severity", "info").lower()
        level = self._severity_to_level(severity)
        return level <= self.min_severity
    
    def _format_slack(self, findings: List[Dict]) -> Dict:
        """Format for Slack incoming webhook."""
        if len(findings) == 1:
            finding = findings[0]
            color = {
                "critical": "#FF0000",
                "high": "#FF8800",
                "medium": "#FFCC00",
                "low": "#00CC00",
            }.get(finding.get("severity", "info").lower(), "#999999")
            
            return {
                "attachments": [{
                    "color": color,
                    "title": f"🔴 {finding.get('title', 'Security Finding')}",
                    "title_link": finding.get("url", ""),
                    "fields": [
                        {"title": "Severity", "value": finding.get("severity", "unknown").upper(), "short": True},
                        {"title": "Target", "value": finding.get("target", "N/A"), "short": True},
                        {"title": "Plugin", "value": finding.get("plugin_name", "unknown"), "short": True},
                        {"title": "Confidence", "value": finding.get("confidence", "unknown"), "short": True},
                    ],
                    "footer": "Probe Security Scanner",
                    "ts": int(datetime.now().timestamp()),
                }]
            }
        
        # Batch summary
        by_severity = {}
        for f in findings:
            sev = f.get("severity", "info").upper()
            by_severity[sev] = by_severity.get(sev, 0) + 1
        
        summary = "\n".join([f"{sev}: {count}" for sev, count in by_severity.items()])
        
        return {
            "text": f"🔴 *Probe Alert: {len(findings)} findings detected*",
            "attachments": [{
                "color": "#FF0000",
                "text": f"*Summary by Severity:*\n{summary}",
                "footer": "Probe Security Scanner",
                "ts": int(datetime.now().timestamp()),
            }]
        }
    
    def _format_discord(self, findings: List[Dict]) -> Dict:
        """Format for Discord webhook."""
        if len(findings) == 1:
            finding = findings[0]
            color = {
                "critical": 0xFF0000,
                "high": 0xFF8800,
                "medium": 0xFFCC00,
                "low": 0x00CC00,
            }.get(finding.get("severity", "info").lower(), 0x999999)
            
            return {
                "embeds": [{
                    "title": f"🔴 {finding.get('title', 'Security Finding')}",
                    "url": finding.get("url", ""),
                    "color": color,
                    "fields": [
                        {"name": "Severity", "value": finding.get("severity", "unknown").upper(), "inline": True},
                        {"name": "Target", "value": finding.get("target", "N/A"), "inline": True},
                        {"name": "Plugin", "value": finding.get("plugin_name", "unknown"), "inline": True},
                    ],
                    "footer": {"text": "Probe Security Scanner"},
                    "timestamp": datetime.now().isoformat(),
                }]
            }
        
        # Batch summary
        by_severity = {}
        for f in findings:
            sev = f.get("severity", "info").upper()
            by_severity[sev] = by_severity.get(sev, 0) + 1
        
        summary = "\n".join([f"{sev}: {count}" for sev, count in by_severity.items()])
        
        return {
            "embeds": [{
                "title": f"🔴 Probe Alert: {len(findings)} findings",
                "description": f"**Summary by Severity:**\n```{summary}```",
                "color": 0xFF0000,
                "footer": {"text": "Probe Security Scanner"},
                "timestamp": datetime.now().isoformat(),
            }]
        }
    
    def _format_teams(self, findings: List[Dict]) -> Dict:
        """Format for Microsoft Teams webhook."""
        if len(findings) == 1:
            finding = findings[0]
            return {
                "@type": "MessageCard",
                "@context": "https://schema.org/extensions",
                "themeColor": "FF0000" if finding.get("severity") == "critical" else "FF8800",
                "summary": f"Security Finding: {finding.get('title')}",
                "sections": [{
                    "activityTitle": f"🔴 {finding.get('title', 'Security Finding')}",
                    "facts": [
                        {"name": "Severity", "value": finding.get("severity", "unknown").upper()},
                        {"name": "Target", "value": finding.get("target", "N/A")},
                        {"name": "Plugin", "value": finding.get("plugin_name", "unknown")},
                    ],
                    "markdown": True,
                }],
            }
        
        # Batch summary
        facts = [{"name": "Total Findings", "value": str(len(findings))}]
        by_severity = {}
        for f in findings:
            sev = f.get("severity", "info").upper()
            by_severity[sev] = by_severity.get(sev, 0) + 1
        
        for sev, count in by_severity.items():
            facts.append({"name": sev, "value": str(count)})
        
        return {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "themeColor": "FF0000",
            "summary": f"Probe Alert: {len(findings)} findings detected",
            "sections": [{
                "activityTitle": f"🔴 Probe Alert: {len(findings)} findings detected",
                "facts": facts,
                "markdown": True,
            }],
        }
    
    def _format_generic(self, findings: List[Dict]) -> Dict:
        """Generic JSON format."""
        return {
            "scanner": "Probe",
            "timestamp": datetime.now().isoformat(),
            "finding_count": len(findings),
            "findings": findings,
        }
    
    def _format_payload(self, findings: List[Dict]) -> Dict:
        """Format payload based on platform."""
        formatters = {
            "slack": self._format_slack,
            "discord": self._format_discord,
            "teams": self._format_teams,
            "generic": self._format_generic,
        }
        return formatters.get(self.platform, self._format_generic)(findings)
    
    async def _send_with_retry(self, payload: Dict) -> bool:
        """Send webhook with retry logic."""
        import aiohttp
        
        for attempt in range(self.max_retries):
            try:
                timeout = aiohttp.ClientTimeout(total=30)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.post(
                        self.webhook_url,
                        json=payload,
                        headers={"Content-Type": "application/json"},
                    ) as response:
                        if response.status in (200, 201, 204):
                            return True
                        text = await response.text()
                        print(f"[!] Webhook failed (status {response.status}): {text}")
                        
            except asyncio.TimeoutError:
                print(f"[!] Webhook timeout (attempt {attempt + 1})")
            except Exception as e:
                print(f"[!] Webhook error (attempt {attempt + 1}): {e}")
            
            if attempt < self.max_retries - 1:
                await asyncio.sleep(2 ** attempt)  # Exponential backoff
        
        return False
    
    async def notify(self, finding: Dict) -> bool:
        """
        Send or queue a finding notification.
        
        Args:
            finding: Finding dictionary
        
        Returns:
            True if queued/sent successfully
        """
        if not self._should_notify(finding):
            return True
        
        if self.mode == WebhookMode.IMMEDIATE:
            payload = self._format_payload([finding])
            return await self._send_with_retry(payload)
        
        # Batch mode
        async with self._lock:
            self._batch.append(finding)
        
        return True
    
    async def flush(self) -> bool:
        """Send all batched findings."""
        async with self._lock:
            if not self._batch:
                return True
            
            findings = self._batch.copy()
            self._batch.clear()
        
        payload = self._format_payload(findings)
        return await self._send_with_retry(payload)
    
    async def notify_scan_complete(
        self,
        target: str,
        duration: float,
        findings_summary: Dict,
    ) -> bool:
        """Send scan completion notification."""
        if self.mode != WebhookMode.IMMEDIATE:
            await self.flush()
        
        summary = {
            "scanner": "Probe",
            "event": "scan_complete",
            "target": target,
            "duration": f"{duration:.1f}s",
            "timestamp": datetime.now().isoformat(),
            **findings_summary,
        }
        
        # Format based on platform
        if self.platform == "slack":
            payload = {
                "attachments": [{
                    "color": "#36a64f",
                    "title": f"✅ Scan Complete: {target}",
                    "fields": [
                        {"title": "Duration", "value": summary["duration"], "short": True},
                        {"title": "Total Findings", "value": str(findings_summary.get("total", 0)), "short": True},
                    ],
                    "footer": "Probe Security Scanner",
                }]
            }
        elif self.platform == "discord":
            payload = {
                "embeds": [{
                    "title": f"✅ Scan Complete: {target}",
                    "color": 0x36a64f,
                    "fields": [
                        {"name": "Duration", "value": summary["duration"], "inline": True},
                        {"name": "Total Findings", "value": str(findings_summary.get("total", 0)), "inline": True},
                    ],
                }]
            }
        else:
            payload = summary
        
        return await self._send_with_retry(payload)
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.flush()


class MultiWebhookNotifier:
    """Send to multiple webhooks simultaneously."""
    
    def __init__(self, notifiers: List[WebhookNotifier]):
        self.notifiers = notifiers
    
    async def notify(self, finding: Dict):
        """Send to all configured webhooks."""
        tasks = [n.notify(finding) for n in self.notifiers]
        await asyncio.gather(*tasks, return_exceptions=True)
    
    async def flush(self):
        """Flush all batched notifiers."""
        tasks = [n.flush() for n in self.notifiers]
        await asyncio.gather(*tasks, return_exceptions=True)
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.flush()


# Convenience function for simple use cases
async def send_alert(
    webhook_url: str,
    finding: Dict,
    platform: Optional[str] = None,
) -> bool:
    """
    Send a single alert immediately.
    
    Args:
        webhook_url: Webhook endpoint
        finding: Finding to send
        platform: "slack", "discord", "teams", or "generic"
    
    Returns:
        True if sent successfully
    """
    async with WebhookNotifier(
        webhook_url,
        mode="immediate",
        platform=platform,
    ) as notifier:
        return await notifier.notify(finding)
