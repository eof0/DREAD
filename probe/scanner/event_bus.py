"""
Event Bus for Probe

Provides decoupled event-driven architecture.
Features can subscribe to events without modifying core engine.

Events:
- finding_detected
- scan_started  
- scan_completed
- critical_finding
- high_risk_detected

Usage:
    from scanner.event_bus import event_bus, EventType
    
    # Subscribe to events
    @event_bus.on(EventType.FINDING_DETECTED)
    def handle_finding(finding):
        print(f"Found: {finding['title']}")
    
    # Emit events
    event_bus.emit(EventType.FINDING_DETECTED, finding_data)
"""

from enum import Enum, auto
from typing import Callable, Dict, List, Any
from dataclasses import dataclass
from datetime import datetime
import asyncio
from concurrent.futures import ThreadPoolExecutor


class EventType(Enum):
    """Core event types emitted by Probe."""
    
    # Scan lifecycle
    SCAN_STARTED = "scan_started"
    SCAN_COMPLETED = "scan_completed"
    SCAN_FAILED = "scan_failed"
    
    # Findings
    FINDING_DETECTED = "finding_detected"
    CRITICAL_FINDING = "critical_finding"
    HIGH_RISK_DETECTED = "high_risk_detected"
    
    # Evidence
    SCREENSHOT_CAPTURED = "screenshot_captured"
    EVIDENCE_COLLECTED = "evidence_collected"
    
    # Reporting
    REPORT_GENERATED = "report_generated"


@dataclass
class Event:
    """Event data structure."""
    type: EventType
    data: Any
    timestamp: datetime
    metadata: Dict = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class EventBus:
    """
    Central event bus for Probe.
    
    Supports:
    - Synchronous subscribers
    - Asynchronous subscribers
    - Priority ordering
    - One-time subscriptions
    """
    
    def __init__(self):
        self._subscribers: Dict[EventType, List[Dict]] = {
            event_type: [] for event_type in EventType
        }
        self._executor = ThreadPoolExecutor(max_workers=5)
        self._middleware: List[Callable] = []
    
    def on(
        self,
        event_type: EventType,
        priority: int = 0,
        once: bool = False
    ) -> Callable:
        """
        Decorator to subscribe to events.
        
        Args:
            event_type: Type of event to subscribe to
            priority: Higher priority = called first (default 0)
            once: If True, unsubscribe after first event
        
        Example:
            @event_bus.on(EventType.FINDING_DETECTED, priority=10)
            def my_handler(finding):
                pass
        """
        def decorator(func: Callable) -> Callable:
            self.subscribe(event_type, func, priority, once)
            return func
        return decorator
    
    def subscribe(
        self,
        event_type: EventType,
        handler: Callable,
        priority: int = 0,
        once: bool = False
    ):
        """Subscribe a handler to an event type."""
        subscription = {
            "handler": handler,
            "priority": priority,
            "once": once,
        }
        
        self._subscribers[event_type].append(subscription)
        
        # Sort by priority (highest first)
        self._subscribers[event_type].sort(
            key=lambda s: s["priority"],
            reverse=True
        )
    
    def unsubscribe(self, event_type: EventType, handler: Callable):
        """Unsubscribe a handler from an event type."""
        self._subscribers[event_type] = [
            s for s in self._subscribers[event_type]
            if s["handler"] != handler
        ]
    
    def emit(self, event_type: EventType, data: Any = None, metadata: Dict = None):
        """
        Emit an event synchronously.
        
        Args:
            event_type: Type of event
            data: Event payload
            metadata: Additional event metadata
        """
        event = Event(
            type=event_type,
            data=data,
            timestamp=datetime.now(),
            metadata=metadata or {}
        )
        
        # Run middleware
        for middleware in self._middleware:
            event = middleware(event)
            if event is None:  # Middleware can cancel event
                return
        
        # Notify subscribers
        subscribers = self._subscribers[event_type].copy()
        to_remove = []
        
        for subscription in subscribers:
            try:
                handler = subscription["handler"]
                
                # Check if async
                if asyncio.iscoroutinefunction(handler):
                    # Schedule async handler
                    asyncio.create_task(handler(event.data))
                else:
                    # Call sync handler
                    handler(event.data)
                
                # Mark for removal if once=True
                if subscription["once"]:
                    to_remove.append((event_type, handler))
                    
            except Exception as e:
                print(f"[!] Event handler error: {e}")
        
        # Clean up one-time subscriptions
        for event_type, handler in to_remove:
            self.unsubscribe(event_type, handler)
    
    def emit_async(self, event_type: EventType, data: Any = None, metadata: Dict = None):
        """Emit event asynchronously in background thread."""
        self._executor.submit(self.emit, event_type, data, metadata)
    
    def add_middleware(self, middleware: Callable):
        """Add middleware to process events."""
        self._middleware.append(middleware)
    
    def wait_for(
        self,
        event_type: EventType,
        timeout: float = 30.0,
        predicate: Callable = None
    ) -> Any:
        """
        Wait for an event and return its data.
        
        Args:
            event_type: Event to wait for
            timeout: Maximum wait time
            predicate: Optional function to filter events
        
        Returns:
            Event data or None if timeout
        """
        import threading
        
        result = None
        event_received = threading.Event()
        
        def handler(data):
            nonlocal result
            if predicate is None or predicate(data):
                result = data
                event_received.set()
        
        self.subscribe(event_type, handler, once=True)
        
        if event_received.wait(timeout=timeout):
            return result
        else:
            self.unsubscribe(event_type, handler)
            return None
    
    def get_subscriber_count(self, event_type: EventType = None) -> int:
        """Get number of subscribers."""
        if event_type:
            return len(self._subscribers.get(event_type, []))
        return sum(len(subs) for subs in self._subscribers.values())


# Global event bus instance
event_bus = EventBus()


# Convenience functions for common event patterns

def on_finding_detected(severity_filter: str = None, priority: int = 0):
    """
    Decorator for finding detection with optional severity filter.
    
    Example:
        @on_finding_detected(severity_filter="critical")
        def alert_on_critical(finding):
            send_alert(finding)
    """
    def decorator(func: Callable) -> Callable:
        @event_bus.on(EventType.FINDING_DETECTED, priority=priority)
        def wrapper(finding):
            if severity_filter is None or finding.get("severity") == severity_filter:
                return func(finding)
        return func
    return decorator


def on_scan_complete(func: Callable = None, *, priority: int = 0):
    """Decorator for scan completion."""
    if func is None:
        def decorator(f):
            return event_bus.on(EventType.SCAN_COMPLETED, priority=priority)(f)
        return decorator
    return event_bus.on(EventType.SCAN_COMPLETED, priority=priority)(func)


# Event-driven helper classes

class EventDrivenWebhook:
    """Webhook notifier that subscribes to events."""
    
    def __init__(self, webhook_url: str, min_severity: str = "high"):
        self.webhook_url = webhook_url
        self.min_severity = min_severity
        self._subscribe()
    
    def _subscribe(self):
        """Subscribe to finding events."""
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        min_level = severity_order.get(self.min_severity, 1)
        
        @event_bus.on(EventType.FINDING_DETECTED, priority=5)
        def handle_finding(finding):
            finding_level = severity_order.get(finding.get("severity"), 4)
            if finding_level <= min_level:
                self._send_webhook(finding)
    
    def _send_webhook(self, finding: Dict):
        """Send webhook notification."""
        try:
            import requests
            payload = {
                "scanner": "Probe",
                "event": "finding_detected",
                "timestamp": datetime.now().isoformat(),
                "finding": finding,
            }
            requests.post(self.webhook_url, json=payload, timeout=10)
        except Exception as e:
            print(f"[!] Webhook failed: {e}")


class EventDrivenScreenshotter:
    """Screenshot capture that subscribes to events."""
    
    def __init__(self, output_dir: str = "evidence", min_severity: str = "high"):
        self.output_dir = output_dir
        self.min_severity = min_severity
        self._subscribe()
    
    def _subscribe(self):
        """Subscribe to finding events."""
        severity_order = {"critical": 0, "high": 1, "medium": 2}
        min_level = severity_order.get(self.min_severity, 1)
        
        @event_bus.on(EventType.FINDING_DETECTED, priority=3)
        def handle_finding(finding):
            finding_level = severity_order.get(finding.get("severity"), 4)
            if finding_level <= min_level:
                self._capture_screenshot(finding)
    
    def _capture_screenshot(self, finding: Dict):
        """Capture screenshot for finding."""
        try:
            from scanner.evidence.screenshotter import capture_screenshot_sync as capture_screenshot
            
            url = finding.get("url", "")
            if not url.startswith(("http://", "https://")):
                return
            
            import os
            os.makedirs(self.output_dir, exist_ok=True)
            
            filename = f"{finding.get('plugin_name', 'finding')}_{hash(finding.get('title', '')) % 10000}.png"
            output_path = os.path.join(self.output_dir, filename)
            
            result = capture_screenshot(url, output_path)
            if result:
                event_bus.emit(
                    EventType.SCREENSHOT_CAPTURED,
                    {"finding": finding, "screenshot_path": result}
                )
        except Exception as e:
            print(f"[!] Screenshot capture failed: {e}")


# Example usage
if __name__ == "__main__":
    # Example: Subscribe to events
    @event_bus.on(EventType.FINDING_DETECTED)
    def log_finding(finding):
        print(f"Finding: {finding.get('title')}")
    
    @event_bus.on(EventType.CRITICAL_FINDING, priority=100)
    def urgent_alert(finding):
        print(f"🚨 CRITICAL: {finding.get('title')}")
    
    # Example: Emit events
    event_bus.emit(EventType.SCAN_STARTED, {"target": "example.com"})
    
    event_bus.emit(EventType.FINDING_DETECTED, {
        "title": "Exposed .env file",
        "severity": "critical",
        "url": "https://example.com/.env"
    })
    
    event_bus.emit(EventType.SCAN_COMPLETED, {
        "target": "example.com",
        "findings_count": 5
    })
