"""CMS-specific deep enumeration helpers (WordPress, and room to grow)."""

from scanner.cms.wordpress import (
    WordPressReport,
    enumerate_wordpress,
    is_wordpress,
)

__all__ = ["WordPressReport", "enumerate_wordpress", "is_wordpress"]
