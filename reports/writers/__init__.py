# Reports writers

from __future__ import annotations

from typing import Any

# Customer-facing names for the cloud storage providers attack-surface discovery checks.
_CLOUD_STORAGE_LABELS = {
    "s3_buckets": "Amazon S3",
    "cloudfront": "Amazon CloudFront",
    "azure_blob": "Azure Blob Storage",
    "gcs": "Google Cloud Storage",
}


def cloud_storage_checked(summary: dict[str, Any]) -> str:
    keys = (summary.get("cloud_bucket_counts") or {}).keys()
    return ", ".join(_CLOUD_STORAGE_LABELS.get(k, k) for k in keys) or "none"
