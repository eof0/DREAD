from typing import Optional

def normalize_version(v: Optional[str]) -> Optional[str]:
    if not v:
        return None
    return v.strip().lower().lstrip("v")

def versions_match(db_version: str, detected_version: Optional[str]) -> bool:
    """
    Very simple version matching logic:
    - If db_version == "any" → always match
    - If detected_version is None → only match if db_version == "any"
    - Else, match if exact or major.minor match.
    """
    db_version = normalize_version(db_version)
    detected_version = normalize_version(detected_version)

    if db_version is None:
        return False

    if db_version == "any":
        return True

    if detected_version is None:
        return False

    if detected_version == db_version:
        return True

    # Major.minor prefix match
    db_parts = db_version.split(".")
    det_parts = detected_version.split(".")

    if len(db_parts) >= 2 and len(det_parts) >= 2:
        return db_parts[0] == det_parts[0] and db_parts[1] == det_parts[1]

    return False
