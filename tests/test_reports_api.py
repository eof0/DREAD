import pytest
from fastapi import HTTPException

from reports.api.app import _validate_target


def test_validate_target_accepts_domains_and_adds_scheme():
    assert _validate_target("example.com") == "example.com"
    assert _validate_target("https://example.com/app") == "https://example.com/app"


@pytest.mark.parametrize("target", ["not a url", "ftp://example.com", "javascript:alert(1)"])
def test_validate_target_rejects_non_web_targets(target):
    with pytest.raises(HTTPException) as error:
        _validate_target(target)
    assert error.value.status_code == 422
