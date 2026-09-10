from datetime import datetime, timezone

from plugins.tls_analysis import TLSAnalysisPlugin


def cert(days_left):
    expiry = datetime.now(timezone.utc).replace(microsecond=0)
    from datetime import timedelta
    expiry += timedelta(days=days_left)
    return {
        "notAfter": expiry.strftime("%b %d %H:%M:%S %Y GMT"),
        "subject": ((("commonName", "example.test"),),),
        "issuer": ((("commonName", "Test CA"),),),
    }


def mock_tls(monkeypatch, protocol="TLSv1.3", cipher=("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256), days_left=67):
    class Socket:
        def __enter__(self): return self
        def __exit__(self, *_args): pass
        def getpeercert(self): return cert(days_left)
        def version(self): return protocol
        def cipher(self): return cipher

    class Context:
        def wrap_socket(self, *_args, **_kwargs): return Socket()

    monkeypatch.setattr("plugins.tls_analysis.ssl.create_default_context", lambda: Context())
    monkeypatch.setattr("plugins.tls_analysis.socket.create_connection", lambda *_args, **_kwargs: Socket())


def test_strong_tls_is_an_informational_observation(monkeypatch):
    mock_tls(monkeypatch)

    findings = TLSAnalysisPlugin()._analyze_port("example.test", 443)

    assert len(findings) == 1
    assert findings[0].severity == "info"
    assert findings[0].metadata["classification"] == "warning"
    assert "not a vulnerability" in findings[0].description.lower()


def test_weak_tls_remains_a_vulnerability(monkeypatch):
    mock_tls(monkeypatch, protocol="TLSv1.1")

    findings = TLSAnalysisPlugin()._analyze_port("example.test", 443)

    assert findings[0].severity == "medium"
    assert findings[0].metadata.get("classification") != "warning"
    assert "Weak TLS protocol" in findings[0].description
