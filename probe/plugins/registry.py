from plugins.fingerprinting import FingerprintingPlugin
from plugins.network_scanner import NetworkScannerPlugin
from plugins.security_headers import SecurityHeadersPlugin
from plugins.sensitive_files import SensitiveFilesPlugin
from plugins.tls_analysis import TLSAnalysisPlugin
from plugins.cve_correlation import CVECorrelationPlugin

PLUGINS = [
    FingerprintingPlugin(),
    NetworkScannerPlugin(),
    SecurityHeadersPlugin(),
    SensitiveFilesPlugin(),
    TLSAnalysisPlugin(),
    CVECorrelationPlugin(),
]
