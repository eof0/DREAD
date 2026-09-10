"""
API Endpoint Discovery Plugin

Discovers REST API endpoints and GraphQL endpoints during crawling.
Detects API documentation, OpenAPI specs, and common API patterns.
"""

from plugins.base_plugin import BasePlugin, Finding
from typing import Dict, List, Optional
import re
import json


class APIDiscoveryPlugin(BasePlugin):
    """
    Discovers API endpoints by:
    - Detecting common API paths (/api/, /v1/, /graphql, etc.)
    - Finding OpenAPI/Swagger documentation
    - Identifying GraphQL endpoints
    - Extracting API patterns from JavaScript
    """

    # Common API path patterns
    API_PATH_PATTERNS = [
        r"^/api/[\w/]+",
        r"^/v\d+/[\w/]+",
        r"^/rest/[\w/]+",
        r"^/graphql/?",
        r"^/gql/?",
        r"^/jsonrpc/?",
        r"^/soap/?",
        r"^/wp-json/[\w/]+",  # WordPress REST API
    ]

    # OpenAPI/Swagger documentation paths
    DOC_PATHS = [
        "/openapi.json",
        "/openapi.yaml",
        "/swagger.json",
        "/swagger.yaml",
        "/api-docs",
        "/api/docs",
        "/swagger-ui.html",
        "/swagger-ui/",
        "/api/swagger.json",
        "/api/openapi.json",
    ]

    # API response content types
    API_CONTENT_TYPES = [
        "application/json",
        "application/xml",
        "application/graphql",
        "application/x-www-form-urlencoded",
    ]

    # GraphQL introspection query
    GRAPHQL_INTROSPECTION = """
    {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
      }
    }
    """

    def get_name(self) -> str:
        return "api_discovery"

    def get_description(self) -> str:
        return "Discovers REST APIs, GraphQL endpoints, and API documentation"

    def _is_api_response(self, response) -> bool:
        """Check if response appears to be from an API endpoint."""
        content_type = response.headers.get("Content-Type", "").lower()
        
        for api_type in self.API_CONTENT_TYPES:
            if api_type in content_type:
                return True
        
        # Check if body looks like JSON
        try:
            if response.text and response.text.strip().startswith(("{", "[")):
                json.loads(response.text)
                return True
        except:
            pass
        
        return False

    def _detect_api_type(self, response, url: str) -> Optional[str]:
        """Determine the type of API endpoint."""
        url_lower = url.lower()
        
        if "graphql" in url_lower:
            return "GraphQL"
        
        content_type = response.headers.get("Content-Type", "").lower()
        
        if "soap" in content_type or "xml" in content_type:
            return "SOAP"
        
        if "json" in content_type:
            # Check for REST patterns in URL
            if re.search(r"/v\d+/", url):
                return "REST (Versioned)"
            return "REST"
        
        return "API"

    def _check_graphql_endpoint(self, url: str, request_handler) -> Optional[Dict]:
        """Test if URL is a GraphQL endpoint."""
        graphql_urls = [
            url if "/graphql" in url.lower() else f"{url.rstrip('/')}/graphql",
            url if "/gql" in url.lower() else f"{url.rstrip('/')}/gql",
        ]
        
        for graphql_url in graphql_urls:
            try:
                response = request_handler.post(
                    graphql_url,
                    json={"query": self.GRAPHQL_INTROSPECTION},
                    headers={"Content-Type": "application/json"},
                )
                
                if response and response.status_code == 200:
                    data = response.json()
                    if "data" in data and "__schema" in data.get("data", {}):
                        schema = data["data"]["__schema"]
                        return {
                            "url": graphql_url,
                            "type": "GraphQL",
                            "introspection_enabled": True,
                            "query_type": schema.get("queryType", {}).get("name"),
                            "mutation_type": schema.get("mutationType", {}).get("name"),
                            "subscription_type": schema.get("subscriptionType", {}).get("name"),
                        }
            except Exception:
                continue
        
        return None

    def _find_api_documentation(self, base_url: str, request_handler) -> List[Dict]:
        """Search for API documentation endpoints."""
        found_docs = []
        
        for doc_path in self.DOC_PATHS:
            doc_url = f"{base_url.rstrip('/')}{doc_path}"
            try:
                response = request_handler.get(doc_url)
                if response and response.status_code == 200:
                    doc_type = "Unknown"
                    if "swagger" in doc_path.lower():
                        doc_type = "Swagger UI"
                    elif "openapi" in doc_path.lower():
                        doc_type = "OpenAPI"
                    
                    found_docs.append({
                        "url": doc_url,
                        "type": doc_type,
                        "path": doc_path,
                    })
            except Exception:
                continue
        
        return found_docs

    def _extract_api_from_js(self, response_text: str) -> List[str]:
        """Extract potential API endpoints from JavaScript code."""
        endpoints = set()
        
        # Common patterns in JS
        patterns = [
            r'["\'](\/api\/[^"\'\s]+)["\']',
            r'["\'](\/v\d+\/[^"\'\s]+)["\']',
            r'["\'](\/graphql)["\']',
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.[a-z]+\(["\']([^"\']+)["\']',
            r'url:\s*["\']([^"\']+)["\']',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            for match in matches:
                if match.startswith(("/api/", "/v", "/graphql")):
                    endpoints.add(match)
        
        return list(endpoints)

    def scan(self, url_info: Dict, request_handler) -> List[Finding]:
        findings = []
        
        url = url_info["url"]
        response = request_handler.get(url)
        if response is None:
            return findings
        
        # Only check root URLs for documentation
        if url_info.get("depth", 0) == 0:
            # Search for API documentation
            doc_findings = self._find_api_documentation(url, request_handler)
            for doc in doc_findings:
                findings.append(
                    Finding(
                        plugin_name=self.get_name(),
                        severity="info",
                        title=f"API Documentation Found: {doc['type']}",
                        description=f"{doc['type']} documentation is publicly accessible at {doc['path']}",
                        url=doc["url"],
                        evidence={
                            "documentation_type": doc["type"],
                            "path": doc["path"],
                        },
                        remediation="Consider restricting API documentation access to authenticated users only.",
                    )
                )
            
            # Check for GraphQL
            graphql_info = self._check_graphql_endpoint(url, request_handler)
            if graphql_info:
                severity = "medium" if graphql_info["introspection_enabled"] else "low"
                findings.append(
                    Finding(
                        plugin_name=self.get_name(),
                        severity=severity,
                        title=f"GraphQL Endpoint Detected{'' if graphql_info['introspection_enabled'] else ''}",
                        description=(
                            f"GraphQL endpoint found at {graphql_info['url']}. "
                            f"{'Introspection is ENABLED - schema can be queried.' if graphql_info['introspection_enabled'] else 'Introspection status unknown.'}"
                        ),
                        url=graphql_info["url"],
                        evidence=graphql_info,
                        remediation="Disable introspection in production. Implement query depth limiting and complexity analysis.",
                    )
                )
        
        # Check if current URL is an API endpoint
        is_api = False
        for pattern in self.API_PATH_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                is_api = True
                break
        
        if is_api or self._is_api_response(response):
            api_type = self._detect_api_type(response, url)
            
            # Determine severity based on exposure
            severity = "info"
            if "admin" in url.lower() or "internal" in url.lower():
                severity = "medium"
            
            findings.append(
                Finding(
                    plugin_name=self.get_name(),
                    severity=severity,
                    title=f"{api_type} Endpoint Discovered",
                    description=f"A {api_type} API endpoint was discovered at this location.",
                    url=url,
                    evidence={
                        "api_type": api_type,
                        "content_type": response.headers.get("Content-Type"),
                        "methods_allowed": response.headers.get("Allow", "Unknown"),
                    },
                    remediation="Ensure API endpoints implement proper authentication, rate limiting, and input validation.",
                )
            )
        
        # Extract API endpoints from JavaScript (only for HTML responses)
        content_type = response.headers.get("Content-Type", "").lower()
        if "text/html" in content_type and response.text:
            js_endpoints = self._extract_api_from_js(response.text)
            for endpoint in js_endpoints[:5]:  # Limit to first 5 unique endpoints
                findings.append(
                    Finding(
                        plugin_name=self.get_name(),
                        severity="info",
                        title=f"API Endpoint Found in JavaScript: {endpoint}",
                        description=f"An API endpoint was referenced in client-side JavaScript code.",
                        url=f"{url} (referenced in JS)",
                        evidence={
                            "discovered_endpoint": endpoint,
                            "source": "JavaScript analysis",
                        },
                        remediation="Ensure API endpoints called from JavaScript are properly secured and don't expose sensitive data.",
                    )
                )
        
        return findings
