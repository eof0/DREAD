"""
Vulnerability Template Engine

Loads and executes YAML-based vulnerability templates similar to Nuclei.
Enables rapid vulnerability detection without writing Python code.

Template format:
    id: template-id
    name: Template Name
    severity: high
    description: What this finds
    
    requests:
      - method: GET
        path:
          - "{{BaseURL}}/.git/config"
        headers:
          User-Agent: "Probe/1.0"
    
    matchers:
      - type: word
        words:
          - "repositoryformatversion"
        part: body
        
    extractors:
      - type: regex
        regex:
          - "repositoryformatversion = (\\d+)"
        part: body
"""

import yaml
import re
import os
from typing import Dict, List, Optional, Any
from pathlib import Path
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor
import time


@dataclass
class Template:
    """Represents a vulnerability template."""
    id: str
    name: str
    severity: str
    description: str
    requests: List[Dict]
    matchers: List[Dict]
    extractors: Optional[List[Dict]] = None
    metadata: Dict = field(default_factory=dict)
    
    def __post_init__(self):
        """Validate template after creation."""
        if not self.id:
            raise ValueError("Template must have an 'id'")
        if not self.requests:
            raise ValueError("Template must have at least one request")
        if not self.matchers:
            raise ValueError("Template must have at least one matcher")


class TemplateLoader:
    """Load templates from disk."""
    
    def __init__(self, templates_dir: str = "templates"):
        self.templates_dir = Path(templates_dir)
        self.templates: Dict[str, Template] = {}
    
    def load_template(self, path: Path) -> Optional[Template]:
        """Load a single template from YAML file."""
        try:
            with open(path, 'r') as f:
                data = yaml.safe_load(f)
            
            if not data:
                return None
            
            return Template(
                id=data.get("id", path.stem),
                name=data.get("name", data.get("id", "Unknown")),
                severity=data.get("severity", "medium"),
                description=data.get("description", ""),
                requests=data.get("requests", []),
                matchers=data.get("matchers", []),
                extractors=data.get("extractors"),
                metadata=data.get("metadata", {}),
            )
        except Exception as e:
            print(f"[!] Failed to load template {path}: {e}")
            return None
    
    def load_all(self) -> List[Template]:
        """Load all templates from templates directory."""
        if not self.templates_dir.exists():
            print(f"[!] Templates directory not found: {self.templates_dir}")
            return []
        
        templates = []
        
        # Recursively find all .yaml files
        for yaml_file in self.templates_dir.rglob("*.yaml"):
            template = self.load_template(yaml_file)
            if template:
                self.templates[template.id] = template
                templates.append(template)
        
        print(f"[*] Loaded {len(templates)} templates from {self.templates_dir}")
        return templates
    
    def get_by_id(self, template_id: str) -> Optional[Template]:
        """Get template by ID."""
        return self.templates.get(template_id)
    
    def get_by_severity(self, severity: str) -> List[Template]:
        """Get all templates of a specific severity."""
        return [t for t in self.templates.values() if t.severity == severity]


class TemplateExecutor:
    """Execute templates against targets."""
    
    def __init__(self, request_handler):
        self.request_handler = request_handler
        self.max_workers = 10
    
    def render_request(self, request: Dict, target: str) -> Dict:
        """Render request with target variables."""
        rendered = {}
        
        for key, value in request.items():
            if isinstance(value, str):
                rendered[key] = self._render_template(value, target)
            elif isinstance(value, list):
                rendered[key] = [self._render_template(v, target) if isinstance(v, str) else v for v in value]
            elif isinstance(value, dict):
                rendered[key] = {k: self._render_template(v, target) if isinstance(v, str) else v 
                                for k, v in value.items()}
            else:
                rendered[key] = value
        
        return rendered
    
    def _render_template(self, template: str, target: str) -> str:
        """Replace template variables."""
        replacements = {
            "{{BaseURL}}": target.rstrip('/'),
            "{{baseURL}}": target.rstrip('/'),
            "{{Hostname}}": self._get_hostname(target),
            "{{hostname}}": self._get_hostname(target),
        }
        
        result = template
        for key, value in replacements.items():
            result = result.replace(key, value)
        
        return result
    
    def _get_hostname(self, url: str) -> str:
        """Extract hostname from URL."""
        from urllib.parse import urlparse
        return urlparse(url).netloc
    
    def execute_request(self, request: Dict) -> Optional[Any]:
        """Execute a single request."""
        method = request.get("method", "GET").upper()
        path = request.get("path", ["/"])
        
        # Handle multiple paths
        if isinstance(path, list):
            path = path[0] if path else "/"
        
        headers = request.get("headers", {})
        body = request.get("body", None)
        
        try:
            if method == "GET":
                return self.request_handler.get(path, headers=headers)
            elif method == "POST":
                return self.request_handler.post(path, data=body, headers=headers)
            elif method == "HEAD":
                return self.request_handler.head(path, headers=headers)
            elif method == "OPTIONS":
                return self.request_handler.options(path, headers=headers)
            else:
                return None
        except Exception as e:
            print(f"[!] Request failed: {e}")
            return None
    
    def check_matchers(self, response, matchers: List[Dict]) -> bool:
        """Check if response matches all matchers."""
        for matcher in matchers:
            if not self._check_single_matcher(response, matcher):
                return False
        return True
    
    def _check_single_matcher(self, response, matcher: Dict) -> bool:
        """Check a single matcher against response."""
        matcher_type = matcher.get("type", "word")
        part = matcher.get("part", "body")
        negative = matcher.get("negative", False)
        condition = matcher.get("condition", "or")
        
        # Get response part
        if part == "body":
            content = response.text if hasattr(response, 'text') else str(response)
        elif part == "header":
            content = str(dict(response.headers)) if hasattr(response, 'headers') else ""
        elif part == "status":
            content = str(response.status_code) if hasattr(response, 'status_code') else ""
        else:
            content = response.text if hasattr(response, 'text') else str(response)
        
        # Check based on matcher type
        matched = False
        
        if matcher_type == "word":
            words = matcher.get("words", [])
            if condition == "and":
                matched = all(word in content for word in words)
            else:  # or
                matched = any(word in content for word in words)
        
        elif matcher_type == "regex":
            patterns = matcher.get("regex", [])
            flags = 0
            if matcher.get("case-insensitive", False):
                flags |= re.IGNORECASE
            
            if condition == "and":
                matched = all(re.search(p, content, flags) for p in patterns)
            else:
                matched = any(re.search(p, content, flags) for p in patterns)
        
        elif matcher_type == "status":
            status = matcher.get("status", [])
            actual_status = response.status_code if hasattr(response, 'status_code') else 0
            matched = actual_status in status
        
        elif matcher_type == "dsl":
            # Simplified DSL - just check if expression evaluates
            expression = matcher.get("expression", "")
            matched = self._evaluate_dsl(expression, response)
        
        return not matched if negative else matched
    
    def _evaluate_dsl(self, expression: str, response) -> bool:
        """Evaluate a simple DSL expression."""
        # Basic DSL: contains(body, "string"), status_code == 200, etc.
        try:
            if "contains(" in expression:
                match = re.search(r'contains\((\w+),\s*["\']([^"\']+)["\']\)', expression)
                if match:
                    part, search = match.groups()
                    if part == "body":
                        content = response.text if hasattr(response, 'text') else ""
                    else:
                        content = str(response.headers.get(part, "")) if hasattr(response, 'headers') else ""
                    return search in content
            
            if "status_code" in expression:
                code = response.status_code if hasattr(response, 'status_code') else 0
                # Simple evaluation
                if "==" in expression:
                    expected = int(expression.split("==")[-1].strip())
                    return code == expected
                elif "!=" in expression:
                    expected = int(expression.split("!=")[-1].strip())
                    return code != expected
            
            return False
        except:
            return False
    
    def run_extraction(self, response, extractors: List[Dict]) -> Dict[str, Any]:
        """Extract data from response using extractors."""
        extracted = {}
        
        for extractor in extractors:
            name = extractor.get("name", "extracted")
            ext_type = extractor.get("type", "regex")
            part = extractor.get("part", "body")
            
            # Get content
            if part == "body":
                content = response.text if hasattr(response, 'text') else str(response)
            elif part == "header":
                content = str(dict(response.headers)) if hasattr(response, 'headers') else ""
            else:
                content = response.text if hasattr(response, 'text') else str(response)
            
            if ext_type == "regex":
                patterns = extractor.get("regex", [])
                matches = []
                for pattern in patterns:
                    found = re.findall(pattern, content)
                    matches.extend(found)
                extracted[name] = matches
            
            elif ext_type == "xpath":
                # Would require lxml or similar
                pass
            
            elif ext_type == "json":
                try:
                    import json
                    data = json.loads(content)
                    json_path = extractor.get("json", "")
                    # Simple dot-notation path
                    keys = json_path.split(".")
                    value = data
                    for key in keys:
                        if isinstance(value, dict):
                            value = value.get(key)
                        elif isinstance(value, list) and key.isdigit():
                            value = value[int(key)] if int(key) < len(value) else None
                        else:
                            value = None
                            break
                    extracted[name] = value
                except:
                    extracted[name] = None
        
        return extracted
    
    def execute(self, template: Template, target: str) -> Optional[Dict]:
        """
        Execute a template against a target.
        
        Returns finding dict if matched, None otherwise.
        """
        for request in template.requests:
            # Render request
            rendered = self.render_request(request, target)
            
            # Execute request
            response = self.execute_request(rendered)
            if not response:
                continue
            
            # Check matchers
            if not self.check_matchers(response, template.matchers):
                continue
            
            # Build finding
            finding = {
                "template_id": template.id,
                "template_name": template.name,
                "severity": template.severity,
                "description": template.description,
                "url": rendered.get("path", target),
                "matched_request": rendered,
            }
            
            # Run extractors
            if template.extractors:
                extracted = self.run_extraction(response, template.extractors)
                finding["extracted"] = extracted
            
            return finding
        
        return None
    
    def execute_all(
        self,
        templates: List[Template],
        target: str,
        max_workers: int = 10,
    ) -> List[Dict]:
        """Execute all templates against a target with concurrency."""
        findings = []
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(self.execute, template, target): template
                for template in templates
            }
            
            for future in futures:
                try:
                    result = future.result(timeout=30)
                    if result:
                        findings.append(result)
                except Exception as e:
                    template = futures[future]
                    print(f"[!] Template {template.id} failed: {e}")
        
        return findings


class TemplatePlugin:
    """
    Plugin wrapper for template engine integration.
    """
    
    def __init__(self, templates_dir: str = "templates"):
        self.loader = TemplateLoader(templates_dir)
        self.templates = []
    
    def load_templates(self):
        """Load all templates."""
        self.templates = self.loader.load_all()
    
    def scan(self, url_info: Dict, request_handler) -> List[Dict]:
        """Run all templates against URL."""
        if not self.templates:
            self.load_templates()
        
        executor = TemplateExecutor(request_handler)
        target = url_info["url"]
        
        return executor.execute_all(self.templates, target)
