import json
import yaml
from typing import Dict, List, Tuple, Any
from urllib.parse import urljoin
from .models import HTTPMethod

class OpenAPIAnalyzer:
    """OpenAPI/Swagger specification analyzer"""
    @staticmethod
    def parse_openapi(spec_url_or_path: str) -> Dict[str, Any]:
        """Parse OpenAPI specification"""
        try:
            import requests
            if spec_url_or_path.startswith('http'):
                response = requests.get(spec_url_or_path, timeout=10)
                content = response.text
            else:
                with open(spec_url_or_path, 'r') as f:
                    content = f.read()
            # Try JSON first, then YAML
            try:
                return json.loads(content)
            except json.JSONDecodeError:
                try:
                    return yaml.safe_load(content)
                except:
                    return {}
        except Exception:
            return {}

    @staticmethod
    def extract_endpoints(openapi_spec: Dict[str, Any]) -> List[Tuple[str, str, str]]:
        """Extract endpoints from OpenAPI spec"""
        endpoints = []
        base_url = ""
        # Get base URL from servers
        if "servers" in openapi_spec and openapi_spec["servers"]:
            base_url = openapi_spec["servers"][0].get("url", "")
        paths = openapi_spec.get("paths", {})
        for path, methods in paths.items():
            for method, details in methods.items():
                if method.upper() in [m.value for m in HTTPMethod]:
                    full_url = urljoin(base_url, path) if base_url else path
                    operation_id = details.get("operationId", f"{method}_{path}")
                    endpoints.append((method.upper(), full_url, operation_id))
        return endpoints
