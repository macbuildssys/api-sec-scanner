import asyncio
from typing import List
from urllib.parse import urljoin
import aiohttp
from .models import DiscoveryResult, TechnologyInfo
from .detector import TechnologyDetector

class APIDiscoverer:
    """API discovery and reconnaissance"""
    def __init__(self):
        self.common_paths = [
            # OpenAPI/Swagger
            "/openapi.json", "/openapi.yaml", "/swagger.json", "/swagger.yaml",
            "/api/openapi.json", "/api/swagger.json", "/docs/openapi.json",
            "/v1/openapi.json", "/v2/openapi.json", "/v3/openapi.json",
            # GraphQL
            "/graphql", "/api/graphql", "/v1/graphql", "/query",
            # Well-known paths
            "/.well-known/openapi.json", "/.well-known/security.txt",
            "/.well-known/jwks.json", "/.well-known/oauth-authorization-server",
            # Exposed files
            "/.env", "/.env.dev", "/.env.prod", "/.env.local",
            "/config.json", "/config.yaml", "/swagger-ui.html",
            "/api-docs", "/docs", "/redoc", "/health", "/status",
            "/version", "/info", "/metrics", "/debug"
        ]

    async def discover(self, base_url: str) -> DiscoveryResult:
        """Discover API endpoints and information"""
        result = DiscoveryResult(
            openapi_urls=[],
            graphql_urls=[],
            well_known_urls=[],
            exposed_files=[],
            technologies=TechnologyInfo()
        )
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
            # Test main endpoint first for technology detection
            try:
                async with session.get(base_url) as response:
                    content = await response.text()
                    result.technologies = TechnologyDetector.detect_from_response(
                        content, dict(response.headers)
                    )
            except:
                pass
            tasks = []
            for path in self.common_paths:
                test_url = urljoin(base_url, path)
                tasks.append(self._test_endpoint(session, test_url, result))
            await asyncio.gather(*tasks, return_exceptions=True)
        return result

    async def _test_endpoint(self, session: aiohttp.ClientSession, url: str, result: DiscoveryResult):
        """Test individual endpoint"""
        try:
            async with session.get(url) as response:
                if response.status == 200:
                    content = await response.text()
                    content_type = response.headers.get('content-type', '').lower()
                    # Categorize found endpoints
                    if any(keyword in url.lower() for keyword in ['openapi', 'swagger']):
                        result.openapi_urls.append(url)
                    elif 'graphql' in url.lower():
                        result.graphql_urls.append(url)
                    elif '.well-known' in url:
                        result.well_known_urls.append(url)
                    elif any(file in url for file in ['.env', 'config', 'debug']):
                        result.exposed_files.append(url)
        except:
            pass
