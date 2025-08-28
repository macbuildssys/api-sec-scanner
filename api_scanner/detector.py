from typing import Dict
from .models import TechnologyInfo

class TechnologyDetector:
    """Detect technologies and frameworks"""
    @staticmethod
    def detect_from_headers(headers: Dict[str, str]) -> TechnologyInfo:
        """Detect technology from HTTP headers"""
        tech = TechnologyInfo()
        # Server detection
        server = headers.get('server', '').lower()
        if 'nginx' in server:
            tech.server = f"Nginx:{server.split('/')[1] if '/' in server else 'Unknown'}"
        elif 'apache' in server:
            tech.server = f"Apache:{server.split('/')[1] if '/' in server else 'Unknown'}"
        elif 'flask' in server:
            tech.server = f"Flask:{server.split('/')[1] if '/' in server else 'Unknown'}"
            tech.framework = tech.server
            tech.language = "Python"
        elif 'express' in server:
            tech.server = f"Express:{server.split('/')[1] if '/' in server else 'Unknown'}"
            tech.framework = tech.server
            tech.language = "JavaScript/Node.js"
        elif 'django' in server:
            tech.framework = "Django"
            tech.language = "Python"
        # Additional header-based detection
        powered_by = headers.get('x-powered-by', '').lower()
        if 'php' in powered_by:
            tech.language = f"PHP:{powered_by.split('/')[1] if '/' in powered_by else 'Unknown'}"
        elif 'asp.net' in powered_by:
            tech.language = "ASP.NET"
            tech.framework = "ASP.NET"
        return tech

    @staticmethod
    def detect_from_response(content: str, headers: Dict[str, str]) -> TechnologyInfo:
        """Enhanced technology detection from response content"""
        tech = TechnologyDetector.detect_from_headers(headers)
        content_lower = content.lower()
        # Framework detection patterns
        if 'django' in content_lower:
            tech.framework = "Django"
            tech.language = "Python"
        elif 'flask' in content_lower:
            tech.framework = "Flask"
            tech.language = "Python"
        elif 'fastapi' in content_lower:
            tech.framework = "FastAPI"
            tech.language = "Python"
        elif 'spring boot' in content_lower or 'spring-boot' in content_lower:
            tech.framework = "Spring Boot"
            tech.language = "Java"
        elif 'express' in content_lower and 'node' in content_lower:
            tech.framework = "Express.js"
            tech.language = "Node.js"
        elif 'react' in content_lower:
            tech.framework = "React"
            tech.language = "JavaScript"
        return tech
