"""OpenAPI 3.x and Swagger 2.0 loading.

Turns a specification into a list of Endpoint objects with usable example values,
resolves local $ref pointers (with a loop guard), and reads the security model.
"""

from __future__ import annotations

import json
from typing import Any, Optional
from urllib.parse import urljoin, urlsplit

import yaml

from .models import Endpoint, Param

HTTP_METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")
_MAX_REF_DEPTH = 12

class SpecError(Exception):
    pass

def parse_spec_text(text: str) -> dict:
    """Parse JSON first, then YAML. Raises SpecError if neither yields an API description."""
    data: Any = None
    try:
        data = json.loads(text)
    except ValueError:
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise SpecError(f"not valid JSON or YAML: {exc}") from exc
    if not isinstance(data, dict) or ("openapi" not in data and "swagger" not in data) or "paths" not in data:
        raise SpecError("document is not an OpenAPI or Swagger specification (needs 'openapi'/'swagger' and 'paths')")
    return data

def looks_like_spec(text: str) -> bool:
    try:
        parse_spec_text(text)
        return True
    except SpecError:
        return False

class SpecModel:
    def __init__(self, document: dict, source_url: Optional[str] = None, base_url_override: Optional[str] = None):
        self.doc = document
        self.source_url = source_url
        self.base_url_override = base_url_override
        self.is_swagger2 = "swagger" in document
        self.version = str(document.get("openapi") or document.get("swagger"))

    # reference handling

    def _resolve(self, node: Any, depth: int = 0) -> Any:
        """Follow $ref chains for the node itself (not its children)."""
        seen = 0
        while isinstance(node, dict) and "$ref" in node and seen < _MAX_REF_DEPTH:
            ref = node["$ref"]
            if not isinstance(ref, str) or not ref.startswith("#/"):
                return {}  # external references are not fetched
            target: Any = self.doc
            for part in ref[2:].split("/"):
                part = part.replace("~1", "/").replace("~0", "~")
                if isinstance(target, dict) and part in target:
                    target = target[part]
                else:
                    return {}
            node = target
            seen += 1
        return node

    def _deep(self, node: Any, depth: int = 0) -> Any:
        """Resolve $ref recursively with a depth limit so recursive schemas terminate."""
        if depth > _MAX_REF_DEPTH:
            return {}
        node = self._resolve(node)
        if isinstance(node, dict):
            return {k: self._deep(v, depth + 1) for k, v in node.items()}
        if isinstance(node, list):
            return [self._deep(v, depth + 1) for v in node]
        return node

    # servers

    def base_urls(self) -> list:
        if self.base_url_override:
            return [self.base_url_override.rstrip("/")]
        urls = []
        if self.is_swagger2:
            host = self.doc.get("host")
            base = self.doc.get("basePath", "") or ""
            schemes = self.doc.get("schemes") or ["https"]
            if host:
                urls = [f"{s}://{host}{base}".rstrip("/") for s in schemes]
            elif self.source_url:
                parts = urlsplit(self.source_url)
                urls = [f"{parts.scheme}://{parts.netloc}{base}".rstrip("/")]
        else:
            for server in self.doc.get("servers") or []:
                url = str(server.get("url", ""))
                for name, var in (server.get("variables") or {}).items():
                    url = url.replace("{" + name + "}", str(var.get("default", "")))
                if self.source_url:
                    url = urljoin(self.source_url, url)
                if url.startswith("http"):
                    urls.append(url.rstrip("/"))
            if not urls and self.source_url:
                parts = urlsplit(self.source_url)
                urls = [f"{parts.scheme}://{parts.netloc}"]
        return urls

    def declared_http_servers(self) -> list:
        return [u for u in self.base_urls() if u.startswith("http://")]

    # security

    def security_schemes(self) -> dict:
        if self.is_swagger2:
            return self.doc.get("securityDefinitions") or {}
        return (self.doc.get("components") or {}).get("securitySchemes") or {}

    # endpoints

    def endpoints(self) -> list:
        bases = self.base_urls()
        if not bases:
            raise SpecError("the specification has no usable server URL; pass --base-url")
        base = bases[0]
        result = []
        for path, item in (self.doc.get("paths") or {}).items():
            item = self._resolve(item)
            if not isinstance(item, dict):
                continue
            shared = [self._deep(p) for p in item.get("parameters", [])]
            for method in HTTP_METHODS:
                op = item.get(method)
                if not isinstance(op, dict):
                    continue
                result.append(self._build_endpoint(base, path, method.upper(), op, shared))
        return result

    def _build_endpoint(self, base: str, path: str, method: str, op: dict, shared_params: list) -> Endpoint:
        params_raw = {}
        for p in shared_params + [self._deep(p) for p in op.get("parameters", [])]:
            if isinstance(p, dict) and "name" in p and "in" in p:
                params_raw[(p["in"], p["name"])] = p
        params = []
        body_schema = None
        body_type = None
        for (loc, name), p in params_raw.items():
            if loc == "body":  # swagger 2
                body_schema = p.get("schema") or {}
                body_type = "application/json"
                continue
            if loc == "formData":
                continue
            schema = p.get("schema") if "schema" in p else {k: v for k, v in p.items() if k in ("type", "format", "enum", "default", "example", "minimum", "maximum", "items")}
            schema = schema or {}
            example = p.get("example", schema.get("example"))
            if example is None:
                example = example_from_schema(schema, name=name)
            params.append(Param(name=name, location=loc, required=bool(p.get("required") or loc == "path"), schema=schema, example=example))

        request_body = self._deep(op.get("requestBody")) if op.get("requestBody") else None
        if request_body:
            content = request_body.get("content") or {}
            for ctype in ("application/json", "application/*+json"):
                if ctype in content:
                    body_type = ctype
                    body_schema = (content[ctype] or {}).get("schema") or {}
                    break
            else:
                if content:
                    body_type = next(iter(content))
        body_example = example_from_schema(body_schema) if body_schema else None

        secured, schemes = self._security_for(op)
        return Endpoint(
            method=method,
            path=path,
            base_url=base,
            op_id=str(op.get("operationId") or f"{method.lower()}_{path}"),
            params=params,
            body_schema=body_schema,
            body_example=body_example,
            body_content_type=body_type,
            secured=secured,
            security_schemes=schemes,
            tags=[str(t) for t in op.get("tags", [])],
            deprecated=bool(op.get("deprecated")),
            summary=str(op.get("summary") or ""),
        )

    def _security_for(self, op: dict) -> tuple:
        """Returns (secured, scheme names). secured is None when the spec says nothing."""
        if "security" in op:
            requirements = op["security"]
        elif "security" in self.doc:
            requirements = self.doc["security"]
        else:
            return None, []
        requirements = requirements or []
        names = sorted({name for req in requirements if isinstance(req, dict) for name in req})
        if not requirements:
            return False, []  # an explicit empty list means public
        if any(isinstance(req, dict) and not req for req in requirements):
            return False, names  # an empty requirement object makes auth optional
        return True, names

def example_from_schema(schema: Any, name: str = "", depth: int = 0) -> Any:
    """Build a plausible example value from a (resolved) JSON schema."""
    if not isinstance(schema, dict) or depth > 6:
        return None
    if "example" in schema:
        return schema["example"]
    if "default" in schema:
        return schema["default"]
    if schema.get("enum"):
        return schema["enum"][0]
    for combo in ("allOf", "oneOf", "anyOf"):
        if schema.get(combo):
            if combo == "allOf":
                merged: dict = {}
                for sub in schema[combo]:
                    value = example_from_schema(sub, name, depth + 1)
                    if isinstance(value, dict):
                        merged.update(value)
                return merged or None
            return example_from_schema(schema[combo][0], name, depth + 1)
    kind = schema.get("type")
    fmt = schema.get("format", "")
    if kind == "object" or "properties" in schema:
        out = {}
        for key, sub in list((schema.get("properties") or {}).items())[:20]:
            out[key] = example_from_schema(sub, key, depth + 1)
        return out
    if kind == "array":
        item = example_from_schema(schema.get("items") or {}, name, depth + 1)
        return [item] if item is not None else []
    if kind == "integer":
        return max(1, int(schema.get("minimum", 1)))
    if kind == "number":
        return 1.0
    if kind == "boolean":
        return True
    if kind == "string" or kind is None:
        if fmt == "uuid":
            return "00000000-0000-4000-8000-000000000001"
        if fmt == "email":
            return "scanner@example.com"
        if fmt in ("date-time",):
            return "2024-01-01T00:00:00Z"
        if fmt == "date":
            return "2024-01-01"
        if fmt in ("uri", "url"):
            return "https://example.com/"
        lowered = name.lower()
        if lowered.endswith("id") or lowered in ("id", "uid"):
            return "1"
        return "test"
    return None

def is_numeric_id_param(param: Param) -> bool:
    """True for a path parameter that holds a counting number (a candidate for id walking)."""
    if param.location != "path":
        return False
    if param.schema.get("type") in ("integer", "number"):
        return True
    return str(param.example).isdigit()
