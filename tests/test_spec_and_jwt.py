import base64
import json

import pytest

from api_scanner.checks.jwt_audit import b64url_decode, crack_hmac_secret, damage_signature, forge_none, parse_jwt
from api_scanner.spec import SpecError, SpecModel, example_from_schema, parse_spec_text

OAS3 = """
openapi: 3.0.3
info: {title: t, version: '1'}
servers:
  - url: https://{env}.example.com/api
    variables: {env: {default: staging}}
security:
  - bearerAuth: []
components:
  securitySchemes:
    bearerAuth: {type: http, scheme: bearer}
  parameters:
    Id: {name: id, in: path, required: true, schema: {type: integer}}
  schemas:
    Node:
      type: object
      properties:
        name: {type: string}
        child: {$ref: '#/components/schemas/Node'}
paths:
  /things/{id}:
    parameters:
      - $ref: '#/components/parameters/Id'
    get:
      operationId: getThing
      parameters:
        - {name: limit, in: query, schema: {type: integer, maximum: 50}}
    put:
      security: []
      requestBody:
        content:
          application/json:
            schema: {$ref: '#/components/schemas/Node'}
  /health:
    get:
      security: [{}]
"""

SWAGGER2 = {
    "swagger": "2.0", "host": "api.example.com", "basePath": "/v1", "schemes": ["https"],
    "paths": {"/pets": {"post": {"parameters": [{"in": "body", "name": "b", "schema": {"type": "object", "properties": {"n": {"type": "string"}}}}]}}},
}

def test_openapi3_refs_servers_and_security():
    model = SpecModel(parse_spec_text(OAS3))
    assert model.base_urls() == ["https://staging.example.com/api"]
    eps = {e.label: e for e in model.endpoints()}
    get = eps["GET /things/{id}"]
    assert get.secured is True and get.security_schemes == ["bearerAuth"]
    assert [p.name for p in get.params if p.location == "path"] == ["id"]  # resolved from a shared $ref
    assert get.url().endswith("/api/things/1")
    assert eps["PUT /things/{id}"].secured is False  # explicit empty security means public
    assert eps["GET /health"].secured is False  # an empty requirement object makes auth optional
    body = eps["PUT /things/{id}"].body_example
    assert body["name"] == "test"  # recursive schema terminated

def test_swagger2_is_supported():
    model = SpecModel(SWAGGER2)
    ep = model.endpoints()[0]
    assert ep.base_url == "https://api.example.com/v1"
    assert ep.body_example == {"n": "test"}

def test_relative_server_is_resolved_against_spec_location():
    model = SpecModel({"openapi": "3.0.0", "servers": [{"url": "/api/v2"}], "paths": {}}, source_url="https://h.example/docs/openapi.json")
    assert model.base_urls() == ["https://h.example/api/v2"]

def test_missing_server_is_an_error_not_a_silent_miss():
    model = SpecModel({"openapi": "3.0.0", "paths": {"/a": {"get": {}}}})
    with pytest.raises(SpecError):
        model.endpoints()

def test_not_a_spec_is_rejected():
    with pytest.raises(SpecError):
        parse_spec_text('{"hello": "world"}')

def test_examples_use_formats():
    assert example_from_schema({"type": "string", "format": "uuid"}).count("-") == 4
    assert example_from_schema({"type": "integer", "minimum": 5}) == 5
    assert example_from_schema({"enum": ["a", "b"]}) == "a"

def _token(header, payload, secret=None):
    import hashlib
    import hmac

    def enc(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()

    signing = f"{enc(header)}.{enc(payload)}"
    sig = b""
    if secret is not None:
        sig = hmac.new(secret.encode(), signing.encode(), hashlib.sha256).digest()
    return signing + "." + base64.urlsafe_b64encode(sig).rstrip(b"=").decode()

def test_weak_secret_is_recovered_and_strong_one_is_not():
    assert crack_hmac_secret(_token({"alg": "HS256"}, {"sub": "a"}, "secret")) == "secret"
    assert crack_hmac_secret(_token({"alg": "HS256"}, {"sub": "a"}, "k9$Zq2!vWm4#xL7pRt8@")) is None
    assert crack_hmac_secret("not-a-jwt") is None

def test_damaged_signature_really_changes_the_decoded_bytes():
    token = _token({"alg": "HS256"}, {"sub": "a"}, "whatever")
    damaged = damage_signature(token)
    assert damaged != token
    assert b64url_decode(damaged.split(".")[2]) != b64url_decode(token.split(".")[2])

def test_none_algorithm_token_has_empty_signature():
    forged = forge_none(_token({"alg": "HS256"}, {"sub": "a"}, "x"), "none")
    header, payload, _, sig = parse_jwt(forged)
    assert header["alg"] == "none" and payload == {"sub": "a"} and sig == b"" and forged.endswith(".")
