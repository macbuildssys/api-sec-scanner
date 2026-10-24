# API Security Scanner

<p align="center">
  <img src="icons/api-sec-scanner.png" alt="api-sec-scanner logo" width="200">
</p>

Detect vulnerabilities in REST APIs and websites. The scanner sends real requests, compares the answers, and only reports a weakness when it saw the evidence. Every weakness gets a CVSS 4.0 score and is mapped to the OWASP API Security Top 10 (2023), the OWASP Top 10 (2025), CWE and MITRE ATT&CK.

## How it works

* Give it an API address (it finds the OpenAPI document by itself, or you pass `--spec`) or a website address (it crawls up to 25 pages).
* It checks headers, TLS, cookies, forms, leftover files, access control, JWT tokens and the software versions the server announces.
* It asks free public sources (certificate logs, web archives, DNS) about the site to find more things to test. Only the site name is sent. Turn this off with `--no-osint`, or turn off every outside lookup with `--offline`.
* Safe by default: read requests only. `--active` adds attack payloads (injection, SSRF, path traversal). `--allow-mutating` also sends POST, PUT, PATCH and DELETE, which can change data, so use it only on a test system.
* The report lists each weakness with severity, CVSS score, priority and the evidence. Reports can be console, JSON, Markdown, HTML or SARIF.

Only scan systems you own or have written permission to test.

## Install


The .deb, for Debian, Ubuntu and Mint. It adds the commands `api-sec-scanner` and `scan`:

    sudo apt install ./dist/api-sec-scanner-v0.0.1.deb

The AppImage, for any 64 bit Linux. Nothing is installed:

    chmod +x dist/api-sec-scanner-v0.0.1-x86_64.AppImage
    ./dist/api-sec-scanner-v0.0.1-x86_64.AppImage

## Run

Guided scan, it asks for the address and options:

    api-sec-scanner

Scan an address:

    scan https://www.example.com
    scan https://api.example.com --spec https://api.example.com/openapi.json --token "$TOKEN"

Save reports (default folder is Downloads, named report-DD-MM-YYYY):

    scan https://www.example.com -f html -f json

Other commands:

    api-sec-scanner checks              # list the checks
    api-sec-scanner explain BOLA-001    # read about one check
    scan --help                         # all options

Useful options: `--active`, `--allow-mutating`, `--token`, `--token-b` (a second user, to prove broken object access), `--browser` (JavaScript sites), `--max-pages`, `--rps`, `--fail-on high` (for CI), `--profile asset-profile.yaml`.

## Build the packages

    packaging/build-deb.sh          # dist/api-sec-scanner-v0.0.1.deb
    packaging/build-appimage.sh     # dist/api-sec-scanner-v0.0.1-x86_64.AppImage

## Limits

A clean report is not proof that a target is secure. The scanner only finds what shows up over HTTP, and it does not replace a penetration test.

## License

Distributed under the MIT License. See [LICENSE](LICENSE).