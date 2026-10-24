"""The OSINT section shared by the console, Markdown and HTML reports. It reads the summary stored in ScanResult.mode["osint"]."""

from __future__ import annotations

from urllib.parse import urlsplit

HOST_COLUMNS = ("Host", "Address", "Web", "What answers")

def host_rows(info: dict) -> list:
    """One row per name that was resolved: the live ones first."""
    rows = []
    for h in info.get("hosts", []):
        if h["resolves"] is False:
            web = "does not resolve" + (f" (CNAME {h['cname']})" if h["cname"] else "")
        elif h["status"] is None:
            web = "no web answer"
        else:
            web = str(h["status"]) + (f" to {urlsplit(h['location']).netloc}" if urlsplit(h["location"]).netloc else "")
        detail = (h["title"] or h["server"])[:40]
        rows.append((h["status"] is None, h["name"], (h["ips"] or [""])[0],
                     web, detail))
    rows.sort(key=lambda r: (r[0], r[1]))
    return [r[1:] for r in rows]

def facts(info: dict) -> list:
    """Plain sentences about what the sources said."""
    out = []
    reg = info.get("registration") or {}
    if reg:
        bits = [f"registered {reg['created']}" if reg.get("created") else "", f"expires {reg['expires']}" if reg.get("expires") else "",
                f"registrar {reg['registrar']}" if reg.get("registrar") else "", f"name servers {', '.join(reg['nameservers'][:4])}" if reg.get("nameservers") else ""]
        out.append(f"Domain {info['domain']}: " + ", ".join(b for b in bits if b) + ".")
    mail = info.get("mail")
    if mail:
        out.append(f"Mail: {mail['domain']} receives mail via {', '.join(mail['mx'])}; SPF {'present' if mail['spf'] else 'missing'}, "
                   f"DMARC {'present' if mail['dmarc'] else 'missing'}.")
    for ip, ports in (info.get("open_ports") or {}).items():
        out.append(f"Shodan InternetDB lists these open ports on {ip}: {', '.join(str(p) for p in ports) or 'none'}.")
    if info.get("robots_paths"):
        out.append(f"robots.txt asks crawlers to avoid: {', '.join(info['robots_paths'][:8])}.")
    if info.get("security_txt") is not None:
        out.append("A security.txt file " + ("is published." if info["security_txt"] else "is not published."))
    if info.get("sources"):
        out.append("Sources that answered: " + ", ".join(f"{k} ({v})" for k, v in info["sources"].items()) + ".")
    if info.get("tools"):
        out.append("Installed tools used: " + ", ".join(info["tools"]) + ".")
    if info.get("unavailable"):
        out.append("Sources that did not answer: " + ", ".join(info["unavailable"]) + ".")
    return out
