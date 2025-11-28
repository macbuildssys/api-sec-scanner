from typing import Optional
from rich.align import Align
from rich.console import Console
from rich.text import Text
from rich.panel import Panel
from rich.table import Table
from rich.markdown import Markdown
from rich.tree import Tree
from api_scanner.models import DiscoveryResult, ScanResult, RiskLevel


class ReportGenerator:
    @staticmethod
    def display_discovery_results(discovery: DiscoveryResult):
        """Display API discovery results in professional format"""
        console = Console()
        console.print("\n[bold blue] API Discovery Results[/bold blue]\n")
        has_urls = any([discovery.openapi_urls, discovery.graphql_urls, discovery.well_known_urls, discovery.exposed_files])
        has_tech = any([discovery.technologies.framework, discovery.technologies.language, discovery.technologies.server])
        if not has_urls and not has_tech:
            console.print("[yellow]No API endpoints, files, or technology information discovered.[/yellow]")
            return
        if has_urls:
            url_table = Table(title="Discovered URLs", show_header=True, header_style="bold magenta")
            url_table.add_column("TYPE", style="bold")
            url_table.add_column("URL", style="dim")
            for url in discovery.openapi_urls:
                url_table.add_row("OpenAPI", url)
            for url in discovery.graphql_urls:
                url_table.add_row("GraphQL", url)
            for url in discovery.well_known_urls:
                url_table.add_row("Well-Known", url)
            for url in discovery.exposed_files:
                url_table.add_row("Exposed Files", url)
            console.print(url_table)
            console.print()
        if has_tech:
            tech_table = Table(title="Technology Detection", show_header=True, header_style="bold magenta")
            tech_table.add_column("TECH STACK", style="bold")
            tech_table.add_column("VALUE", style="dim")
            if discovery.technologies.framework:
                tech_table.add_row("Framework", discovery.technologies.framework)
            if discovery.technologies.language:
                tech_table.add_row("Language", discovery.technologies.language)
            if discovery.technologies.server:
                tech_table.add_row("Server", discovery.technologies.server)
            if discovery.technologies.version:
                tech_table.add_row("Version", discovery.technologies.version)
            console.print(tech_table)

    @staticmethod
    def display_scan_results(scan_result: ScanResult):
        """Display comprehensive scan results"""
        console = Console()
        console.print(f"\n[bold green] API Security Scan Results[/bold green]\n")
        # Technology information
        if any([scan_result.technologies.framework, scan_result.technologies.language, scan_result.technologies.server]):
            tech_table = Table(show_header=True, header_style="bold magenta")
            tech_table.add_column("TECH STACK", style="bold")
            tech_table.add_column("VALUE", style="dim")
            if scan_result.technologies.framework:
                tech_table.add_row("Framework", scan_result.technologies.framework)
            if scan_result.technologies.language:
                tech_table.add_row("Language", scan_result.technologies.language)
            if scan_result.technologies.server:
                tech_table.add_row("Server", scan_result.technologies.server)
            console.print(tech_table)
            console.print()
        # Advice
        advice_color = "red" if "Critical" in scan_result.advice else "yellow" if "medium-risk" in scan_result.advice else "green"
        console.print(f"[{advice_color}]Advice: {scan_result.advice}[/{advice_color}]\n")
        if not scan_result.vulnerabilities:
            console.print("[green] No vulnerabilities detected![/green]")
            return
        # Vulnerabilities table
        vuln_table = Table(show_header=True, header_style="bold magenta")
        vuln_table.add_column("OPERATION", style="bold", width=20)
        vuln_table.add_column("RISK LEVEL", style="bold", width=12)
        vuln_table.add_column("CVSS 4.0 SCORE", style="bold", width=15)
        vuln_table.add_column("OWASP", style="bold", width=15)
        vuln_table.add_column("VULNERABILITY", style="dim", width=40)
        # Group vulnerabilities by operation for better display
        for vuln in scan_result.vulnerabilities:
            risk_color = {
                RiskLevel.CRITICAL: "bright_red",
                RiskLevel.HIGH: "red",
                RiskLevel.MEDIUM: "yellow",
                RiskLevel.LOW: "blue",
                RiskLevel.INFO: "green"
            }[vuln.risk_level]
            vuln_table.add_row(
                vuln.operation,
                f"[{risk_color}]{vuln.risk_level.value}[/{risk_color}]",
                f"{vuln.cvss_score.score}",
                vuln.owasp_category,
                vuln.description
            )
        console.print(vuln_table)
        console.print(f"\n[dim]Scan completed in {scan_result.scan_duration:.2f}s | Operations scanned: {scan_result.total_operations} | Vulnerabilities found: {len(scan_result.vulnerabilities)}[/dim]")
