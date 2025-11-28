import asyncio
import click
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from api_scanner.scanner import AdvancedAPIScanner
from cli.report import ReportGenerator

WELCOME_MESSAGE = r"""
__        __   _                            _
\ \      / /__| | ___ ___  _ __ ___   ___  | |
 \ \ /\ / / _ \ |/ __/ _ \| '_ ` _ \ / _ \ | |
  \ V  V /  __/ | (_| (_) | | | | | |  __/ |_|
   \_/\_/ \___|_|\___\___/|_| |_| |_|\___| (_)
   Detect vulnerabilities in HTTPS/REST APIs
"""

@click.command()
@click.argument('url', required=False)
@click.option('--output', '-o', help='Output file for report')
@click.option('--format', '-f', type=click.Choice(['json', 'markdown', 'console']),
              default='console', help='Report format')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def main(url, output, format, verbose):
    """
    Advanced API Security Scanner - Detect vulnerabilities in REST APIs
    URL: Target API base URL to scan (optional - will prompt if not provided)
    """
    console = Console()
    console.print(Panel(Align.center(WELCOME_MESSAGE, style="bold blue"), title="[bold blue]API Security Scanner[/bold blue]", border_style="blue"))

    if not url:
        console.print("\n[yellow]Please enter the API URL to scan:[/yellow]")
        url = click.prompt("API URL", type=str)
    console.print(f"[blue]Target URL: {url}[/blue]")
    # Ask user to choose scan method
    console.print("\n[yellow]Choose scanning method:[/yellow]")
    console.print("1. [bold]HTTPS/REST API Scan[/bold] - Standard endpoint security scan (supports OpenAPI/Swagger)")
    console.print("2. [bold]Discovery Mode[/bold] - Find endpoints and technologies")
    choice = click.prompt("Select option", type=click.Choice(['1', '2']), default='1')
    try:
        scanner = AdvancedAPIScanner()
        if choice == '1':
            # HTTPS/REST API Scan
            console.print("\n[bold green]Starting HTTPS/REST API security scan...[/bold green]")
            # Detect authentication
            console.print("[yellow]Detecting authentication requirements...[/yellow]")
            try:
                import requests
                initial_response = requests.get(url, timeout=10)
                console.print(f"[blue]Detected auth type: none[/blue]")
                # Ask for JWT token if needed
                jwt_token = None
                if click.confirm("Do you have a JWT token for authentication?", default=False):
                    jwt_token = click.prompt("Enter JWT token", hide_input=True)
                    console.print("[green] JWT token configured[/green]")
                # Always attempt OpenAPI/Swagger scan
                openapi_path = f"{url}/openapi.json"
                console.print(f"\n[bold green] Attempting OpenAPI/Swagger specification scan at {openapi_path}...[/bold green]")
                try:
                    scan_result = asyncio.run(scanner.scan_openapi(openapi_path, jwt_token))
                except Exception:
                    console.print("[yellow]️ OpenAPI/Swagger scan failed, falling back to standard REST scan[/yellow]")
                    scan_result = asyncio.run(scanner.scan_curl(url, "GET", {}, jwt_token))
            except requests.exceptions.RequestException as e:
                console.print(f"[red]Failed to connect to {url}: {str(e)}[/red]")
                return
        else:
            # Discovery Mode
            console.print(f"\n[bold green] Starting API discovery...[/bold green]")
            discovery_result = asyncio.run(scanner.discover_api(url))
            ReportGenerator.display_discovery_results(discovery_result)
            return
        # Display results
        report_gen = ReportGenerator()
        if format == 'console' or not output:
            report_gen.display_scan_results(scan_result)
        if output:
            if format == 'json':
                report_gen.generate_json_report(scan_result, output)
            elif format == 'markdown':
                report_gen.generate_markdown_report(scan_result, output)
        console.print(f"\n[green] Scan completed in {scan_result.scan_duration:.2f} seconds[/green]")
    except Exception as e:
        console.print(f"[red]Unexpected error: {str(e)}[/red]")
        if verbose:
            import traceback
            console.print(traceback.format_exc())
