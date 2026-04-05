#!/usr/bin/env python3
"""
API Misconfiguration Scanner - Main Entry Point

DISCLAIMER: This tool is for authorized security research and penetration testing ONLY.
Always obtain written permission before testing any system you do not own.
Unauthorized testing is illegal and unethical.
"""

import asyncio
import aiohttp
import sys
import json
import time
from pathlib import Path
from datetime import datetime

import urllib3
import click

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from modules.mutator import JWTMutator, HMACMutator
from modules.sender import RequestSender, AsyncRequestSender
from modules.analyzer import ResponseAnalyzer
from modules.reporter import Reporter, REMEDIATION_MAP
from modules.config_loader import load_config
from modules.token_validator import validate_token_health, summarise_token

console = Console()

BANNER = """
[bold cyan]
 █████╗ ██████╗ ██╗    ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
██╔══██╗██╔══██╗██║    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
███████║██████╔╝██║    ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
██╔══██║██╔═══╝ ██║    ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
██║  ██║██║     ██║    ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
╚═╝  ╚═╝╚═╝     ╚═╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
[/bold cyan]
[bold green]➜[/bold green] [bold white]API Misconfiguration Scanner[/bold white] [bold yellow]v2.1.0[/bold yellow]
[dim red]─────────────────────────────────────────────────────────────────────────────[/dim red]
[bold red]  ⚠ FOR AUTHORIZED SECURITY RESEARCH ONLY. GET WRITTEN PERMISSION FIRST. ⚠[/bold red]
[dim red]─────────────────────────────────────────────────────────────────────────────[/dim red]
"""


def wizard_mode():
    """Interactive guided setup for the scanner."""
    console.print(Panel("[bold yellow]Interactive Setup Wizard[/bold yellow]\n[dim]Follow the prompts to configure your scan[/dim]", border_style="yellow"))
    
    target = click.prompt("[bold cyan]Target Base URL[/bold cyan] (e.g., http://localhost:5000)", type=str)
    endpoint = click.prompt("[bold cyan]Endpoint Path[/bold cyan] (e.g., /api/admin)", type=str)
    
    token_type = click.prompt(
        "[bold cyan]Token Type[/bold cyan]",
        type=click.Choice(["jwt", "hmac", "oauth", "session", "apikey", "basic"]),
        default="jwt"
    )
    
    token = click.prompt("[bold cyan]Valid Auth Token / Value[/bold cyan]", type=str)
    
    secret = None
    if token_type == "hmac":
        secret = click.prompt("[bold cyan]HMAC Secret[/bold cyan] (press enter to brute-force)", default="", show_default=False)
        secret = secret if secret else None

    html_report = click.confirm("[bold cyan]Generate HTML report?[/bold cyan]", default=True)
    async_scan = click.confirm("[bold cyan]Enable asynchronous scanning? (Faster)[/bold cyan]", default=False)
    
    return {
        "target": target, "endpoint": endpoint, "token": token,
        "token_type": token_type, "secret": secret, "html_report": html_report,
        "async_scan": async_scan
    }


def detect_auth_scheme(response):
    headers = response.get("headers", {})
    raw_body = response.get("raw_body", "")
    cookies = headers.get("set-cookie", "") or headers.get("Set-Cookie", "")
    auth_header = headers.get("WWW-Authenticate", "")
    if "Bearer" in auth_header:
        return "token"
    if "session=" in cookies.lower():
        return "session"
    if "<form" in raw_body.lower() and "csrf" in raw_body.lower():
        return "session"
    return "unknown"


def build_mutations(token_type, token, secret, verbose, wordlist, ml_rank):
    mutations = []
    if token_type == "jwt":
        mutator = JWTMutator(token, verbose=verbose)
        mutations = mutator.generate_all_mutations()
    elif token_type == "hmac":
        mutator = HMACMutator(token, secret=secret, verbose=verbose, wordlist=wordlist)
        mutations = mutator.generate_all_mutations()
    elif token_type == "oauth":
        from extensions.oauth_mutator import OAuthMutator
        mutator = OAuthMutator(token, verbose=verbose)
        mutations = mutator.generate_all_mutations()
    elif token_type == "session":
        from modules.generic_auth_scanner import SessionCookieMutator
        mutator = SessionCookieMutator("session", token, verbose=verbose)
        mutations = mutator.generate_all_mutations()
    elif token_type == "apikey":
        from modules.generic_auth_scanner import APIKeyMutator
        mutator = APIKeyMutator(token, verbose=verbose)
        mutations = mutator.generate_all_mutations()
    elif token_type == "basic":
        from modules.generic_auth_scanner import BasicAuthMutator
        user, _, pwd = token.partition(":")
        mutator = BasicAuthMutator(user, pwd, verbose=verbose)
        mutations = mutator.generate_all_mutations()

    if ml_rank and mutations:
        try:
            from extensions.ml_ranker import MLRanker
            ranker = MLRanker()
            mutations = ranker.rank_mutations(mutations)
            console.print(f"[dim]ML ranking applied to {len(mutations)} mutations[/dim]")
        except Exception as e:
            console.print(f"[yellow]ML ranking unavailable: {e}[/yellow]")

    return mutations


def send_mutation(sender, full_url, method, mutation, token_type,
                  cookie_name, api_key_header, extra_headers):
    if token_type == "session":
        name = mutation.get("cookie_name", cookie_name or "session")
        return sender.send_with_cookie(
            url=full_url, method=method,
            token=mutation["token"],
            cookie_name=name,
            extra_headers=extra_headers,
        )
    if token_type == "apikey":
        hdr_name = mutation.get("header_name", api_key_header or "X-API-Key")
        custom = {hdr_name: mutation["token"]}
        custom.update(extra_headers)
        return sender.send(url=full_url, method=method, token="", token_type="jwt", headers=custom)
    if token_type == "basic":
        custom = {"Authorization": mutation["token"]}
        custom.update(extra_headers)
        return sender.send(url=full_url, method=method, token="", token_type="jwt", headers=custom)
    return sender.send(
        url=full_url, method=method,
        token=mutation["token"],
        token_type="jwt" if token_type == "oauth" else token_type,
        headers=extra_headers,
    )


@click.command()
@click.option("--target",         default=None)
@click.option("--endpoint",       default=None)
@click.option("--token",          default=None)
@click.option("--type",           "token_type", default=None,
              type=click.Choice(["jwt", "hmac", "oauth", "session", "apikey", "basic"]))
@click.option("--secret",         default=None)
@click.option("--method",         default="GET")
@click.option("--headers",        default=None)
@click.option("--output",         default=None)
@click.option("--html-report",    is_flag=True, default=False)
@click.option("--rate-limit",     default=1.0, type=float)
@click.option("--timeout",        default=10, type=int)
@click.option("--safe-mode",      is_flag=True, default=True)
@click.option("--verbose",        is_flag=True, default=False)
@click.option("--ml-rank",        is_flag=True, default=False)
@click.option("--grpc",           is_flag=True, default=False)
@click.option("--proxy",          default=None)
@click.option("--insecure",       is_flag=True, default=False)
@click.option("--auth-header",    default="Authorization")
@click.option("--async-scan",     "async_scan", is_flag=True, default=False)
@click.option("--concurrency",    default=10, type=int)
@click.option("--wordlist",       default=None)
@click.option("--config",         "config_file", default=None)
@click.option("--cookie-name",    default=None, help="Cookie name for session auth")
@click.option("--api-key-header", default="X-API-Key", help="Header name for API key auth")
@click.option("--wizard",         is_flag=True, default=False, help="Launch interactive setup wizard")
def main(target, endpoint, token, token_type, secret, method, headers,
         output, html_report, rate_limit, timeout, safe_mode, verbose, ml_rank, grpc,
         proxy, insecure, auth_header, async_scan, concurrency, wordlist, config_file,
         cookie_name, api_key_header, wizard):
    
    console.print(BANNER)

    if wizard:
        w_params = wizard_mode()
        target      = w_params["target"]
        endpoint    = w_params["endpoint"]
        token       = w_params["token"]
        token_type  = w_params["token_type"]
        secret      = w_params["secret"]
        html_report = w_params["html_report"]
        async_scan  = w_params["async_scan"]

    config_params = {}

    config_params = {}
    if config_file:
        try:
            config_params = load_config(config_file)
        except Exception as e:
            console.print(f"[red]Error loading config: {e}[/red]")
            sys.exit(1)

    target     = target     or config_params.get("target")
    endpoint   = endpoint   or config_params.get("endpoint")
    token      = token      or config_params.get("token")
    token_type = token_type or config_params.get("type")

    missing = [f for f, v in [("--target", target), ("--endpoint", endpoint),
                               ("--token", token), ("--type", token_type)] if not v]
    if missing:
        console.print(f"[red]Missing required arguments: {', '.join(missing)}[/red]")
        sys.exit(1)

    is_healthy, health_msg = validate_token_health(token, token_type)
    if not is_healthy:
        console.print(f"[red]Token health check failed: {health_msg}[/red]")
        sys.exit(1)
    if "WARNING" in health_msg:
        console.print(f"[yellow]{health_msg}[/yellow]")

    console.print(BANNER)

    tok_summary = summarise_token(token, token_type)
    parts = [f"{k}={v}" for k, v in tok_summary.items() if k != "type" and v is not None]
    console.print(f"[dim]Token info: {' | '.join(parts)}[/dim]")

    console.print(Panel(
        f"[bold cyan]Target      :[/bold cyan] [white]{target}{endpoint}[/white]\n"
        f"[bold cyan]Auth Type   :[/bold cyan] [bold yellow]{token_type.upper()}[/bold yellow]\n"
        f"[bold cyan]Method      :[/bold cyan] {method}\n"
        f"[bold cyan]Safe Mode   :[/bold cyan] {'[green]Enabled[/green]' if safe_mode else '[red]Disabled[/red]'}" +
        (f"\n[bold cyan]Cookie      :[/bold cyan] {cookie_name}" if cookie_name else "") +
        (f"\n[bold cyan]API Header  :[/bold cyan] {api_key_header}" if token_type == "apikey" else "") +
        (f"\n[bold cyan]Wordlist    :[/bold cyan] {wordlist}" if wordlist else "") +
        (f"\n[bold cyan]Async       :[/bold cyan] {'[green]Yes[/green]' if async_scan else '[white]No[/white]'}"),
        title="[bold white]SCAN CONFIGURATION[/bold white]",
        border_style="cyan",
        expand=False
    ))

    extra_headers = json.loads(headers) if headers else {}
    full_url      = f"{target.rstrip('/')}/{endpoint.lstrip('/')}"

    sender   = RequestSender(
        base_url=target, timeout=timeout,
        rate_limit=rate_limit if safe_mode else 0,
        verbose=verbose, proxy=proxy,
        verify_ssl=not insecure, auth_header_name=auth_header,
    )
    analyzer = ResponseAnalyzer(verbose=verbose)
    reporter = Reporter()

    console.print("[yellow]Getting baseline response...[/yellow]")
    baseline = send_mutation(
        sender, full_url, method,
        {"token": token, "cookie_name": cookie_name, "header_name": api_key_header},
        token_type, cookie_name, api_key_header, extra_headers,
    )

    if not baseline:
        console.print("[red]Could not reach target.[/red]")
        sys.exit(1)

    console.print(f"[green]Baseline HTTP {baseline.get('status_code')}[/green]")

    auth_scheme = detect_auth_scheme(baseline)
    if auth_scheme == "session" and token_type not in ("session",):
        console.print("[yellow]Session-cookie auth detected. Consider --type session[/yellow]")

    try:
        mutations = build_mutations(token_type, token, secret, verbose, wordlist, ml_rank)
    except Exception as e:
        console.print(f"[red]Failed to generate mutations: {e}[/red]")
        sys.exit(1)

    console.print(f"[green]{len(mutations)} mutations generated[/green]")

    findings      = []
    all_responses = []

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn()) as progress:
        task = progress.add_task("Scanning...", total=len(mutations))

        if async_scan and token_type in ("jwt", "hmac", "oauth"):
            findings = asyncio.run(run_async_scan(
                target=target, endpoint=endpoint, token_type=token_type,
                method=method, mutations=mutations, extra_headers=extra_headers,
                timeout=timeout, verbose=verbose, proxy=proxy, insecure=insecure,
                auth_header=auth_header, baseline=baseline, analyzer=analyzer,
                progress=progress, task_id=task, concurrency=concurrency,
            ))
        else:
            for mutation in mutations:
                response = send_mutation(
                    sender, full_url, method, mutation,
                    token_type, cookie_name, api_key_header, extra_headers,
                )
                all_responses.append(response)
                if response:
                    finding = analyzer.analyze(mutation=mutation, response=response, baseline=baseline)
                    if finding["is_vulnerable"]:
                        findings.append(finding)
                progress.advance(task)
                if safe_mode:
                    time.sleep(rate_limit)

    if not async_scan and all_responses:
        baseline_time = baseline.get("response_time_ms", 100)
        timing_findings = analyzer.detect_timing_oracle(mutations, all_responses, baseline_time)
        if timing_findings:
            console.print(f"[yellow]{len(timing_findings)} potential timing oracle(s) detected[/yellow]")
            findings.extend(timing_findings)

    _display_results(findings, len(mutations))

    summary_counts = {
        "total_vulnerabilities": len(findings),
        "critical": sum(1 for f in findings if f.get("severity") == "CRITICAL"),
        "high":     sum(1 for f in findings if f.get("severity") == "HIGH"),
        "medium":   sum(1 for f in findings if f.get("severity") == "MEDIUM"),
        "low":      sum(1 for f in findings if f.get("severity") == "LOW"),
    }

    report_data = {
        "scan_info": {
            "target": full_url, "token_type": token_type,
            "timestamp": datetime.now().isoformat(),
            "total_mutations": len(mutations),
            "baseline_status": baseline.get("status_code"),
        },
        "summary": summary_counts,
        "findings": findings,
    }

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    if not output:
        Path("reports").mkdir(exist_ok=True)
        output = f"reports/scan_{timestamp}.json"

    Path(output).parent.mkdir(parents=True, exist_ok=True)
    reporter.save_json(report_data, output)
    console.print(f"[green]JSON report: {output}[/green]")

    if html_report:
        html_path = output.replace(".json", ".html")
        reporter.save_html(report_data, html_path)
        console.print(f"[green]HTML report: {html_path}[/green]")


async def run_async_scan(target, endpoint, token_type, method, mutations, extra_headers,
                         timeout, verbose, proxy, insecure, auth_header, baseline,
                         analyzer, progress, task_id, concurrency):
    full_url  = f"{target.rstrip('/')}/{endpoint.lstrip('/')}"
    sender    = AsyncRequestSender(
        base_url=target, timeout=timeout, verbose=verbose,
        proxy=proxy, verify_ssl=not insecure, auth_header_name=auth_header,
    )
    findings  = []
    semaphore = asyncio.Semaphore(concurrency)

    async def scan_mutation(session, mutation):
        async with semaphore:
            response = await sender.send(
                session=session, url=full_url, method=method,
                token=mutation["token"],
                token_type="jwt" if token_type == "oauth" else token_type,
                headers=extra_headers,
            )
            if response:
                finding = analyzer.analyze(mutation=mutation, response=response, baseline=baseline)
                if finding["is_vulnerable"]:
                    findings.append(finding)
            progress.advance(task_id)

    async with aiohttp.ClientSession() as session:
        await asyncio.gather(*[scan_mutation(session, m) for m in mutations])
    return findings


def _display_results(findings, total):
    console.rule("[bold cyan]SCAN RESULTS[/bold cyan]")
    if not findings:
        console.print(f"[green]No vulnerabilities detected across {total} mutations[/green]")
        return

    table = Table(box=box.ROUNDED, show_header=True, header_style="bold magenta")
    table.add_column("Mutation")
    table.add_column("Category")
    table.add_column("Severity")
    table.add_column("Status")
    table.add_column("Confidence")

    for f in findings:
        color = ("red" if f["severity"] == "CRITICAL"
                 else "yellow" if f["severity"] in ("HIGH", "MEDIUM") else "cyan")
        table.add_row(
            f["mutation_name"], f["category"],
            f"[{color}]{f['severity']}[/{color}]",
            str(f["response_status"]),
            f"{f.get('confidence', 0):.0%}",
        )

    console.print(table)
    console.print()
    console.rule("[bold yellow]DETAILED FINDINGS[/bold yellow]")

    for i, finding in enumerate(findings, 1):
        severity = finding.get("severity", "INFO")
        color = ("red" if severity == "CRITICAL" else "yellow" if severity == "HIGH"
                 else "magenta" if severity == "MEDIUM" else "cyan")
        details = (
            f"[bold]Category:[/bold] {finding.get('category')}\n"
            f"[bold]Status:[/bold] {finding.get('response_status')} (baseline: {finding.get('baseline_status')})\n"
            f"[bold]Description:[/bold] {finding.get('description', '')}\n\n[bold]Evidence:[/bold]\n"
        )
        for ev in finding.get("evidence", []):
            details += f"  • {ev}\n"
        remediation = REMEDIATION_MAP.get(finding.get("category", ""), "Review auth logic.")
        details += f"\n[bold green]Remediation:[/bold green]\n{remediation}"
        console.print(Panel(
            details,
            title=f"[{color}][{i}/{len(findings)}] {finding.get('mutation_name')} ({severity})[/{color}]",
            border_style=color, expand=False,
        ))
        console.print()


if __name__ == "__main__":
    main()
