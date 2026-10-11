"""
Command-Line and Interactive Interface for AppSec Research Assistant.

Provides an interactive console interface to select audit suites, view findings,
explore the vulnerability knowledge base, and export reports.
"""

import sys
import argparse
from typing import List

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markdown import Markdown

from appsec_assistant.models import TargetConfig, VulnerabilityFinding, SeverityLevel
from appsec_assistant.engine import AuditEngine
from appsec_assistant.config import ScopeViolationError, ScopeGuard
from appsec_assistant.knowledge_base import VulnerabilityKnowledgeBase
from appsec_assistant.reporters.markdown_reporter import MarkdownReporter
from appsec_assistant.reporters.json_reporter import JSONReporter
from appsec_assistant.lab_server import LocalLabServer

console = Console()


def print_banner() -> None:
    banner = """
    ╔═══════════════════════════════════════════════════════════════╗
    ║                 AppSec Research Assistant                     ║
    ║       Modular Web Security Analysis for Defensive Study       ║
    ╚═══════════════════════════════════════════════════════════════╝
    """
    console.print(f"[bold cyan]{banner}[/bold cyan]")
    console.print("[dim]Safeguards: Strictly restricted to local lab environments (localhost / 127.0.0.1)[/dim]\n")


def display_findings_table(findings: List[VulnerabilityFinding]) -> None:
    if not findings:
        console.print("[green]✔ No security weaknesses found.[/green]")
        return

    table = Table(title="Security Assessment Findings (Phase 3 Controlled Workflow)", border_style="cyan")
    table.add_column("ID", style="dim", width=14)
    table.add_column("Tier", width=14)
    table.add_column("Severity", width=10)
    table.add_column("Confidence", width=12)
    table.add_column("Title", style="bold")
    table.add_column("Category", style="cyan")
    table.add_column("Reviewed", width=9)

    # Sort by severity descending, then confidence rank descending
    sorted_findings = sorted(findings, key=lambda x: (x.severity.rank, x.confidence.rank), reverse=True)

    for f in sorted_findings:
        sev_style = {
            SeverityLevel.CRITICAL: "[bold red]CRITICAL[/bold red]",
            SeverityLevel.HIGH: "[red]HIGH[/red]",
            SeverityLevel.MEDIUM: "[yellow]MEDIUM[/yellow]",
            SeverityLevel.LOW: "[green]LOW[/green]",
            SeverityLevel.INFO: "[blue]INFO[/blue]",
        }.get(f.severity, f.severity.value)

        conf_style = {
            "CONFIRMED": "[bold green]CONFIRMED[/bold green]",
            "HIGH": "[green]HIGH[/green]",
            "MEDIUM": "[yellow]MEDIUM[/yellow]",
            "LOW": "[dim]LOW[/dim]",
            "HEURISTIC": "[cyan]HEURISTIC[/cyan]",
        }.get(f.confidence.value, f.confidence.value)

        tier_style = {
            "OBSERVATION": "[dim cyan]Observation[/dim cyan]",
            "HEURISTIC_INDICATOR": "[cyan]Heuristic[/cyan]",
            "SUSPECTED_VULNERABILITY": "[yellow]Suspected[/yellow]",
            "INDEPENDENTLY_VERIFIED": "[bold green]Verified[/bold green]",
        }.get(getattr(f.finding_tier, "value", "SUSPECTED_VULNERABILITY"), "Suspected")

        hr_str = "[green]YES[/green]" if getattr(f, "human_reviewed", False) else "[dim]NO[/dim]"

        table.add_row(
            f.finding_id,
            tier_style,
            sev_style,
            conf_style,
            f.title,
            f.category,
            hr_str
        )

    console.print(table)


def display_finding_detail(f: VulnerabilityFinding) -> None:
    affected = ", ".join(f.affected_urls) if f.affected_urls else f.target_url
    tier_label = f.finding_tier.label if hasattr(f, "finding_tier") else "Suspected Vulnerability"
    hr_status = f"Approved by {f.reviewed_by} on {f.review_date}" if getattr(f, "human_reviewed", False) else "Pending Human Review"
    
    repro_formatted = "\n".join(f"- {s}" for s in getattr(f, "reproduction_steps", []))
    sanitized_ev = getattr(f, "sanitized_evidence", "") or f.evidence

    content = f"""
**Finding ID:** `{f.finding_id}`  
**Category:** {f.category}  
**Verification Tier:** **`{tier_label}`**  
**Severity:** {f.severity.value}  
**Confidence:** {f.confidence.value} ({f.confidence_explanation})  
**Target URL:** `{f.target_url}`  
**Affected Endpoints:** `{affected}`  
**Human Review Status:** `{hr_status}`  
**OWASP Category:** {f.owasp_category or 'N/A'}  
**CWE ID:** {f.cwe_id or 'N/A'}  

### Priority & Severity Rationale
{f.priority_rationale}

### Step-by-Step Reproduction Guide
{repro_formatted}

### Sanitized Evidence (Tokens & Credentials Redacted)
```text
{sanitized_ev.strip()}
```

### Remediation Guidance
{f.remediation}
"""
    console.print(Panel(Markdown(content), title=f"[bold]{f.title}[/bold]", border_style="cyan"))


def run_interactive_menu() -> None:
    engine: AuditEngine = None
    lab_server: LocalLabServer = None
    current_target = "http://127.0.0.1:5000"

    # Start built-in lab server by default for seamless out-of-the-box exploration
    lab_server = LocalLabServer(host="127.0.0.1", port=5000)
    lab_server.start()

    config = TargetConfig(base_url=current_target)
    engine = AuditEngine(config)

    while True:
        console.print("\n[bold yellow]── Main Navigation Menu ──[/bold yellow]")
        console.print(f"[dim]Current Target: {engine.config.base_url} (Findings: {len(engine.findings)})[/dim]")
        console.print("  [bold 1]1.[/bold 1] 🚀 Run Security Audit on Built-in Local Lab (port 5000)")
        console.print("  [bold 2]2.[/bold 2] 🧃 Run Security Audit on OWASP Juice Shop (http://localhost:3000)")
        console.print("  [bold 3]3.[/bold 3] 🎯 Audit a Custom Local Endpoint")
        console.print("  [bold 4]4.[/bold 4] 📋 View Discovered Findings & Evidence")
        console.print("  [bold 5]5.[/bold 5] 💾 Export Vulnerability Assessment Report (Markdown / JSON)")
        console.print("  [bold 6]6.[/bold 6] 📚 Explore Vulnerability Knowledge Base (IDOR, XSS, SQLi, Auth)")
        console.print("  [bold 7]7.[/bold 7] 🛡️  Test Scope Guard Safety Controls")
        console.print("  [bold 8]8.[/bold 8] 🚪 Exit")

        choice = console.input("\n[bold cyan]Select an option [1-8]: [/bold cyan]").strip()

        if choice == "1":
            console.print("\n[bold blue]Auditing Built-in Local Training Lab...[/bold blue]")
            endpoints = ["/", "/api/Users/1", "/rest/basket/1", "/admin", "/hardened"]
            engine.config.base_url = "http://127.0.0.1:5000"
            new_f = engine.run_suite(endpoints)
            console.print(f"[green]Audit completed. Discovered {len(new_f)} new finding(s).[/green]")
            display_findings_table(engine.findings)

        elif choice == "2":
            console.print("\n[bold blue]Configuring for OWASP Juice Shop (http://localhost:3000)...[/bold blue]")
            juice_config = TargetConfig(base_url="http://localhost:3000")
            juice_engine = AuditEngine(juice_config)
            juice_endpoints = ["/", "/api/Users/1", "/rest/basket/1", "/administration"]
            try:
                console.print("[dim]Connecting to Juice Shop... (Make sure Juice Shop is running on :3000)[/dim]")
                juice_engine.run_suite(juice_endpoints)
                for f in juice_engine.findings:
                    if f not in engine.findings:
                        engine._findings.append(f)
                display_findings_table(juice_engine.findings)
            except Exception as e:
                console.print(f"[red]Error contacting Juice Shop on port 3000: {e}[/red]")
                console.print("[yellow]Tip: Run Juice Shop via Docker: `docker run -d -p 3000:3000 bkimminich/juice-shop`[/yellow]")

        elif choice == "3":
            custom_url = console.input("[cyan]Enter local URL or relative path (e.g., http://localhost:5000/api/Users/2): [/cyan]").strip()
            if custom_url:
                try:
                    console.print(f"[dim]Auditing {custom_url}...[/dim]")
                    new_findings = engine.audit_endpoint(custom_url)
                    console.print(f"[green]Analysis complete. {len(new_findings)} finding(s) identified.[/green]")
                    display_findings_table(new_findings)
                except ScopeViolationError as sve:
                    console.print(f"[bold red]⛔ Safeguard Triggered:[/bold red] {sve}")
                except Exception as e:
                    console.print(f"[red]Request failed: {e}[/red]")

        elif choice == "4":
            if not engine.findings:
                console.print("[yellow]No findings recorded yet. Run an audit (Option 1 or 2) first.[/yellow]")
            else:
                display_findings_table(engine.findings)
                sub_choice = console.input("\nEnter Finding ID for deep-dive details (or press Enter to return): ").strip()
                if sub_choice:
                    target_finding = next((f for f in engine.findings if f.finding_id.lower() == sub_choice.lower()), None)
                    if target_finding:
                        display_finding_detail(target_finding)
                    else:
                        console.print(f"[red]Finding ID '{sub_choice}' not found.[/red]")

        elif choice == "5":
            if not engine.findings:
                console.print("[yellow]No findings to export. Run an audit first.[/yellow]")
                continue
            fmt = console.input("Choose format ([m]arkdown / [j]son) [default: m]: ").strip().lower()
            out_file = console.input("Output file path [default: security_report.md]: ").strip()
            if not out_file:
                out_file = "security_report.json" if fmt == "j" else "security_report.md"

            if fmt == "j":
                JSONReporter.save_to_file(engine.findings, engine.config.base_url, out_file)
            else:
                MarkdownReporter.save_to_file(engine.findings, engine.config.base_url, out_file)

            console.print(f"[bold green]✔ Report successfully exported to '{out_file}'[/bold green]")

        elif choice == "6":
            topics = VulnerabilityKnowledgeBase.get_all_topics()
            console.print("\n[bold cyan]Educational Vulnerability Encyclopedia:[/bold cyan]")
            for idx, t in enumerate(topics, start=1):
                g = VulnerabilityKnowledgeBase.get_guide(t)
                console.print(f"  {idx}. [bold]{g.title}[/bold] ({g.cwe_id})")
            t_choice = console.input("\nEnter topic number or name to read guide (or press Enter to return): ").strip()
            if t_choice:
                topic_key = None
                if t_choice.isdigit() and 1 <= int(t_choice) <= len(topics):
                    topic_key = topics[int(t_choice) - 1]
                else:
                    topic_key = t_choice
                guide = VulnerabilityKnowledgeBase.get_guide(topic_key)
                if guide:
                    content = f"""
# {guide.title}
**Category:** {guide.owasp_category} | **CWE:** {guide.cwe_id}

## 1. Summary
{guide.summary}

## 2. Core Mechanism & How it Works
{guide.how_it_works}

## 3. Detection Methodology (Educational/Defensive)
{guide.detection_methodology}

## 4. Defensive Remediation & Mitigations
{guide.defensive_remediation}

## 5. Secure Code Example
```python
{guide.code_example}
```
"""
                    console.print(Panel(Markdown(content), title=f"[bold green]{guide.title}[/bold green]", border_style="green"))
                else:
                    console.print(f"[red]Topic '{t_choice}' not found.[/red]")

        elif choice == "7":
            console.print("\n[bold cyan]Testing Scope Guard Safeguards:[/bold cyan]")
            guard = ScopeGuard()
            test_targets = [
                ("http://localhost:5000", True),
                ("http://127.0.0.1:3000", True),
                ("https://google.com", False),
                ("https://facebook.com", False),
                ("http://192.168.1.1", False),
            ]
            for target_url, should_permit in test_targets:
                try:
                    guard.validate_url(target_url)
                    result = "[green]ALLOWED (In Scope)[/green]"
                except ScopeViolationError:
                    result = "[red]BLOCKED (Out of Scope)[/red]"
                console.print(f"  • Target `{target_url}`: {result}")

        elif choice == "8":
            console.print("[dim]Stopping background services and exiting...[/dim]")
            if lab_server:
                lab_server.stop()
            console.print("[green]Goodbye![/green]")
            break


from appsec_assistant.policy import ProgramPolicyManager, PolicyVerificationError


def main() -> None:
    parser = argparse.ArgumentParser(
        description="AppSec Research Assistant: Web Security Analysis for Defensive Study"
    )
    parser.add_argument("--target", help="Target URL (must be local, e.g. http://localhost:3000)")
    parser.add_argument("--export-md", help="Export findings to Markdown file")
    parser.add_argument("--export-json", help="Export findings to JSON file")
    parser.add_argument("--lab", action="store_true", help="Spin up local mock lab and run audit")
    parser.add_argument("--guide", help="Print educational guide for a vulnerability (idor, xss, sqli, auth, broken_access_control)")
    parser.add_argument("--policies", action="store_true", help="List configured VDP program policies and verification status")
    parser.add_argument("--verify-policy", help="Manually verify and enable a program policy by ID")
    parser.add_argument("--reviewer", default="Security Researcher", help="Reviewer name for policy verification or finding sign-off")
    parser.add_argument("--notes", default="Manual scope verification completed.", help="Verification notes")
    parser.add_argument("--exercises", action="store_true", help="List available guided security exercises")
    parser.add_argument("--run-exercise", help="Execute a specific guided exercise by ID (e.g. EX-AC-01, EX-IDOR-01)")
    parser.add_argument("--review-all", action="store_true", help="Mark all generated findings as human-reviewed before export")

    args = parser.parse_args()

    print_banner()

    policy_mgr = ProgramPolicyManager()

    # If --policies flag specified
    if args.policies:
        console.print("[bold cyan]Configured Vulnerability Disclosure Program Policies:[/bold cyan]")
        p_table = Table(border_style="cyan")
        p_table.add_column("Program ID", style="bold")
        p_table.add_column("Organization")
        p_table.add_column("Verified", width=10)
        p_table.add_column("Enabled", width=10)
        p_table.add_column("Authorized Scope Assets")
        for p in policy_mgr.list_policies():
            v_str = "[green]YES[/green]" if p.is_verified else "[red]NO[/red]"
            e_str = "[green]ENABLED[/green]" if p.is_enabled else "[yellow]DISABLED[/yellow]"
            p_table.add_row(p.program_id, p.organization, v_str, e_str, ", ".join(p.authorized_assets))
        console.print(p_table)
        sys.exit(0)

    # If --verify-policy flag specified
    if args.verify_policy:
        try:
            policy_mgr.verify_policy(args.verify_policy, reviewer_name=args.reviewer, verification_notes=args.notes)
            policy_mgr.enable_policy(args.verify_policy)
            console.print(f"[bold green]✔ Successfully verified and enabled policy '{args.verify_policy}' by {args.reviewer}.[/bold green]")
        except PolicyVerificationError as pve:
            console.print(f"[bold red]✖ Policy Verification Failed: {pve}[/bold red]")
            sys.exit(1)
        sys.exit(0)

    # If --exercises flag specified
    if args.exercises:
        console.print("[bold cyan]Guided Educational Security Exercises:[/bold cyan]")
        e_table = Table(border_style="cyan")
        e_table.add_column("Exercise ID", style="bold", width=12)
        e_table.add_column("Category", width=22)
        e_table.add_column("Target Endpoint", width=20)
        e_table.add_column("Expected Tier", width=22)
        e_table.add_column("Title")
        for ex in VulnerabilityKnowledgeBase.list_exercises():
            e_table.add_row(ex.exercise_id, ex.category, ex.target_endpoint, ex.expected_tier.label, ex.title)
        console.print(e_table)
        sys.exit(0)

    # If --run-exercise flag specified
    if args.run_exercise:
        exercise = VulnerabilityKnowledgeBase.get_exercise(args.run_exercise)
        if not exercise:
            console.print(f"[red]Exercise '{args.run_exercise}' not found. Use --exercises to list available exercises.[/red]")
            sys.exit(1)

        lab_server = LocalLabServer(port=5000)
        lab_server.start()
        console.print(f"[green]✔ Started practice lab on http://127.0.0.1:5000[/green]")
        console.print(f"[cyan]Executing Exercise: {exercise.title}[/cyan]")
        console.print(f"[dim]Objective: {exercise.objective}[/dim]\n")

        config = TargetConfig(base_url="http://127.0.0.1:5000")
        engine = AuditEngine(config, policy_manager=policy_mgr)
        findings = engine.audit_exercise(exercise)

        display_findings_table(findings)
        console.print(f"\n[bold green]Verification Criteria:[/bold green] {exercise.verification_criteria}")
        console.print(f"[bold cyan]Remediation Summary:[/bold cyan] {exercise.remediation_summary}")

        lab_server.stop()
        sys.exit(0)

    # If guide flag specified
    if args.guide:
        guide = VulnerabilityKnowledgeBase.get_guide(args.guide)
        if not guide:
            console.print(f"[red]Unknown topic '{args.guide}'. Available: {VulnerabilityKnowledgeBase.get_all_topics()}[/red]")
            sys.exit(1)
        console.print(Panel(Markdown(f"# {guide.title}\n{guide.summary}\n\n### Defensive Remediation\n{guide.defensive_remediation}\n\n```python\n{guide.code_example}\n```")))
        sys.exit(0)

    # If scripted execution via flags
    if args.lab or args.target:
        lab_server = None
        target_url = args.target or "http://127.0.0.1:5000"
        if args.lab:
            lab_server = LocalLabServer(port=5000)
            lab_server.start()
            console.print("[green]✔ Started built-in training lab on http://127.0.0.1:5000[/green]")

        config = TargetConfig(base_url=target_url)
        engine = AuditEngine(config, policy_manager=policy_mgr)
        console.print(f"[cyan]Auditing target: {target_url}...[/cyan]")

        endpoints = ["/", "/api/Users/1", "/rest/basket/1", "/admin", "/hardened"]
        engine.run_suite(endpoints)

        if args.review_all:
            import datetime
            now_dt = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
            for f in engine.findings:
                f.human_reviewed = True
                f.reviewed_by = args.reviewer
                f.review_date = now_dt
                f.review_notes = "Verified through CLI regression audit."
            console.print(f"[green]✔ Marked all findings as Human-Reviewed by {args.reviewer}[/green]")

        display_findings_table(engine.findings)

        if args.export_md:
            MarkdownReporter.save_to_file(engine.findings, target_url, args.export_md)
            console.print(f"[green]✔ Exported Markdown report to {args.export_md}[/green]")

        if args.export_json:
            JSONReporter.save_to_file(engine.findings, target_url, args.export_json)
            console.print(f"[green]✔ Exported JSON report to {args.export_json}[/green]")

        if lab_server:
            lab_server.stop()
        sys.exit(0)

    # Otherwise run full interactive menu
    run_interactive_menu()


if __name__ == "__main__":
    main()
