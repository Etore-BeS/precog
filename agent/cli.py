from __future__ import annotations

from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from agent.core import PrecogAgent
from agent.settings import get_settings

app = typer.Typer(add_completion=False, no_args_is_help=True, help="Precog — authorized OSINT/recon agent")
console = Console()


@app.command()
def doctor() -> None:
    """Validate env, scope, providers, tools."""
    checks = PrecogAgent().doctor()
    console.print_json(data=checks)
    raise typer.Exit(0 if checks.get("ok") else 1)


@app.command()
def plan(
    objective: str = typer.Argument(...),
    target: Optional[str] = typer.Option(None, "--target", "-t"),
    active: bool = typer.Option(False, "--active"),
) -> None:
    """Create a gated plan (no execution)."""
    p = PrecogAgent().plan(objective, target=target, include_active=active)
    console.print(p.summary_text())
    console.print(f"\n[green]plan id:[/green] {p.id}")


@app.command("plan-run")
def plan_run(
    objective: str = typer.Argument(...),
    target: Optional[str] = typer.Option(None, "--target", "-t"),
    active: bool = typer.Option(False, "--active"),
    yes: bool = typer.Option(False, "--yes", "-y"),
) -> None:
    """Plan and run (requires --yes)."""
    agent = PrecogAgent()
    p = agent.plan(objective, target=target, include_active=active)
    console.print(p.summary_text())
    if not yes:
        console.print("[red]Refusing without --yes[/red]")
        raise typer.Exit(2)
    agent.approve(p.id)
    result = agent.run(p.id)
    console.print_json(
        data={"approved": result.approved, "report": result.report_path, "results": result.results}
    )


@app.command()
def tools() -> None:
    """List tools."""
    table = Table(title="Precog tools")
    for col in ("name", "category", "risk", "requires_confirm", "description"):
        table.add_column(col)
    for r in PrecogAgent().list_tools():
        table.add_row(r["name"], r["category"], r["risk"], r["requires_confirm"], r["description"])
    console.print(table)


@app.command()
def audit(limit: int = typer.Option(20, "--limit", "-n")) -> None:
    """Show recent audit events."""
    console.print_json(data=PrecogAgent().audit.list_recent(limit))


@app.command()
def report(plan_id: str = typer.Argument(...)) -> None:
    """Print report markdown."""
    path = get_settings().report_dir / f"report-{plan_id}.md"
    if not path.exists():
        console.print(f"[red]No report for {plan_id}[/red]")
        raise typer.Exit(1)
    console.print(path.read_text(encoding="utf-8"))


@app.command()
def telegram() -> None:
    """Start Telegram long-polling bot."""
    from agent.telegram.bot import run_bot

    run_bot()


def main() -> None:
    app()


if __name__ == "__main__":
    main()
