from typing import Optional
from uuid import UUID

import httpx
import typer
from rich.console import Console
from rich.table import Table

from backend.app.api.v1.endpoints.targets import (
    TargetCreateRequest,
    target_registry,
)

targets_app = typer.Typer(
    help="Manage authorized target applications and ScopeGate boundary definitions."
)
console = Console()


@targets_app.command("list", help="List registered authorized targets.")
def targets_list_cmd(
    api_url: Optional[str] = typer.Option(
        None, "--api-url", help="Optional running API URL (e.g. http://127.0.0.1:8000/api/v1)"
    ),
    format_out: str = typer.Option("table", "--format", "-f", help="Output format: table or json"),
) -> None:
    if api_url:
        try:
            resp = httpx.get(f"{api_url.rstrip('/')}/targets/", timeout=10.0)
            resp.raise_for_status()
            items = resp.json().get("data", [])
        except Exception as exc:
            console.print(f"[bold red][!] Failed to fetch targets:[/bold red] {exc}")
            raise typer.Exit(code=1)
    else:
        items = [t.model_dump(mode="json") for t in target_registry.list_targets()]

    if format_out.lower() == "json":
        import json

        typer.echo(json.dumps(items, indent=2))
        return

    table = Table(title="Ashlynx Authorized Targets", border_style="cyan")
    table.add_column("ID", style="dim")
    table.add_column("Name", style="bold white")
    table.add_column("Base URL", style="cyan")
    table.add_column("Verified", justify="center")
    for item in items:
        table.add_row(
            str(item.get("id", "")),
            str(item.get("name", "")),
            str(item.get("base_url", "")),
            "YES" if item.get("verified") else "NO",
        )
    console.print(table)


@targets_app.command("add", help="Register a new authorized target.")
def targets_add_cmd(
    name: str = typer.Option(..., "--name", "-n", help="Human-readable target name"),
    url: str = typer.Option(..., "--url", "-u", help="Base URL (http:// or https://)"),
    description: Optional[str] = typer.Option(None, "--description", "-d", help="Scope notes"),
    criticality: float = typer.Option(3.0, "--criticality", "-c", help="Asset criticality (0.1-5.0)"),
    api_url: Optional[str] = typer.Option(
        None, "--api-url", help="Optional running API URL (e.g. http://127.0.0.1:8000/api/v1)"
    ),
) -> None:
    try:
        req = TargetCreateRequest(
            name=name,
            base_url=url,
            description=description,
            asset_criticality=criticality,
        )
    except Exception as exc:
        console.print(f"[bold red][!] Target validation failed:[/bold red] {exc}")
        raise typer.Exit(code=1)

    if api_url:
        try:
            resp = httpx.post(
                f"{api_url.rstrip('/')}/targets/",
                json=req.model_dump(mode="json"),
                timeout=10.0,
            )
            resp.raise_for_status()
            created = resp.json()["data"]
            console.print(f"[bold green][+] Registered target {created['id']} ({created['base_url']})[/bold green]")
        except Exception as exc:
            console.print(f"[bold red][!] Failed to register target via API:[/bold red] {exc}")
            raise typer.Exit(code=1)
    else:
        created = target_registry.create_target(req)
        console.print(f"[bold green][+] Registered target {created.id} ({created.base_url})[/bold green]")


@targets_app.command("delete", help="Delete a registered target by UUID.")
def targets_delete_cmd(
    target_id: UUID = typer.Argument(..., help="Target UUID to remove"),
    api_url: Optional[str] = typer.Option(
        None, "--api-url", help="Optional running API URL (e.g. http://127.0.0.1:8000/api/v1)"
    ),
) -> None:
    if api_url:
        try:
            resp = httpx.delete(f"{api_url.rstrip('/')}/targets/{target_id}", timeout=10.0)
            resp.raise_for_status()
            console.print(f"[bold green][+] Deleted target {target_id}[/bold green]")
        except Exception as exc:
            console.print(f"[bold red][!] Failed to delete target via API:[/bold red] {exc}")
            raise typer.Exit(code=1)
    else:
        if not target_registry.delete_target(target_id):
            console.print(f"[bold red][!] Target '{target_id}' not found.[/bold red]")
            raise typer.Exit(code=1)
        console.print(f"[bold green][+] Deleted target {target_id}[/bold green]")
