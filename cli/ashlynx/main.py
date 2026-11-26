import typer
from cli.ashlynx.commands.scan import run_scan
from cli.ashlynx.commands.report import report_app
from cli.ashlynx.commands.recon import run_recon
from cli.ashlynx.commands.attack_surface import run_attack_surface
from cli.ashlynx.commands.findings import findings_app
from cli.ashlynx.commands.analytics import analytics_app
from cli.ashlynx.commands.targets import targets_app
from cli.ashlynx.output.formatter import TerminalFormatter

app = typer.Typer(
    name="ashlynx",
    help="Ashlynx WebSec Scanner - Enterprise DAST & Automated Vulnerability Assessment CLI",
    add_completion=False
)

app.command("scan", help="Trigger and monitor web application security scans.")(run_scan)
app.command("recon", help="Execute attack surface reconnaissance and bounded HTTP crawling.")(run_recon)
app.command("attack-surface", help="Discover attack surface, classify parameters, map APIs, and build intelligence graph.")(run_attack_surface)
app.command("surface", hidden=True)(run_attack_surface)
app.add_typer(report_app, name="report")
app.add_typer(findings_app, name="findings")
app.add_typer(analytics_app, name="analytics")
app.add_typer(targets_app, name="targets")


@app.command("version")
def version():
    """Display scanner version and architecture details."""
    TerminalFormatter.print_banner("Ashlynx WebSec Scanner", "2.0.0-dev")


if __name__ == "__main__":
    app()
