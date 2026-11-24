import typer
from cli.ashlynx.commands.scan import run_scan
from cli.ashlynx.commands.report import report_app
from cli.ashlynx.commands.recon import run_recon
from cli.ashlynx.output.formatter import TerminalFormatter

app = typer.Typer(
    name="ashlynx",
    help="Ashlynx WebSec Scanner - Enterprise DAST & Automated Vulnerability Assessment CLI",
    add_completion=False
)

app.command("scan", help="Trigger and monitor web application security scans.")(run_scan)
app.command("recon", help="Execute attack surface reconnaissance and bounded HTTP crawling.")(run_recon)
app.add_typer(report_app, name="report")


@app.command("version")
def version():
    """Display scanner version and architecture details."""
    TerminalFormatter.print_banner("Ashlynx WebSec Scanner", "2.0.0-dev")


if __name__ == "__main__":
    app()
