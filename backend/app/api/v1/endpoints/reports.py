from uuid import UUID
from fastapi import APIRouter, HTTPException, Query, Response
from shared.schemas.report import ReportFormat
from backend.app.scanner.orchestration.scan_orchestrator import scan_registry
from backend.app.reporting.manager import ReportManager

router = APIRouter()
report_manager = ReportManager()


@router.get("/{scan_id}")
async def get_report_by_id(
    scan_id: UUID,
    format: ReportFormat = Query(ReportFormat.JSON, description="Output format: json, html, markdown"),
    download: bool = Query(False, description="Whether to trigger file download attachment"),
) -> Response:
    """Retrieves unified scan report in requested format (JSON, HTML, Markdown)."""
    report = scan_registry.get_report(scan_id)
    if not report:
        raise HTTPException(
            status_code=404,
            detail=f"Report for scan '{scan_id}' not found. Verify scan has completed."
        )

    try:
        content = report_manager.generate_report(report, format)
        media_type = report_manager.get_content_type(format)
        headers = {}
        if download:
            ext_map = {
                ReportFormat.JSON: "json",
                ReportFormat.HTML: "html",
                ReportFormat.MARKDOWN: "md",
                ReportFormat.SARIF: "sarif",
            }
            ext = ext_map.get(format, "txt")
            headers["Content-Disposition"] = f'attachment; filename="ashlynx_report_{scan_id}.{ext}"'

        return Response(content=content, media_type=media_type, headers=headers)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))
