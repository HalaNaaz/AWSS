import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any, Dict


class JSONFormatter(logging.Formatter):
    """Structured JSON formatter with ISO timestamps and correlation ID support."""

    def format(self, record: logging.LogRecord) -> str:
        log_record: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "name": record.name,
            "message": record.getMessage(),
        }
        if hasattr(record, "correlation_id"):
            log_record["correlation_id"] = record.correlation_id
        if hasattr(record, "scan_id"):
            log_record["scan_id"] = str(record.scan_id)
        if record.exc_info:
            log_record["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_record)


def setup_logging(log_level: str = "INFO") -> logging.Logger:
    """Configures root application logging."""
    logger = logging.getLogger("ashlynx")
    logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JSONFormatter())

    # Avoid duplicate handlers if re-called
    if not logger.handlers:
        logger.addHandler(handler)

    return logger


logger = setup_logging()
