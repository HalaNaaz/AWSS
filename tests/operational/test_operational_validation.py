"""
Pytest integration for Phase 3 & Phase 4 Operational Validation.
"""

import os
import sys
from pathlib import Path
import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tests.operational.run_operational_validation import OperationalValidator


@pytest.mark.asyncio
async def test_operational_validation_suite():
    os.environ["ALLOW_PRIVATE_IPS"] = "true"
    validator = OperationalValidator()
    await validator.run_all()
