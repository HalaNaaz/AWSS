from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class CLIConfig(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ASHLYNX_CLI_", extra="ignore")

    API_URL: str = "http://localhost:8000/api/v1"
    API_TOKEN: Optional[str] = None
    TIMEOUT_SECONDS: float = 30.0
    DEFAULT_PROFILE: str = "QUICK_ASSESSMENT"
    COLOR_OUTPUT: bool = True


cli_config = CLIConfig()
