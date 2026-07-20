from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration with all side-effecting capabilities disabled by default."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="DAT_",
        case_sensitive=False,
        extra="ignore",
    )

    environment: str = "development"
    host: str = "127.0.0.1"
    port: int = Field(default=8080, ge=1, le=65535)
    data_dir: Path = Path("./case-data")
    public_base_url: str = "http://127.0.0.1:8080"

    enable_network_collection: bool = False
    enable_screenshots: bool = False
    enable_external_apis: bool = False
    enable_llm: bool = False
    llm_provider: str = "disabled"
    llm_base_url: str = ""
    llm_api_key: str = ""
    llm_model: str = ""

    microsoft_graph_enabled: bool = False
    microsoft_tenant_id: str = ""
    microsoft_client_id: str = ""


@lru_cache
def get_settings() -> Settings:
    return Settings()

