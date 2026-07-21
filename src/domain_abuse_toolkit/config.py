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
    max_export_bytes: int = Field(default=100 * 1024 * 1024, ge=1024 * 1024)
    public_base_url: str = "http://127.0.0.1:8080"

    enable_network_collection: bool = False
    dns_timeout_seconds: float = Field(default=2.0, ge=0.2, le=10)
    dns_lifetime_seconds: float = Field(default=5.0, ge=0.5, le=30)
    max_dns_records_per_type: int = Field(default=50, ge=1, le=200)
    max_pending_collection_jobs: int = Field(default=10, ge=1, le=100)
    http_connect_timeout_seconds: float = Field(default=5.0, ge=0.5, le=30)
    http_read_timeout_seconds: float = Field(default=5.0, ge=0.5, le=30)
    http_total_timeout_seconds: float = Field(default=30.0, ge=2, le=120)
    http_max_redirects: int = Field(default=5, ge=0, le=10)
    http_max_body_bytes: int = Field(default=256 * 1024, ge=1024, le=1024 * 1024)
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
