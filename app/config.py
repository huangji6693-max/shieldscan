from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    shieldscan_host: str = "0.0.0.0"
    shieldscan_port: int = 8000
    shieldscan_database_url: str = "sqlite:///./shieldscan.db"

    zap_api_url: str = "http://127.0.0.1:8081"
    zap_api_key: str = "changeme"
    scanner_mode: str = "zap"  # zap | builtin

    anthropic_api_key: str = ""
    ai_model: str = "claude-sonnet-4-20250514"

    scan_spider_timeout: int = 300
    scan_ajax_spider_timeout: int = 120
    scan_passive_timeout: int = 90
    scan_active_timeout: int = 600
    max_scan_duration: int = 900
    zap_scan_policy: str = "standard"  # quick | standard | deep
    crawl_max_pages: int = 80
    crawl_max_depth: int = 4
    fuzz_max_params: int = 45


@lru_cache
def get_settings() -> Settings:
    return Settings()
