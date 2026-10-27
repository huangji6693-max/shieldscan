from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict

FUZZ_BUDGET_PROFILES: dict[str, dict[str, int]] = {
    "quick": {
        "max_params": 15,
        "max_pages": 25,
        "max_depth": 2,
    },
    "standard": {
        "max_params": 45,
        "max_pages": 80,
        "max_depth": 4,
    },
    "deep": {
        "max_params": 80,
        "max_pages": 120,
        "max_depth": 5,
    },
}


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
    scan_active_timeout: int = 600
    max_scan_duration: int = 900
    fuzz_profile: str = "standard"  # quick | standard | deep
    crawl_max_pages: int = 80
    crawl_max_depth: int = 4
    fuzz_max_params: int = 45

    def get_fuzz_budget(self, profile: str | None = None) -> dict[str, int]:
        """Return parameter fuzz and crawl budgets for the selected profile."""
        selected = (profile or self.fuzz_profile or "standard").strip().lower()
        base = dict(FUZZ_BUDGET_PROFILES.get(selected, FUZZ_BUDGET_PROFILES["standard"]))
        if selected == "standard":
            base["max_params"] = self.fuzz_max_params
            base["max_pages"] = self.crawl_max_pages
            base["max_depth"] = self.crawl_max_depth
        return base


@lru_cache
def get_settings() -> Settings:
    return Settings()
