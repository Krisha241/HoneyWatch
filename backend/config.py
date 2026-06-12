from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Database
    db_user: str = "postgres"
    db_password: str = "password"
    db_name: str = "honeywatch"
    db_host: str = "db"
    db_port: int = 5432

    # App
    environment: str = "development"

    # Honeypot ports
    ssh_trap_port: int = 2222
    http_trap_port: int = 8080
    ftp_trap_port: int = 2121

    @property
    def database_url(self) -> str:
        return (
            f"postgresql://{self.db_user}:{self.db_password}"
            f"@{self.db_host}:{self.db_port}/{self.db_name}"
        )

    @property
    def is_development(self) -> bool:
        return self.environment == "development"

    model_config = {"env_file": ".env", "case_sensitive": False}


settings = Settings()