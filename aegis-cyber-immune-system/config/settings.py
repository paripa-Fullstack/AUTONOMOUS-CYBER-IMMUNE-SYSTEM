"""Application settings using Pydantic Settings."""

from functools import lru_cache
from typing import List

from pydantic_settings import BaseSettings, SettingsConfigDict


class BaseConfig(BaseSettings):
    """Base configuration class."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )


class DatabaseSettings(BaseConfig):
    """Database configuration settings."""

    # Neo4j
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "password"

    # Elasticsearch
    elasticsearch_url: str = "http://localhost:9200"

    # Redis
    redis_url: str = "redis://localhost:6379"


class KafkaSettings(BaseConfig):
    """Kafka messaging configuration."""

    kafka_bootstrap_servers: str = "localhost:9092"
    kafka_topic_telemetry: str = "telemetry"
    kafka_topic_alerts: str = "alerts"
    kafka_topic_logs: str = "logs"


class SecuritySettings(BaseConfig):
    """Security configuration settings."""

    secret_key: str = "your-secret-key-here"
    jwt_secret_key: str = "your-jwt-secret"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 30


class AppConfig(BaseConfig):
    """Application configuration settings."""

    app_name: str = "AEGIS"
    app_version: str = "1.0.0"
    debug: bool = False
    environment: str = "development"

    # API settings
    api_v1_prefix: str = "/api/v1"
    cors_origins: List[str] = ["*"]
    allowed_hosts: List[str] = ["*"]


class Settings(BaseConfig):
    """Main settings class combining all configurations."""

    # Application
    app_name: str = "AEGIS"
    app_version: str = "1.0.0"
    debug: bool = False
    environment: str = "development"
    secret_key: str = "your-secret-key-here"

    # API settings
    api_v1_prefix: str = "/api/v1"
    cors_origins: List[str] = ["*"]
    allowed_hosts: List[str] = ["*"]

    # Neo4j
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "password"

    # Elasticsearch
    elasticsearch_url: str = "http://localhost:9200"

    # Redis
    redis_url: str = "redis://localhost:6379"

    # Kafka
    kafka_bootstrap_servers: str = "localhost:9092"
    kafka_topic_telemetry: str = "telemetry"
    kafka_topic_alerts: str = "alerts"
    kafka_topic_logs: str = "logs"

    # Security
    jwt_secret_key: str = "your-jwt-secret"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 30

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance.

    Returns:
        Settings: Application settings instance.
    """
    return Settings()


settings = get_settings()
