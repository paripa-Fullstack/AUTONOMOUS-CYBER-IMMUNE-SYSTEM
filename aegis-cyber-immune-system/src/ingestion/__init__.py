"""Data ingestion module for AEGIS."""

from src.ingestion.kafka_consumer import KafkaConsumer
from src.ingestion.parsers import NetFlowParser, SyslogParser, CEFParser, STIXParser
from src.ingestion.validators import SchemaValidator

__all__ = [
    "KafkaConsumer",
    "NetFlowParser",
    "SyslogParser",
    "CEFParser",
    "STIXParser",
    "SchemaValidator",
]
