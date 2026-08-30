"""Async Kafka consumer for AEGIS data ingestion."""

import asyncio
import json
import logging
from typing import Callable, Dict, Any, Optional, List

from aiokafka import AIOKafkaConsumer
from aiokafka.errors import KafkaError

from config.settings import settings
from src.core.exceptions import IngestionError
from src.core.utils import retry_async

logger = logging.getLogger(__name__)


class KafkaConsumer:
    """Asynchronous Kafka consumer for ingesting security telemetry.

    Subscribes to multiple topics (telemetry, logs, alerts) and processes
    incoming messages with error handling and retry logic.
    """

    def __init__(
        self,
        bootstrap_servers: Optional[str] = None,
        topics: Optional[List[str]] = None,
        group_id: str = "aegis-consumer-group",
        auto_commit: bool = True,
    ):
        """Initialize Kafka consumer.

        Args:
            bootstrap_servers: Kafka broker addresses.
            topics: List of topics to subscribe to.
            group_id: Consumer group ID.
            auto_commit: Enable automatic offset commit.
        """
        self.bootstrap_servers = (
            bootstrap_servers or settings.kafka_bootstrap_servers
        ).split(",")
        self.topics = topics or [
            settings.kafka_topic_telemetry,
            settings.kafka_topic_logs,
            settings.kafka_topic_alerts,
        ]
        self.group_id = group_id
        self.auto_commit = auto_commit
        self.consumer: Optional[AIOKafkaConsumer] = None
        self.message_handlers: Dict[str, Callable] = {}
        self.running = False

    def register_handler(self, topic: str, handler: Callable) -> None:
        """Register a message handler for a specific topic.

        Args:
            topic: Kafka topic name.
            handler: Async function to handle messages.
        """
        self.message_handlers[topic] = handler
        logger.info(f"Registered handler for topic: {topic}")

    @retry_async(max_retries=3, delay=1.0, backoff=2.0)
    async def start(self) -> None:
        """Start the Kafka consumer.

        Raises:
            IngestionError: If consumer fails to start.
        """
        try:
            self.consumer = AIOKafkaConsumer(
                *self.topics,
                bootstrap_servers=",".join(self.bootstrap_servers),
                group_id=self.group_id,
                auto_offset_reset="earliest",
                enable_auto_commit=self.auto_commit,
                value_deserializer=lambda v: json.loads(v.decode("utf-8")),
            )
            await self.consumer.start()
            self.running = True
            logger.info(f"Kafka consumer started, subscribed to topics: {self.topics}")

        except Exception as e:
            logger.error(f"Failed to start Kafka consumer: {e}")
            raise IngestionError(f"Failed to start Kafka consumer: {e}", source="kafka")

    async def stop(self) -> None:
        """Stop the Kafka consumer gracefully."""
        self.running = False
        if self.consumer:
            await self.consumer.stop()
            logger.info("Kafka consumer stopped")

    async def consume(self) -> None:
        """Consume messages from Kafka topics.

        Processes messages using registered handlers.
        Runs until stopped or an unrecoverable error occurs.
        """
        if not self.consumer:
            raise IngestionError("Consumer not started", source="kafka")

        logger.info("Starting message consumption...")

        try:
            async for msg in self.consumer:
                if not self.running:
                    break

                topic = msg.topic
                value = msg.value
                partition = msg.partition
                offset = msg.offset

                logger.debug(
                    f"Received message from {topic}[{partition}]@{offset}: {value}"
                )

                # Process message with appropriate handler
                handler = self.message_handlers.get(topic)
                if handler:
                    try:
                        await handler(value)
                    except Exception as e:
                        logger.error(f"Error processing message from {topic}: {e}")
                else:
                    logger.warning(f"No handler registered for topic: {topic}")

        except KafkaError as e:
            logger.error(f"Kafka error during consumption: {e}")
            raise IngestionError(f"Kafka consumption error: {e}", source="kafka")
        except Exception as e:
            logger.error(f"Unexpected error during consumption: {e}")
            raise

    async def consume_batch(self, max_messages: int = 100, timeout_ms: int = 1000) -> List[Dict[str, Any]]:
        """Consume a batch of messages.

        Args:
            max_messages: Maximum number of messages to fetch.
            timeout_ms: Timeout in milliseconds.

        Returns:
            List of message values.
        """
        if not self.consumer:
            raise IngestionError("Consumer not started", source="kafka")

        messages = []
        try:
            async for msg in self.consumer:
                messages.append(msg.value)
                if len(messages) >= max_messages:
                    break
        except Exception as e:
            logger.error(f"Error consuming batch: {e}")

        return messages
