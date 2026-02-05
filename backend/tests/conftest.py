"""
Pytest configuration and fixtures
"""
import os
import pytest
import asyncio
from typing import Generator, AsyncGenerator

# Set test environment
os.environ["ENVIRONMENT"] = "test"
os.environ["DATABASE_HOST"] = os.environ.get("DATABASE_HOST", "localhost")
os.environ["DATABASE_PORT"] = os.environ.get("DATABASE_PORT", "5432")
os.environ["DATABASE_USER"] = os.environ.get("DATABASE_USER", "test")
os.environ["DATABASE_PASSWORD"] = os.environ.get("DATABASE_PASSWORD", "test")
os.environ["DATABASE_NAME"] = os.environ.get("DATABASE_NAME", "securesight_test")
os.environ["ELASTICSEARCH_HOST"] = os.environ.get("ELASTICSEARCH_HOST", "localhost")
os.environ["ELASTICSEARCH_PORT"] = os.environ.get("ELASTICSEARCH_PORT", "9200")
os.environ["REDIS_HOST"] = os.environ.get("REDIS_HOST", "localhost")
os.environ["REDIS_PORT"] = os.environ.get("REDIS_PORT", "6379")
os.environ["SECRET_KEY"] = "test-secret-key"
os.environ["API_KEY"] = "test-api-key"


@pytest.fixture(scope="session")
def event_loop() -> Generator:
    """Create event loop for async tests"""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
async def async_client() -> AsyncGenerator:
    """Create async test client"""
    from httpx import AsyncClient
    from app.main import app
    
    async with AsyncClient(app=app, base_url="http://test") as client:
        yield client


@pytest.fixture
def api_key_headers():
    """Headers with API key for authenticated requests"""
    return {"X-API-Key": os.environ["API_KEY"]}


@pytest.fixture
def sample_log():
    """Sample log event for testing"""
    return {
        "timestamp": "2024-01-15T10:30:00Z",
        "source": "linux_auth",
        "host": "test-server",
        "message": "Failed password for root from 192.168.1.100 port 22 ssh2",
        "severity": "medium",
        "event_type": "auth_failure",
    }


@pytest.fixture
def sample_rule():
    """Sample detection rule for testing"""
    return {
        "name": "Test Brute Force Rule",
        "description": "Detects multiple failed login attempts",
        "rule_type": "threshold",
        "severity": "high",
        "conditions": {
            "field": "event_type",
            "operator": "equals",
            "value": "auth_failure"
        },
        "threshold_count": 5,
        "threshold_window": 300,
        "enabled": True,
    }
