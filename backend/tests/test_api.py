"""
SecureSight Backend Tests
"""
import pytest


@pytest.fixture
def test_client():
    """Create a test client"""
    from httpx import AsyncClient
    from app.main import app
    
    return AsyncClient(app=app, base_url="http://test")


class TestHealth:
    """Health endpoint tests"""
    
    @pytest.mark.asyncio
    async def test_health_check(self, test_client):
        """Test basic health check"""
        async with test_client as client:
            response = await client.get("/api/v1/health")
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "healthy"
    
    @pytest.mark.asyncio
    async def test_liveness(self, test_client):
        """Test liveness probe"""
        async with test_client as client:
            response = await client.get("/api/v1/health/live")
            assert response.status_code == 200


class TestAuth:
    """Authentication tests"""
    
    @pytest.mark.asyncio
    async def test_login_invalid_credentials(self, test_client):
        """Test login with invalid credentials"""
        async with test_client as client:
            response = await client.post(
                "/api/v1/auth/login",
                data={
                    "username": "invalid@test.com",
                    "password": "wrongpassword"
                }
            )
            assert response.status_code == 401


class TestLogs:
    """Log ingestion tests"""
    
    @pytest.mark.asyncio
    async def test_ingest_without_api_key(self, test_client):
        """Test log ingestion without API key"""
        async with test_client as client:
            response = await client.post(
                "/api/v1/logs/ingest",
                json={
                    "timestamp": "2024-01-01T00:00:00Z",
                    "source": "test",
                    "host": "test-host",
                    "message": "Test message"
                }
            )
            # Should fail without API key
            assert response.status_code in [401, 403]
