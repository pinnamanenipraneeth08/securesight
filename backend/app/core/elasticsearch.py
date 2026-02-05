"""
SecureSight - Elasticsearch Configuration
"""

from typing import Optional, TYPE_CHECKING
import structlog

from app.core.config import settings

if TYPE_CHECKING:
    from elasticsearch import AsyncElasticsearch as AsyncElasticsearchType

logger = structlog.get_logger()

# Global Elasticsearch client
es_client: Optional["AsyncElasticsearchType"] = None


def get_elasticsearch() -> "AsyncElasticsearchType":
    """Get Elasticsearch client instance"""
    from elasticsearch import AsyncElasticsearch
    
    global es_client
    if es_client is None:
        es_client = AsyncElasticsearch(
            hosts=[settings.ELASTICSEARCH_URL],
            basic_auth=(settings.ELASTICSEARCH_USER, settings.ELASTICSEARCH_PASSWORD),
            verify_certs=False,
            ssl_show_warn=False,
        )
    return es_client


# Alias for worker compatibility
async def get_es_client() -> "AsyncElasticsearchType":
    """Async getter for Elasticsearch client (worker compatibility)"""
    return get_elasticsearch()


async def init_elasticsearch():
    """Initialize Elasticsearch and create index templates"""
    client = get_elasticsearch()
    
    # Check connection
    try:
        info = await client.info()
        logger.info("Elasticsearch connected", version=info["version"]["number"])
    except Exception as e:
        logger.error("Elasticsearch connection failed", error=str(e))
        return
    
    # Create index template for logs
    log_template = {
        "index_patterns": [f"{settings.ELASTICSEARCH_INDEX_PREFIX}-logs-*"],
        "template": {
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0,
                "index.refresh_interval": "5s",
            },
            "mappings": {
                "properties": {
                    "timestamp": {"type": "date"},
                    "source": {"type": "keyword"},
                    "host": {"type": "keyword"},
                    "event_type": {"type": "keyword"},
                    "severity": {"type": "keyword"},
                    "message": {"type": "text"},
                    "raw": {"type": "text"},
                    "parsed": {"type": "object", "enabled": True},
                    "tags": {"type": "keyword"},
                    "geo": {
                        "properties": {
                            "ip": {"type": "ip"},
                            "country": {"type": "keyword"},
                            "city": {"type": "keyword"},
                            "location": {"type": "geo_point"}
                        }
                    },
                    "user": {
                        "properties": {
                            "name": {"type": "keyword"},
                            "id": {"type": "keyword"},
                            "domain": {"type": "keyword"}
                        }
                    },
                    "process": {
                        "properties": {
                            "name": {"type": "keyword"},
                            "pid": {"type": "integer"},
                            "command": {"type": "text"}
                        }
                    },
                    "network": {
                        "properties": {
                            "src_ip": {"type": "ip"},
                            "dst_ip": {"type": "ip"},
                            "src_port": {"type": "integer"},
                            "dst_port": {"type": "integer"},
                            "protocol": {"type": "keyword"}
                        }
                    }
                }
            }
        }
    }
    
    # Create alerts index template
    alert_template = {
        "index_patterns": [f"{settings.ELASTICSEARCH_INDEX_PREFIX}-alerts-*"],
        "template": {
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0,
            },
            "mappings": {
                "properties": {
                    "timestamp": {"type": "date"},
                    "rule_id": {"type": "keyword"},
                    "rule_name": {"type": "keyword"},
                    "severity": {"type": "keyword"},
                    "status": {"type": "keyword"},
                    "source_host": {"type": "keyword"},
                    "message": {"type": "text"},
                    "matched_logs": {"type": "keyword"},
                    "metadata": {"type": "object"}
                }
            }
        }
    }
    
    try:
        # Create log template
        await client.indices.put_index_template(
            name=f"{settings.ELASTICSEARCH_INDEX_PREFIX}-logs-template",
            body=log_template
        )
        logger.info("Log index template created")
        
        # Create alert template
        await client.indices.put_index_template(
            name=f"{settings.ELASTICSEARCH_INDEX_PREFIX}-alerts-template",
            body=alert_template
        )
        logger.info("Alert index template created")
        
    except Exception as e:
        logger.warning("Failed to create index templates", error=str(e))


async def close_elasticsearch():
    """Close Elasticsearch connection"""
    global es_client
    if es_client:
        await es_client.close()
        es_client = None
