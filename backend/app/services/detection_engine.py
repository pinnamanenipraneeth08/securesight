"""
SecureSight - Detection Engine

Real-time threat detection using rules and behavioral analysis.
"""

from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import re
import hashlib
import structlog

from app.core.redis import get_redis
from app.core.elasticsearch import get_elasticsearch
from app.core.config import settings

logger = structlog.get_logger()


class DetectionEngine:
    """Detection engine for evaluating rules against logs"""
    
    def __init__(self, session=None):
        """
        Initialize detection engine.
        
        Args:
            session: Database session for creating alerts
        """
        self.session = session
        self.es = get_elasticsearch()
    
    async def evaluate_rule(self, rule, log: dict) -> Optional[Dict[str, Any]]:
        """
        Evaluate a single rule against a single log.
        
        Args:
            rule: Detection rule (model or dict)
            log: Log entry to evaluate
            
        Returns:
            Alert dict if rule matched, None otherwise
        """
        # Convert rule model to dict if needed
        if hasattr(rule, '__dict__') and hasattr(rule, 'logic'):
            rule_dict = {
                "id": str(rule.id),
                "name": rule.name,
                "type": rule.rule_type.value if hasattr(rule.rule_type, 'value') else rule.rule_type,
                "logic": rule.logic if isinstance(rule.logic, dict) else {},
                "severity": rule.severity.value if hasattr(rule.severity, 'value') else rule.severity,
                "actions": rule.actions or [],
            }
        else:
            rule_dict = rule
        
        # Evaluate rule against single log
        matches = await evaluate_rule(rule_dict, [log])
        
        if matches:
            # Create alert data
            from app.models.alert import AlertSeverity
            return {
                "rule_id": rule_dict.get("id"),
                "rule_name": rule_dict.get("name"),
                "severity": rule_dict.get("severity", "medium"),
                "matched_log": log,
                "timestamp": datetime.utcnow().isoformat(),
            }
        
        return None


class RuleOperators:
    """Supported operators for rule conditions"""
    
    @staticmethod
    def equals(value: Any, expected: Any) -> bool:
        return str(value).lower() == str(expected).lower()
    
    @staticmethod
    def not_equals(value: Any, expected: Any) -> bool:
        return str(value).lower() != str(expected).lower()
    
    @staticmethod
    def contains(value: Any, expected: Any) -> bool:
        return str(expected).lower() in str(value).lower()
    
    @staticmethod
    def not_contains(value: Any, expected: Any) -> bool:
        return str(expected).lower() not in str(value).lower()
    
    @staticmethod
    def starts_with(value: Any, expected: Any) -> bool:
        return str(value).lower().startswith(str(expected).lower())
    
    @staticmethod
    def ends_with(value: Any, expected: Any) -> bool:
        return str(value).lower().endswith(str(expected).lower())
    
    @staticmethod
    def regex(value: Any, pattern: Any) -> bool:
        try:
            return bool(re.search(pattern, str(value), re.IGNORECASE))
        except re.error:
            return False
    
    @staticmethod
    def greater_than(value: Any, expected: Any) -> bool:
        try:
            return float(value) > float(expected)
        except (ValueError, TypeError):
            return False
    
    @staticmethod
    def less_than(value: Any, expected: Any) -> bool:
        try:
            return float(value) < float(expected)
        except (ValueError, TypeError):
            return False
    
    @staticmethod
    def in_list(value: Any, expected_list: List) -> bool:
        return str(value).lower() in [str(e).lower() for e in expected_list]
    
    @staticmethod
    def not_in_list(value: Any, expected_list: List) -> bool:
        return str(value).lower() not in [str(e).lower() for e in expected_list]
    
    @staticmethod
    def is_private_ip(value: Any, _: Any = None) -> bool:
        """Check if IP is in private range"""
        import ipaddress
        try:
            ip = ipaddress.ip_address(value)
            return ip.is_private
        except ValueError:
            return False
    
    @staticmethod
    def is_public_ip(value: Any, _: Any = None) -> bool:
        """Check if IP is public"""
        import ipaddress
        try:
            ip = ipaddress.ip_address(value)
            return not ip.is_private
        except ValueError:
            return False


OPERATORS = {
    "equals": RuleOperators.equals,
    "eq": RuleOperators.equals,
    "not_equals": RuleOperators.not_equals,
    "neq": RuleOperators.not_equals,
    "contains": RuleOperators.contains,
    "not_contains": RuleOperators.not_contains,
    "starts_with": RuleOperators.starts_with,
    "ends_with": RuleOperators.ends_with,
    "regex": RuleOperators.regex,
    "gt": RuleOperators.greater_than,
    "greater_than": RuleOperators.greater_than,
    "lt": RuleOperators.less_than,
    "less_than": RuleOperators.less_than,
    "in": RuleOperators.in_list,
    "not_in": RuleOperators.not_in_list,
    "is_private_ip": RuleOperators.is_private_ip,
    "is_public_ip": RuleOperators.is_public_ip,
}


def get_nested_value(data: dict, field: str) -> Any:
    """Get value from nested dict using dot notation (e.g., 'network.src_ip')"""
    keys = field.split(".")
    value = data
    for key in keys:
        if isinstance(value, dict):
            value = value.get(key)
        else:
            return None
    return value


def evaluate_condition(log: dict, condition: dict) -> bool:
    """
    Evaluate a single condition against a log entry.
    
    Condition format:
    {
        "field": "event_type",
        "operator": "equals",
        "value": "auth_failure"
    }
    """
    field = condition.get("field")
    operator = condition.get("operator", "equals")
    expected = condition.get("value")
    
    if not field:
        return False
    
    # Get actual value from log
    actual = get_nested_value(log, field)
    
    if actual is None:
        return False
    
    # Get operator function
    op_func = OPERATORS.get(operator)
    if not op_func:
        logger.warning("Unknown operator", operator=operator)
        return False
    
    return op_func(actual, expected)


async def evaluate_rule(rule: dict, logs: List[dict]) -> List[dict]:
    """
    Evaluate a detection rule against a list of logs.
    
    Returns list of logs that match the rule.
    """
    rule_type = rule.get("type", "threshold")
    logic = rule.get("logic", {})
    conditions = logic.get("conditions", [])
    
    # Find logs matching all conditions
    matching_logs = []
    
    for log in logs:
        # Check if all conditions match (AND logic)
        all_match = True
        for condition in conditions:
            if not evaluate_condition(log, condition):
                all_match = False
                break
        
        if all_match:
            matching_logs.append(log)
    
    # For simple rules, return matches immediately
    if rule_type == "signature":
        return matching_logs
    
    # For threshold rules, check if count exceeds threshold
    if rule_type == "threshold":
        threshold = logic.get("threshold", 1)
        time_window = logic.get("time_window", 300)  # 5 minutes default
        group_by = logic.get("group_by", [])
        
        if len(matching_logs) >= threshold:
            return matching_logs
        
        # Check historical data if we have a time window
        if time_window > 0 and group_by:
            count = await count_historical_matches(
                conditions=conditions,
                time_window=time_window,
                group_by=group_by,
                current_logs=matching_logs
            )
            if count >= threshold:
                return matching_logs
    
    return []


async def count_historical_matches(
    conditions: List[dict],
    time_window: int,
    group_by: List[str],
    current_logs: List[dict]
) -> int:
    """
    Count matching events in the time window from Elasticsearch.
    Uses Redis for caching/counting.
    """
    if not current_logs:
        return 0
    
    redis = get_redis()
    
    # Build cache key from group_by values
    sample_log = current_logs[0]
    group_values = [str(get_nested_value(sample_log, field) or "") for field in group_by]
    cache_key = f"securesight:detection:{':'.join(group_values)}"
    
    # Increment counter in Redis with TTL
    count = await redis.incr(cache_key)
    await redis.expire(cache_key, time_window)
    
    return count


async def process_logs_for_detection(logs: List[dict]):
    """
    Process logs through the detection engine.
    
    - Loads active rules
    - Evaluates each rule
    - Creates alerts for matches
    """
    if not logs:
        return
    
    # Load active rules from database
    from app.core.database import async_session_factory
    from sqlalchemy import select
    from app.models.rule import Rule
    
    async with async_session_factory() as db:
        result = await db.execute(
            select(Rule).where(Rule.is_enabled == True)
        )
        rules = result.scalars().all()
        
        if not rules:
            return
        
        logger.debug("Evaluating rules", rule_count=len(rules), log_count=len(logs))
        
        # Evaluate each rule
        for rule in rules:
            try:
                matches = await evaluate_rule(rule.to_dict(), logs)
                
                if matches:
                    # Update hit count
                    rule.hit_count = (rule.hit_count or 0) + 1
                    rule.last_triggered = datetime.utcnow()
                    
                    # Create alert if not in test mode
                    if not rule.is_test_mode:
                        await create_alert(db, rule, matches)
                    else:
                        logger.info("Rule matched (test mode)", 
                                   rule=rule.name, matches=len(matches))
                        
            except Exception as e:
                logger.error("Rule evaluation failed", 
                           rule=rule.name, error=str(e))
        
        await db.commit()


async def create_alert(db, rule, matched_logs: List[dict]):
    """Create an alert from a rule match"""
    from app.models.alert import Alert, AlertSeverity
    
    # Generate fingerprint for deduplication
    fingerprint = generate_fingerprint(rule.id, matched_logs)
    
    # Check for existing alert with same fingerprint (deduplication)
    from sqlalchemy import select
    result = await db.execute(
        select(Alert).where(Alert.fingerprint == fingerprint)
    )
    existing = result.scalar_one_or_none()
    
    if existing:
        # Update occurrence count instead of creating new
        existing.occurrence_count = str(int(existing.occurrence_count or "1") + 1)
        existing.last_occurrence = datetime.utcnow()
        logger.info("Alert deduplicated", alert_id=str(existing.id))
        return
    
    # Map rule severity to alert severity
    severity_map = {
        "critical": AlertSeverity.CRITICAL,
        "high": AlertSeverity.HIGH,
        "medium": AlertSeverity.MEDIUM,
        "low": AlertSeverity.LOW,
        "info": AlertSeverity.INFO,
    }
    
    # Extract source info from matched logs
    source_host = matched_logs[0].get("host", "unknown") if matched_logs else None
    source_ip = None
    if matched_logs:
        network = matched_logs[0].get("network", {})
        source_ip = network.get("src_ip")
    
    # Create alert
    alert = Alert(
        title=f"[{rule.severity.value.upper()}] {rule.name}",
        description=rule.description or f"Detection rule '{rule.name}' triggered",
        severity=severity_map.get(rule.severity.value, AlertSeverity.MEDIUM),
        source_host=source_host,
        source_ip=source_ip,
        rule_id=rule.id,
        matched_logs=[log.get("_id") for log in matched_logs if log.get("_id")],
        metadata={
            "matched_count": len(matched_logs),
            "rule_type": rule.rule_type.value,
            "sample_message": matched_logs[0].get("message", "")[:500] if matched_logs else None,
        },
        fingerprint=fingerprint,
    )
    
    db.add(alert)
    
    logger.info("Alert created", 
               rule=rule.name, 
               severity=rule.severity.value,
               matches=len(matched_logs))
    
    # Broadcast alert via WebSocket for real-time updates
    try:
        from app.core.websocket import manager
        await manager.broadcast_alert({
            "id": str(alert.id),
            "title": alert.title,
            "description": alert.description,
            "severity": alert.severity.value,
            "source_host": alert.source_host,
            "source_ip": alert.source_ip,
            "created_at": alert.created_at.isoformat() if alert.created_at else None,
        })
    except Exception as e:
        logger.warning("Failed to broadcast alert via WebSocket", error=str(e))
    
    # Trigger alerting actions
    await trigger_alert_actions(alert, rule.actions or [])


def generate_fingerprint(rule_id, logs: List[dict]) -> str:
    """
    Generate fingerprint for alert deduplication.
    
    Based on rule ID and key attributes from matched logs.
    """
    # Use first log's key fields
    if logs:
        log = logs[0]
        key_data = f"{rule_id}:{log.get('host', '')}:{log.get('event_type', '')}"
        
        # Include source IP if available
        network = log.get("network", {})
        if network.get("src_ip"):
            key_data += f":{network['src_ip']}"
        
        # Include user if available
        user = log.get("user", {})
        if user.get("name"):
            key_data += f":{user['name']}"
    else:
        key_data = str(rule_id)
    
    return hashlib.sha256(key_data.encode()).hexdigest()[:16]


async def trigger_alert_actions(alert, actions: List[str]):
    """Trigger configured alert actions (email, Slack, etc.)"""
    from app.services.alerting import send_email_alert, send_slack_alert, send_telegram_alert
    
    for action in actions:
        try:
            if action == "email":
                await send_email_alert(alert)
            elif action == "slack":
                await send_slack_alert(alert)
            elif action == "telegram":
                await send_telegram_alert(alert)
            elif action == "block_ip":
                # Automated response
                from app.services.response_actions import block_ip
                if alert.source_ip:
                    await block_ip(alert.source_ip)
            else:
                logger.warning("Unknown alert action", action=action)
        except Exception as e:
            logger.error("Alert action failed", action=action, error=str(e))


# Predefined detection rules
DEFAULT_RULES = [
    {
        "name": "Brute Force Detection",
        "description": "Detects multiple failed login attempts from the same source",
        "rule_type": "threshold",
        "severity": "high",
        "logic": {
            "conditions": [
                {"field": "event_type", "operator": "equals", "value": "auth_failure"}
            ],
            "threshold": 5,
            "time_window": 300,
            "group_by": ["network.src_ip", "user.name"]
        },
        "actions": ["email", "slack"],
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1110"
    },
    {
        "name": "Suspicious Login Location",
        "description": "Detects logins from unusual geographic locations",
        "rule_type": "correlation",
        "severity": "medium",
        "logic": {
            "conditions": [
                {"field": "event_type", "operator": "equals", "value": "auth_success"},
                {"field": "geo.country", "operator": "not_in", "value": ["US", "CA", "GB"]}
            ]
        },
        "actions": ["email"],
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T1078"
    },
    {
        "name": "Privilege Escalation Attempt",
        "description": "Detects privilege escalation attempts",
        "rule_type": "signature",
        "severity": "critical",
        "logic": {
            "conditions": [
                {"field": "message", "operator": "regex", "value": "(sudo|su\\s+root|setuid|chmod\\s+[46]|chown.*root)"}
            ]
        },
        "actions": ["email", "slack"],
        "mitre_tactic": "Privilege Escalation",
        "mitre_technique": "T1548"
    },
    {
        "name": "Malware Hash Detection",
        "description": "Detects known malware file hashes",
        "rule_type": "signature",
        "severity": "critical",
        "logic": {
            "conditions": [
                {"field": "parsed.file_hash", "operator": "in", "value": []}
            ]
        },
        "actions": ["email", "slack", "block_ip"],
        "mitre_tactic": "Execution",
        "mitre_technique": "T1204"
    },
    {
        "name": "Port Scan Detection",
        "description": "Detects potential port scanning activity",
        "rule_type": "threshold",
        "severity": "medium",
        "logic": {
            "conditions": [
                {"field": "event_type", "operator": "equals", "value": "firewall_event"},
                {"field": "message", "operator": "contains", "value": "blocked"}
            ],
            "threshold": 20,
            "time_window": 60,
            "group_by": ["network.src_ip"]
        },
        "actions": ["email"],
        "mitre_tactic": "Discovery",
        "mitre_technique": "T1046"
    }
]
