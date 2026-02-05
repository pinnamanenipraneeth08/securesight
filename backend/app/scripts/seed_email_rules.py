"""
SecureSight - Email Detection Rules Seed Script

Run this script to add email-specific detection rules to the database.

Usage:
    cd backend
    python -m app.scripts.seed_email_rules
"""

import asyncio
import uuid
from datetime import datetime

from sqlalchemy import select
from app.core.database import get_db, engine, AsyncSessionLocal
from app.models.rule import Rule, RuleType, RuleSeverity


EMAIL_DETECTION_RULES = [
    {
        "name": "Email Phishing Detection",
        "description": "Detect suspected phishing emails based on keyword analysis and sender reputation",
        "rule_type": RuleType.SIGNATURE,
        "severity": RuleSeverity.HIGH,
        "logic": {
            "conditions": [
                {"field": "event_type", "operator": "equals", "value": "email_phishing_suspected"},
                {"field": "parsed.phishing_score", "operator": "gte", "value": 50}
            ],
            "actions": ["alert", "notify"]
        },
        "tags": ["email", "phishing", "security"],
        "mitre_tactics": ["Initial Access"],
        "mitre_techniques": ["T1566 - Phishing"]
    },
    {
        "name": "Suspicious Email Attachment",
        "description": "Detect emails with potentially dangerous attachments (executables, macros, scripts)",
        "rule_type": RuleType.SIGNATURE,
        "severity": RuleSeverity.HIGH,
        "logic": {
            "conditions": [
                {"field": "event_type", "operator": "equals", "value": "email_suspicious_attachment"}
            ],
            "actions": ["alert", "notify"]
        },
        "tags": ["email", "malware", "attachment"],
        "mitre_tactics": ["Initial Access", "Execution"],
        "mitre_techniques": ["T1566.001 - Spearphishing Attachment"]
    },
    {
        "name": "Microsoft 365 Phishing Alert",
        "description": "Forward Microsoft 365 Defender phishing detections",
        "rule_type": RuleType.SIGNATURE,
        "severity": RuleSeverity.CRITICAL,
        "logic": {
            "conditions": [
                {"field": "event_type", "operator": "equals", "value": "email_phishing_detected"},
                {"field": "source", "operator": "equals", "value": "office365_defender"}
            ],
            "actions": ["alert", "notify", "escalate"]
        },
        "tags": ["email", "phishing", "microsoft365"],
        "mitre_tactics": ["Initial Access"],
        "mitre_techniques": ["T1566 - Phishing"]
    },
    {
        "name": "Email Malware Detection",
        "description": "Microsoft 365 Defender malware detection in email",
        "rule_type": RuleType.SIGNATURE,
        "severity": RuleSeverity.CRITICAL,
        "logic": {
            "conditions": [
                {"field": "event_type", "operator": "equals", "value": "email_malware_detected"}
            ],
            "actions": ["alert", "notify", "escalate", "block"]
        },
        "tags": ["email", "malware", "security"],
        "mitre_tactics": ["Initial Access", "Execution"],
        "mitre_techniques": ["T1204 - User Execution"]
    },
    {
        "name": "Email Sign-in Brute Force",
        "description": "Multiple failed email/Azure AD sign-in attempts from same IP",
        "rule_type": RuleType.THRESHOLD,
        "severity": RuleSeverity.HIGH,
        "logic": {
            "conditions": [
                {"field": "event_type", "operator": "equals", "value": "email_signin_failed"}
            ],
            "threshold": 5,
            "time_window": 300,
            "group_by": ["network.src_ip", "user.email"],
            "actions": ["alert", "notify"]
        },
        "tags": ["email", "brute_force", "authentication"],
        "mitre_tactics": ["Credential Access"],
        "mitre_techniques": ["T1110 - Brute Force"]
    },
    {
        "name": "Risky Email Sign-in",
        "description": "Sign-in with risk indicators detected by Azure AD Identity Protection",
        "rule_type": RuleType.SIGNATURE,
        "severity": RuleSeverity.HIGH,
        "logic": {
            "conditions": [
                {"field": "event_type", "operator": "equals", "value": "email_signin_risky"},
                {"field": "parsed.risk_level", "operator": "in", "value": ["high", "medium"]}
            ],
            "actions": ["alert", "notify"]
        },
        "tags": ["email", "risky_signin", "identity"],
        "mitre_tactics": ["Initial Access"],
        "mitre_techniques": ["T1078 - Valid Accounts"]
    },
    {
        "name": "Email Admin Privilege Escalation",
        "description": "High-risk admin actions in email/Office 365 environment",
        "rule_type": RuleType.SIGNATURE,
        "severity": RuleSeverity.CRITICAL,
        "logic": {
            "conditions": [
                {"field": "event_type", "operator": "equals", "value": "email_admin_high_risk"},
                {"field": "parsed.activity", "operator": "contains_any", "value": [
                    "Add member to role",
                    "Remove member from role",
                    "Update conditional access policy"
                ]}
            ],
            "actions": ["alert", "notify", "escalate"]
        },
        "tags": ["email", "privilege_escalation", "admin"],
        "mitre_tactics": ["Privilege Escalation", "Persistence"],
        "mitre_techniques": ["T1098 - Account Manipulation"]
    },
    {
        "name": "Email DLP Violation",
        "description": "Data Loss Prevention policy violation detected",
        "rule_type": RuleType.SIGNATURE,
        "severity": RuleSeverity.HIGH,
        "logic": {
            "conditions": [
                {"field": "event_type", "operator": "equals", "value": "email_dlp_violation"}
            ],
            "actions": ["alert", "notify"]
        },
        "tags": ["email", "dlp", "data_protection"],
        "mitre_tactics": ["Exfiltration"],
        "mitre_techniques": ["T1048 - Exfiltration Over Alternative Protocol"]
    },
    {
        "name": "Unusual Email Login Location",
        "description": "Sign-in from unusual geographic location",
        "rule_type": RuleType.ANOMALY,
        "severity": RuleSeverity.MEDIUM,
        "logic": {
            "conditions": [
                {"field": "event_type", "operator": "in", "value": ["email_signin_success", "email_signin_risky"]},
                {"field": "network.country", "operator": "not_in", "value": ["United States", "Canada", "United Kingdom"]}
            ],
            "baseline_period": 604800,  # 7 days
            "actions": ["alert"]
        },
        "tags": ["email", "anomaly", "geolocation"],
        "mitre_tactics": ["Initial Access"],
        "mitre_techniques": ["T1078 - Valid Accounts"]
    },
    {
        "name": "Email Password Spray Attack",
        "description": "Multiple failed logins across different accounts from same IP",
        "rule_type": RuleType.CORRELATION,
        "severity": RuleSeverity.CRITICAL,
        "logic": {
            "conditions": [
                {"field": "event_type", "operator": "equals", "value": "email_signin_failed"}
            ],
            "threshold": 10,
            "time_window": 600,
            "group_by": ["network.src_ip"],
            "distinct_count": {"field": "user.email", "min": 5},
            "actions": ["alert", "notify", "block_ip"]
        },
        "tags": ["email", "password_spray", "brute_force"],
        "mitre_tactics": ["Credential Access"],
        "mitre_techniques": ["T1110.003 - Password Spraying"]
    }
]


async def seed_email_rules():
    """Seed email detection rules into database"""
    print("Seeding email detection rules...")
    
    async with AsyncSessionLocal() as db:
        for rule_data in EMAIL_DETECTION_RULES:
            # Check if rule already exists
            result = await db.execute(
                select(Rule).where(Rule.name == rule_data["name"])
            )
            existing = result.scalar_one_or_none()
            
            if existing:
                print(f"  Rule '{rule_data['name']}' already exists, skipping...")
                continue
            
            rule = Rule(
                id=uuid.uuid4(),
                name=rule_data["name"],
                description=rule_data["description"],
                rule_type=rule_data["rule_type"],
                severity=rule_data["severity"],
                logic=rule_data["logic"],
                tags=rule_data.get("tags", []),
                mitre_tactics=rule_data.get("mitre_tactics", []),
                mitre_techniques=rule_data.get("mitre_techniques", []),
                enabled=True,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
            )
            db.add(rule)
            print(f"  Created rule: {rule_data['name']}")
        
        await db.commit()
    
    print(f"Done! Added {len(EMAIL_DETECTION_RULES)} email detection rules.")


if __name__ == "__main__":
    asyncio.run(seed_email_rules())
