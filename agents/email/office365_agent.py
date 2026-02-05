#!/usr/bin/env python3
"""
SecureSight Office 365 Email Monitoring Agent

Monitors Microsoft 365 for:
- Sign-in activities and anomalies
- Email message tracking (sent/received)
- Phishing and malware detections
- DLP policy matches
- Admin audit activities

Requires Azure AD App Registration with these permissions:
- AuditLog.Read.All
- MailboxSettings.Read
- SecurityEvents.Read.All
- Reports.Read.All
"""

import os
import sys
import json
import asyncio
import logging
import argparse
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field

import yaml
import aiohttp
from tenacity import retry, stop_after_attempt, wait_exponential

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('securesight-o365')


@dataclass
class O365Config:
    """Office 365 Agent Configuration"""
    # Azure AD App Registration
    tenant_id: str
    client_id: str
    client_secret: str
    
    # SecureSight API
    siem_url: str
    siem_api_key: str
    
    # Monitoring options
    monitor_signins: bool = True
    monitor_audit: bool = True
    monitor_security_alerts: bool = True
    monitor_message_trace: bool = True
    
    # Polling intervals (seconds)
    signin_interval: int = 60
    audit_interval: int = 300
    security_interval: int = 30
    message_trace_interval: int = 120
    
    # State file
    state_file: str = "o365_state.json"
    
    @classmethod
    def from_file(cls, path: str) -> "O365Config":
        with open(path, 'r') as f:
            data = yaml.safe_load(f)
        return cls(**data)


class O365EmailMonitor:
    """Microsoft 365 Email and Security Monitor"""
    
    GRAPH_URL = "https://graph.microsoft.com/v1.0"
    GRAPH_BETA_URL = "https://graph.microsoft.com/beta"
    
    def __init__(self, config: O365Config):
        self.config = config
        self.access_token: Optional[str] = None
        self.token_expires: Optional[datetime] = None
        self.state = self._load_state()
        self.running = True
    
    def _load_state(self) -> Dict[str, Any]:
        """Load last poll timestamps"""
        try:
            with open(self.config.state_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {
                "last_signin": None,
                "last_audit": None,
                "last_security": None,
                "last_message_trace": None,
            }
    
    def _save_state(self):
        """Save state to disk"""
        with open(self.config.state_file, 'w') as f:
            json.dump(self.state, f, indent=2, default=str)
    
    async def get_access_token(self) -> str:
        """Get or refresh OAuth2 access token"""
        if self.access_token and self.token_expires and datetime.utcnow() < self.token_expires:
            return self.access_token
        
        url = f"https://login.microsoftonline.com/{self.config.tenant_id}/oauth2/v2.0/token"
        data = {
            "grant_type": "client_credentials",
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret,
            "scope": "https://graph.microsoft.com/.default"
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=data) as resp:
                if resp.status != 200:
                    error = await resp.text()
                    raise Exception(f"Failed to get token: {error}")
                
                result = await resp.json()
                self.access_token = result["access_token"]
                expires_in = result.get("expires_in", 3600)
                self.token_expires = datetime.utcnow() + timedelta(seconds=expires_in - 60)
                return self.access_token
    
    async def graph_request(self, endpoint: str, beta: bool = False) -> Dict[str, Any]:
        """Make authenticated request to Microsoft Graph API"""
        token = await self.get_access_token()
        base_url = self.GRAPH_BETA_URL if beta else self.GRAPH_URL
        url = f"{base_url}{endpoint}"
        
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers) as resp:
                if resp.status == 200:
                    return await resp.json()
                elif resp.status == 401:
                    # Token expired, refresh and retry
                    self.access_token = None
                    token = await self.get_access_token()
                    headers["Authorization"] = f"Bearer {token}"
                    async with session.get(url, headers=headers) as retry_resp:
                        return await retry_resp.json()
                else:
                    logger.error(f"Graph API error: {resp.status} - {await resp.text()}")
                    return {"value": []}
    
    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    async def send_to_siem(self, events: List[Dict[str, Any]]):
        """Send events to SecureSight SIEM"""
        if not events:
            return
        
        async with aiohttp.ClientSession() as session:
            await session.post(
                f"{self.config.siem_url}/api/v1/logs/ingest/bulk",
                json={"events": events},
                headers={
                    "X-API-Key": self.config.siem_api_key,
                    "Content-Type": "application/json"
                }
            )
        logger.info(f"Sent {len(events)} events to SIEM")
    
    async def collect_signin_logs(self):
        """Collect Azure AD sign-in logs"""
        logger.info("Collecting sign-in logs...")
        
        # Build filter for new events
        filter_time = self.state.get("last_signin") or (
            datetime.utcnow() - timedelta(hours=1)
        ).isoformat() + "Z"
        
        endpoint = f"/auditLogs/signIns?$filter=createdDateTime gt {filter_time}&$orderby=createdDateTime asc"
        
        try:
            data = await self.graph_request(endpoint)
            events = []
            
            for log in data.get("value", []):
                # Determine severity based on sign-in status
                error_code = log.get("status", {}).get("errorCode", 0)
                risk_level = log.get("riskLevelDuringSignIn", "none")
                
                if risk_level in ["high", "medium"]:
                    severity = "high"
                elif error_code != 0:
                    severity = "medium"
                else:
                    severity = "low"
                
                # Determine event type
                if error_code != 0:
                    event_type = "email_signin_failed"
                elif risk_level != "none":
                    event_type = "email_signin_risky"
                else:
                    event_type = "email_signin_success"
                
                events.append({
                    "timestamp": log["createdDateTime"],
                    "source": "office365",
                    "host": "azure-ad",
                    "event_type": event_type,
                    "severity": severity,
                    "message": f"Sign-in: {log.get('userPrincipalName', 'unknown')} from {log.get('ipAddress', 'unknown')}",
                    "user": {
                        "name": log.get("userPrincipalName"),
                        "id": log.get("userId"),
                        "ip": log.get("ipAddress"),
                    },
                    "network": {
                        "src_ip": log.get("ipAddress"),
                        "location": log.get("location", {}).get("city"),
                        "country": log.get("location", {}).get("countryOrRegion"),
                    },
                    "parsed": {
                        "app_display_name": log.get("appDisplayName"),
                        "client_app": log.get("clientAppUsed"),
                        "device_detail": log.get("deviceDetail"),
                        "conditional_access": log.get("conditionalAccessStatus"),
                        "risk_level": risk_level,
                        "error_code": error_code,
                        "failure_reason": log.get("status", {}).get("failureReason"),
                    }
                })
                
                # Update last processed timestamp
                self.state["last_signin"] = log["createdDateTime"]
            
            if events:
                await self.send_to_siem(events)
                self._save_state()
                logger.info(f"Processed {len(events)} sign-in events")
        
        except Exception as e:
            logger.error(f"Error collecting sign-in logs: {e}")
    
    async def collect_security_alerts(self):
        """Collect Microsoft 365 Defender security alerts"""
        logger.info("Collecting security alerts...")
        
        filter_time = self.state.get("last_security") or (
            datetime.utcnow() - timedelta(hours=24)
        ).isoformat() + "Z"
        
        endpoint = f"/security/alerts_v2?$filter=createdDateTime gt {filter_time}"
        
        try:
            data = await self.graph_request(endpoint)
            events = []
            
            for alert in data.get("value", []):
                # Map Microsoft severity to our severity
                severity_map = {
                    "high": "critical",
                    "medium": "high", 
                    "low": "medium",
                    "informational": "low"
                }
                severity = severity_map.get(alert.get("severity", "").lower(), "medium")
                
                # Determine event type based on category
                category = alert.get("category", "").lower()
                if "phishing" in category or "spam" in category:
                    event_type = "email_phishing_detected"
                elif "malware" in category:
                    event_type = "email_malware_detected"
                elif "data" in category:
                    event_type = "email_dlp_violation"
                else:
                    event_type = "email_security_alert"
                
                # Extract affected users/mailboxes
                evidence = alert.get("evidence", [])
                affected_users = [
                    e.get("userAccount", {}).get("userPrincipalName")
                    for e in evidence
                    if e.get("@odata.type") == "#microsoft.graph.security.userEvidence"
                ]
                
                events.append({
                    "timestamp": alert["createdDateTime"],
                    "source": "office365_defender",
                    "host": "microsoft-365",
                    "event_type": event_type,
                    "severity": severity,
                    "message": f"{alert.get('title', 'Security Alert')}: {alert.get('description', '')}",
                    "user": {
                        "name": affected_users[0] if affected_users else None,
                        "affected_users": affected_users,
                    },
                    "parsed": {
                        "alert_id": alert.get("id"),
                        "category": alert.get("category"),
                        "service_source": alert.get("serviceSource"),
                        "detection_source": alert.get("detectionSource"),
                        "recommended_actions": alert.get("recommendedActions"),
                        "status": alert.get("status"),
                        "classification": alert.get("classification"),
                    }
                })
                
                self.state["last_security"] = alert["createdDateTime"]
            
            if events:
                await self.send_to_siem(events)
                self._save_state()
                logger.info(f"Processed {len(events)} security alerts")
        
        except Exception as e:
            logger.error(f"Error collecting security alerts: {e}")
    
    async def collect_audit_logs(self):
        """Collect Office 365 admin audit logs"""
        logger.info("Collecting audit logs...")
        
        filter_time = self.state.get("last_audit") or (
            datetime.utcnow() - timedelta(hours=24)
        ).isoformat() + "Z"
        
        endpoint = f"/auditLogs/directoryAudits?$filter=activityDateTime gt {filter_time}"
        
        try:
            data = await self.graph_request(endpoint)
            events = []
            
            # High-risk activities
            high_risk_activities = [
                "Add member to role",
                "Remove member from role", 
                "Update user",
                "Delete user",
                "Reset user password",
                "Update application",
                "Add application",
                "Add service principal",
                "Update conditional access policy",
                "Delete conditional access policy",
            ]
            
            for log in data.get("value", []):
                activity = log.get("activityDisplayName", "")
                
                # Determine severity
                if any(risk in activity for risk in high_risk_activities):
                    severity = "high"
                    event_type = "email_admin_high_risk"
                else:
                    severity = "low"
                    event_type = "email_admin_activity"
                
                # Get actor info
                initiated_by = log.get("initiatedBy", {})
                actor = initiated_by.get("user", {}) or initiated_by.get("app", {})
                
                events.append({
                    "timestamp": log["activityDateTime"],
                    "source": "office365_audit",
                    "host": "azure-ad",
                    "event_type": event_type,
                    "severity": severity,
                    "message": f"Admin: {activity} by {actor.get('userPrincipalName') or actor.get('displayName', 'unknown')}",
                    "user": {
                        "name": actor.get("userPrincipalName") or actor.get("displayName"),
                        "id": actor.get("id"),
                        "ip": actor.get("ipAddress"),
                    },
                    "parsed": {
                        "activity": activity,
                        "category": log.get("category"),
                        "result": log.get("result"),
                        "target_resources": log.get("targetResources"),
                        "correlation_id": log.get("correlationId"),
                    }
                })
                
                self.state["last_audit"] = log["activityDateTime"]
            
            if events:
                await self.send_to_siem(events)
                self._save_state()
                logger.info(f"Processed {len(events)} audit events")
        
        except Exception as e:
            logger.error(f"Error collecting audit logs: {e}")
    
    async def run(self):
        """Main monitoring loop"""
        logger.info("Starting Office 365 Email Monitor...")
        
        while self.running:
            tasks = []
            
            if self.config.monitor_signins:
                tasks.append(self.collect_signin_logs())
            
            if self.config.monitor_security_alerts:
                tasks.append(self.collect_security_alerts())
            
            if self.config.monitor_audit:
                tasks.append(self.collect_audit_logs())
            
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            
            # Wait for next poll cycle
            await asyncio.sleep(min(
                self.config.signin_interval,
                self.config.security_interval,
                self.config.audit_interval
            ))
    
    def stop(self):
        """Stop the monitor"""
        self.running = False
        self._save_state()


async def main():
    parser = argparse.ArgumentParser(description="SecureSight Office 365 Monitor")
    parser.add_argument("-c", "--config", required=True, help="Path to config file")
    args = parser.parse_args()
    
    config = O365Config.from_file(args.config)
    monitor = O365EmailMonitor(config)
    
    # Handle shutdown
    import signal
    def shutdown(sig, frame):
        logger.info("Shutting down...")
        monitor.stop()
    
    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)
    
    await monitor.run()


if __name__ == "__main__":
    asyncio.run(main())
