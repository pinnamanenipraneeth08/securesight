"""
SecureSight - Alerting Service

Handles alert notifications via various channels.
"""

import aiohttp
import structlog
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

try:
    import aiosmtplib
    SMTP_AVAILABLE = True
except ImportError:
    aiosmtplib = None  # type: ignore
    SMTP_AVAILABLE = False

from app.core.config import settings

logger = structlog.get_logger()


async def send_email_alert(alert):
    """Send alert notification via email"""
    if not SMTP_AVAILABLE:
        logger.warning("aiosmtplib not installed, email alerting unavailable")
        return
        
    if not settings.SMTP_HOST:
        logger.warning("Email alerting not configured")
        return
    
    try:
        message = MIMEMultipart("alternative")
        message["Subject"] = f"🚨 SecureSight Alert: {alert.title}"
        message["From"] = settings.SMTP_FROM
        message["To"] = settings.SMTP_USER  # Send to configured user
        
        # Plain text version
        text_content = f"""
SecureSight Security Alert
===========================

Title: {alert.title}
Severity: {alert.severity.value.upper()}
Status: {alert.status.value}
Source Host: {alert.source_host or 'N/A'}
Source IP: {alert.source_ip or 'N/A'}

Description:
{alert.description or 'No description'}

Time: {alert.created_at.isoformat()}

---
This is an automated alert from SecureSight SIEM.
        """
        
        # HTML version
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; }}
        .alert-box {{ border: 2px solid #dc3545; border-radius: 8px; padding: 20px; }}
        .severity-critical {{ color: #dc3545; }}
        .severity-high {{ color: #fd7e14; }}
        .severity-medium {{ color: #ffc107; }}
        .severity-low {{ color: #17a2b8; }}
        .label {{ font-weight: bold; color: #666; }}
    </style>
</head>
<body>
    <div class="alert-box">
        <h2>🚨 Security Alert</h2>
        <h3 class="severity-{alert.severity.value}">{alert.title}</h3>
        <p><span class="label">Severity:</span> {alert.severity.value.upper()}</p>
        <p><span class="label">Source Host:</span> {alert.source_host or 'N/A'}</p>
        <p><span class="label">Source IP:</span> {alert.source_ip or 'N/A'}</p>
        <p><span class="label">Description:</span><br>{alert.description or 'No description'}</p>
        <p><span class="label">Time:</span> {alert.created_at.isoformat()}</p>
    </div>
    <p style="color: #888; font-size: 12px;">This is an automated alert from SecureSight SIEM.</p>
</body>
</html>
        """
        
        message.attach(MIMEText(text_content, "plain"))
        message.attach(MIMEText(html_content, "html"))
        
        # aiosmtplib is guaranteed to be available here due to SMTP_AVAILABLE check
        assert aiosmtplib is not None
        await aiosmtplib.send(
            message,
            hostname=settings.SMTP_HOST,
            port=settings.SMTP_PORT,
            username=settings.SMTP_USER,
            password=settings.SMTP_PASSWORD,
            start_tls=True,
        )
        
        logger.info("Email alert sent", alert_id=str(alert.id))
        
    except Exception as e:
        logger.error("Failed to send email alert", error=str(e))


async def send_slack_alert(alert):
    """Send alert notification to Slack"""
    if not settings.SLACK_WEBHOOK_URL:
        logger.warning("Slack alerting not configured")
        return
    
    try:
        severity_emoji = {
            "critical": "🔴",
            "high": "🟠", 
            "medium": "🟡",
            "low": "🔵",
            "info": "⚪",
        }
        
        emoji = severity_emoji.get(alert.severity.value, "⚪")
        
        payload = {
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": f"{emoji} Security Alert",
                        "emoji": True
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": f"*Title:*\n{alert.title}"
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Severity:*\n{alert.severity.value.upper()}"
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Source Host:*\n{alert.source_host or 'N/A'}"
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Source IP:*\n{alert.source_ip or 'N/A'}"
                        }
                    ]
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Description:*\n{alert.description or 'No description'}"
                    }
                },
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": f"⏰ {alert.created_at.isoformat()} | SecureSight SIEM"
                        }
                    ]
                }
            ]
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                settings.SLACK_WEBHOOK_URL,
                json=payload,
            ) as response:
                if response.status != 200:
                    text = await response.text()
                    logger.error("Slack API error", status=response.status, response=text)
                else:
                    logger.info("Slack alert sent", alert_id=str(alert.id))
                    
    except Exception as e:
        logger.error("Failed to send Slack alert", error=str(e))


async def send_telegram_alert(alert):
    """Send alert notification to Telegram"""
    if not settings.TELEGRAM_BOT_TOKEN or not settings.TELEGRAM_CHAT_ID:
        logger.warning("Telegram alerting not configured")
        return
    
    try:
        severity_emoji = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🔵",
            "info": "⚪",
        }
        
        emoji = severity_emoji.get(alert.severity.value, "⚪")
        
        message = f"""
{emoji} *Security Alert*

*Title:* {alert.title}
*Severity:* {alert.severity.value.upper()}
*Source Host:* {alert.source_host or 'N/A'}
*Source IP:* {alert.source_ip or 'N/A'}

*Description:*
{alert.description or 'No description'}

⏰ {alert.created_at.isoformat()}
        """
        
        url = f"https://api.telegram.org/bot{settings.TELEGRAM_BOT_TOKEN}/sendMessage"
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                url,
                json={
                    "chat_id": settings.TELEGRAM_CHAT_ID,
                    "text": message,
                    "parse_mode": "Markdown",
                },
            ) as response:
                if response.status != 200:
                    data = await response.json()
                    logger.error("Telegram API error", response=data)
                else:
                    logger.info("Telegram alert sent", alert_id=str(alert.id))
                    
    except Exception as e:
        logger.error("Failed to send Telegram alert", error=str(e))
