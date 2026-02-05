#!/usr/bin/env python3
"""
SecureSight IMAP Email Monitoring Agent

Monitors email servers via IMAP for:
- Incoming emails with suspicious patterns
- Phishing attempts based on subject/sender analysis
- Attachment monitoring
- Login activity (where supported)

Works with:
- Gmail (with App Password)
- Microsoft 365 (with OAuth or App Password)
- Exchange Server
- Any IMAP-compatible email server
"""

import os
import sys
import json
import email
import asyncio
import logging
import argparse
import hashlib
import re
from datetime import datetime, timedelta
from email.header import decode_header
from email.utils import parseaddr, parsedate_to_datetime
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
import imaplib
import ssl

import yaml
import aiohttp
from tenacity import retry, stop_after_attempt, wait_exponential

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('securesight-imap')


# Phishing indicators
PHISHING_KEYWORDS = [
    "urgent action required",
    "verify your account",
    "suspended account",
    "confirm your identity",
    "unusual activity",
    "click here immediately",
    "your account will be closed",
    "update your payment",
    "lottery winner",
    "you have won",
    "claim your prize",
    "password expires",
    "security alert",
    "unauthorized access",
]

SUSPICIOUS_ATTACHMENT_EXTENSIONS = [
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif",
    ".vbs", ".js", ".jse", ".wsf", ".wsh",
    ".ps1", ".psm1", ".psd1",
    ".hta", ".cpl", ".msi", ".msp",
    ".jar", ".docm", ".xlsm", ".pptm",
]

SPOOFED_DOMAINS = [
    "microsoft-security", "apple-id", "paypa1", "amazom",
    "netflix-billing", "bankofamerica-secure", "chase-verify",
    "google-security", "facebook-confirm", "instagram-support",
]


@dataclass
class MailboxConfig:
    """Configuration for a single mailbox"""
    email: str
    password: str
    imap_server: str
    imap_port: int = 993
    use_ssl: bool = True
    folders: List[str] = field(default_factory=lambda: ["INBOX"])
    label: str = ""  # Optional friendly name


@dataclass
class IMAPConfig:
    """IMAP Agent Configuration"""
    mailboxes: List[MailboxConfig]
    siem_url: str
    siem_api_key: str
    
    # Monitoring options
    check_interval: int = 60  # seconds
    lookback_hours: int = 24  # How far back to check on first run
    analyze_attachments: bool = True
    analyze_links: bool = True
    
    # State file
    state_file: str = "imap_state.json"
    
    @classmethod
    def from_file(cls, path: str) -> "IMAPConfig":
        with open(path, 'r') as f:
            data = yaml.safe_load(f)
        
        mailboxes = [
            MailboxConfig(**mb) for mb in data.get('mailboxes', [])
        ]
        
        return cls(
            mailboxes=mailboxes,
            siem_url=data['siem_url'],
            siem_api_key=data['siem_api_key'],
            check_interval=data.get('check_interval', 60),
            lookback_hours=data.get('lookback_hours', 24),
            analyze_attachments=data.get('analyze_attachments', True),
            analyze_links=data.get('analyze_links', True),
            state_file=data.get('state_file', 'imap_state.json'),
        )


class EmailAnalyzer:
    """Analyzes emails for security threats"""
    
    @staticmethod
    def decode_subject(subject: str) -> str:
        """Decode email subject"""
        if not subject:
            return ""
        
        decoded_parts = []
        for part, encoding in decode_header(subject):
            if isinstance(part, bytes):
                decoded_parts.append(part.decode(encoding or 'utf-8', errors='replace'))
            else:
                decoded_parts.append(part)
        return ' '.join(decoded_parts)
    
    @staticmethod
    def extract_links(html_content: str) -> List[str]:
        """Extract URLs from HTML content"""
        url_pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+'
        return re.findall(url_pattern, html_content or "")
    
    @staticmethod
    def check_phishing_indicators(subject: str, sender: str, body: str) -> Dict[str, Any]:
        """Check for phishing indicators"""
        indicators = []
        score = 0
        
        combined_text = f"{subject} {body}".lower()
        
        # Check for phishing keywords
        for keyword in PHISHING_KEYWORDS:
            if keyword in combined_text:
                indicators.append(f"Phishing keyword: {keyword}")
                score += 20
        
        # Check sender domain
        _, sender_email = parseaddr(sender)
        sender_domain = sender_email.split('@')[-1] if '@' in sender_email else ""
        
        for spoofed in SPOOFED_DOMAINS:
            if spoofed in sender_domain:
                indicators.append(f"Potentially spoofed domain: {sender_domain}")
                score += 40
        
        # Check for urgency in subject
        urgency_words = ["urgent", "immediate", "important", "action required", "asap"]
        if any(word in subject.lower() for word in urgency_words):
            indicators.append("Urgency language in subject")
            score += 10
        
        # Check for mismatched sender name vs email
        display_name, email_addr = parseaddr(sender)
        if display_name and '@' in display_name.lower():
            indicators.append("Email address in display name (spoofing attempt)")
            score += 30
        
        return {
            "is_suspicious": score >= 30,
            "phishing_score": min(score, 100),
            "indicators": indicators,
        }
    
    @staticmethod
    def check_attachments(msg: email.message.Message) -> List[Dict[str, Any]]:
        """Analyze email attachments"""
        attachments = []
        
        for part in msg.walk():
            if part.get_content_maintype() == 'multipart':
                continue
            
            filename = part.get_filename()
            if not filename:
                continue
            
            # Decode filename if needed
            if isinstance(filename, bytes):
                filename = filename.decode('utf-8', errors='replace')
            
            # Check extension
            ext = os.path.splitext(filename.lower())[1]
            is_suspicious = ext in SUSPICIOUS_ATTACHMENT_EXTENSIONS
            
            # Get content hash
            payload = part.get_payload(decode=True)
            file_hash = hashlib.sha256(payload).hexdigest() if payload else None
            
            attachments.append({
                "filename": filename,
                "extension": ext,
                "size": len(payload) if payload else 0,
                "sha256": file_hash,
                "is_suspicious": is_suspicious,
                "content_type": part.get_content_type(),
            })
        
        return attachments


class IMAPEmailMonitor:
    """IMAP Email Monitor"""
    
    def __init__(self, config: IMAPConfig):
        self.config = config
        self.analyzer = EmailAnalyzer()
        self.state = self._load_state()
        self.running = True
    
    def _load_state(self) -> Dict[str, Any]:
        """Load last processed message IDs"""
        try:
            with open(self.config.state_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {}
    
    def _save_state(self):
        """Save state to disk"""
        with open(self.config.state_file, 'w') as f:
            json.dump(self.state, f, indent=2)
    
    def _get_mailbox_key(self, mailbox: MailboxConfig) -> str:
        """Get unique key for mailbox state"""
        return f"{mailbox.email}:{mailbox.imap_server}"
    
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
        logger.info(f"Sent {len(events)} email events to SIEM")
    
    def connect_imap(self, mailbox: MailboxConfig) -> imaplib.IMAP4_SSL:
        """Connect to IMAP server"""
        if mailbox.use_ssl:
            context = ssl.create_default_context()
            conn = imaplib.IMAP4_SSL(
                mailbox.imap_server, 
                mailbox.imap_port,
                ssl_context=context
            )
        else:
            conn = imaplib.IMAP4(mailbox.imap_server, mailbox.imap_port)
        
        conn.login(mailbox.email, mailbox.password)
        return conn
    
    def process_email(self, msg: email.message.Message, mailbox: MailboxConfig) -> Dict[str, Any]:
        """Process a single email and return event data"""
        # Extract headers
        subject = self.analyzer.decode_subject(msg.get("Subject", ""))
        sender = msg.get("From", "")
        to = msg.get("To", "")
        date_str = msg.get("Date", "")
        message_id = msg.get("Message-ID", "")
        
        # Parse date
        try:
            timestamp = parsedate_to_datetime(date_str).isoformat()
        except:
            timestamp = datetime.utcnow().isoformat()
        
        # Get body
        body = ""
        html_body = ""
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == "text/plain":
                    payload = part.get_payload(decode=True)
                    if payload:
                        body = payload.decode('utf-8', errors='replace')
                elif content_type == "text/html":
                    payload = part.get_payload(decode=True)
                    if payload:
                        html_body = payload.decode('utf-8', errors='replace')
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                body = payload.decode('utf-8', errors='replace')
        
        # Analyze for threats
        phishing_analysis = self.analyzer.check_phishing_indicators(subject, sender, body or html_body)
        attachments = self.analyzer.check_attachments(msg)
        links = self.analyzer.extract_links(html_body) if self.config.analyze_links else []
        
        # Determine event type and severity
        suspicious_attachments = [a for a in attachments if a["is_suspicious"]]
        
        if phishing_analysis["is_suspicious"]:
            event_type = "email_phishing_suspected"
            severity = "high" if phishing_analysis["phishing_score"] >= 50 else "medium"
        elif suspicious_attachments:
            event_type = "email_suspicious_attachment"
            severity = "high"
        else:
            event_type = "email_received"
            severity = "info"
        
        _, sender_email = parseaddr(sender)
        _, recipient_email = parseaddr(to)
        
        return {
            "timestamp": timestamp,
            "source": "imap_email",
            "host": mailbox.imap_server,
            "event_type": event_type,
            "severity": severity,
            "message": f"Email from {sender_email}: {subject[:100]}",
            "user": {
                "name": mailbox.email,
                "email": recipient_email,
            },
            "parsed": {
                "message_id": message_id,
                "subject": subject,
                "sender": sender,
                "sender_email": sender_email,
                "recipient": to,
                "attachments": attachments,
                "attachment_count": len(attachments),
                "suspicious_attachments": len(suspicious_attachments),
                "links_found": len(links),
                "phishing_analysis": phishing_analysis,
                "mailbox": mailbox.label or mailbox.email,
            }
        }
    
    async def check_mailbox(self, mailbox: MailboxConfig) -> List[Dict[str, Any]]:
        """Check a single mailbox for new emails"""
        events = []
        mailbox_key = self._get_mailbox_key(mailbox)
        
        try:
            conn = self.connect_imap(mailbox)
            
            for folder in mailbox.folders:
                try:
                    conn.select(folder)
                    
                    # Get last processed UID for this folder
                    folder_key = f"{mailbox_key}:{folder}"
                    last_uid = self.state.get(folder_key, 0)
                    
                    if last_uid == 0:
                        # First run - look back configured hours
                        since_date = (datetime.now() - timedelta(hours=self.config.lookback_hours))
                        search_criteria = f'SINCE {since_date.strftime("%d-%b-%Y")}'
                    else:
                        search_criteria = f'UID {last_uid + 1}:*'
                    
                    _, message_numbers = conn.search(None, search_criteria)
                    
                    if not message_numbers[0]:
                        continue
                    
                    for num in message_numbers[0].split()[-100:]:  # Limit to last 100
                        try:
                            # Get UID
                            _, uid_data = conn.fetch(num, '(UID)')
                            uid_match = re.search(r'UID (\d+)', uid_data[0].decode())
                            if uid_match:
                                uid = int(uid_match.group(1))
                                if uid <= last_uid:
                                    continue
                                self.state[folder_key] = max(self.state.get(folder_key, 0), uid)
                            
                            # Fetch email
                            _, msg_data = conn.fetch(num, '(RFC822)')
                            if msg_data[0] is None:
                                continue
                            
                            raw_email = msg_data[0][1]
                            msg = email.message_from_bytes(raw_email)
                            
                            event = self.process_email(msg, mailbox)
                            events.append(event)
                            
                        except Exception as e:
                            logger.error(f"Error processing message {num}: {e}")
                
                except Exception as e:
                    logger.error(f"Error checking folder {folder}: {e}")
            
            conn.logout()
            
        except Exception as e:
            logger.error(f"Error connecting to {mailbox.email}: {e}")
        
        return events
    
    async def run(self):
        """Main monitoring loop"""
        logger.info(f"Starting IMAP Email Monitor for {len(self.config.mailboxes)} mailbox(es)...")
        
        while self.running:
            all_events = []
            
            for mailbox in self.config.mailboxes:
                logger.info(f"Checking mailbox: {mailbox.email}")
                events = await self.check_mailbox(mailbox)
                all_events.extend(events)
            
            if all_events:
                await self.send_to_siem(all_events)
                self._save_state()
                
                # Log summary
                phishing = sum(1 for e in all_events if "phishing" in e["event_type"])
                suspicious = sum(1 for e in all_events if "suspicious" in e["event_type"])
                logger.info(f"Processed {len(all_events)} emails - {phishing} phishing, {suspicious} suspicious attachments")
            
            await asyncio.sleep(self.config.check_interval)
    
    def stop(self):
        """Stop the monitor"""
        self.running = False
        self._save_state()


async def main():
    parser = argparse.ArgumentParser(description="SecureSight IMAP Email Monitor")
    parser.add_argument("-c", "--config", required=True, help="Path to config file")
    args = parser.parse_args()
    
    config = IMAPConfig.from_file(args.config)
    monitor = IMAPEmailMonitor(config)
    
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
