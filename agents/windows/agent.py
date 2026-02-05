#!/usr/bin/env python3
"""
SecureSight Windows Log Agent

Collects Windows Event Logs and sends them to the SecureSight API.

Features:
- Reads Windows Event Logs (Security, System, Application)
- Parses event data
- Batches and sends logs to API
- Retry mechanism with exponential backoff
- Configuration via YAML file
"""

import os
import sys
import time
import json
import asyncio
import logging
import argparse
from pathlib import Path
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any

import yaml
import aiohttp
from tenacity import retry, stop_after_attempt, wait_exponential

# Windows-specific imports
try:
    import win32evtlog
    import win32evtlogutil
    import win32con
    import win32security
    WINDOWS_AVAILABLE = True
except ImportError:
    WINDOWS_AVAILABLE = False
    print("Warning: pywin32 not available. Running in simulation mode.")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('securesight-windows-agent')


@dataclass
class EventLogConfig:
    """Configuration for an event log"""
    name: str  # Security, System, Application, etc.
    event_types: List[int] = field(default_factory=lambda: [
        win32evtlog.EVENTLOG_ERROR_TYPE if WINDOWS_AVAILABLE else 1,
        win32evtlog.EVENTLOG_WARNING_TYPE if WINDOWS_AVAILABLE else 2,
        win32evtlog.EVENTLOG_INFORMATION_TYPE if WINDOWS_AVAILABLE else 4,
        win32evtlog.EVENTLOG_AUDIT_SUCCESS if WINDOWS_AVAILABLE else 8,
        win32evtlog.EVENTLOG_AUDIT_FAILURE if WINDOWS_AVAILABLE else 16,
    ])


@dataclass
class AgentConfig:
    """Agent configuration"""
    api_url: str
    api_key: str
    hostname: str = ""
    event_logs: List[EventLogConfig] = field(default_factory=list)
    batch_size: int = 100
    flush_interval: int = 5
    poll_interval: int = 1
    retry_attempts: int = 3
    state_file: str = "C:\\ProgramData\\SecureSight\\agent_state.json"
    
    @classmethod
    def from_file(cls, path: str) -> "AgentConfig":
        """Load configuration from YAML file"""
        with open(path, 'r') as f:
            data = yaml.safe_load(f)
        
        event_logs = [
            EventLogConfig(**el) for el in data.get('event_logs', [
                {'name': 'Security'},
                {'name': 'System'},
                {'name': 'Application'},
            ])
        ]
        
        import socket
        return cls(
            api_url=data['api_url'],
            api_key=data['api_key'],
            hostname=data.get('hostname', socket.gethostname()),
            event_logs=event_logs,
            batch_size=data.get('batch_size', 100),
            flush_interval=data.get('flush_interval', 5),
            poll_interval=data.get('poll_interval', 1),
            retry_attempts=data.get('retry_attempts', 3),
            state_file=data.get('state_file', 'C:\\ProgramData\\SecureSight\\agent_state.json'),
        )


# Security Event IDs and their meanings
SECURITY_EVENT_MAP = {
    # Logon/Logoff
    4624: ("auth_success", "An account was successfully logged on"),
    4625: ("auth_failure", "An account failed to log on"),
    4634: ("logoff", "An account was logged off"),
    4647: ("logoff", "User initiated logoff"),
    4648: ("auth_attempt", "A logon was attempted using explicit credentials"),
    
    # Account Management
    4720: ("account_created", "A user account was created"),
    4722: ("account_enabled", "A user account was enabled"),
    4723: ("password_change", "An attempt was made to change an account's password"),
    4724: ("password_reset", "An attempt was made to reset an account's password"),
    4725: ("account_disabled", "A user account was disabled"),
    4726: ("account_deleted", "A user account was deleted"),
    4738: ("account_changed", "A user account was changed"),
    4740: ("account_lockout", "A user account was locked out"),
    
    # Privilege Use
    4672: ("privilege_assigned", "Special privileges assigned to new logon"),
    4673: ("privilege_use", "A privileged service was called"),
    4674: ("privilege_use", "An operation was attempted on a privileged object"),
    
    # Object Access
    4663: ("file_access", "An attempt was made to access an object"),
    4656: ("handle_request", "A handle to an object was requested"),
    4658: ("handle_closed", "The handle to an object was closed"),
    
    # Policy Changes
    4719: ("policy_change", "System audit policy was changed"),
    4739: ("policy_change", "Domain Policy was changed"),
    
    # System Events
    4608: ("system_start", "Windows is starting up"),
    4609: ("system_shutdown", "Windows is shutting down"),
    4616: ("time_change", "The system time was changed"),
    
    # Process Events
    4688: ("process_created", "A new process has been created"),
    4689: ("process_terminated", "A process has exited"),
}


class WindowsEventParser:
    """Parses Windows Event Log entries"""
    
    @staticmethod
    def get_event_type_name(event_type: int) -> str:
        """Get human-readable event type name"""
        if not WINDOWS_AVAILABLE:
            return "unknown"
        
        type_map = {
            win32evtlog.EVENTLOG_ERROR_TYPE: "error",
            win32evtlog.EVENTLOG_WARNING_TYPE: "warning",
            win32evtlog.EVENTLOG_INFORMATION_TYPE: "info",
            win32evtlog.EVENTLOG_AUDIT_SUCCESS: "audit_success",
            win32evtlog.EVENTLOG_AUDIT_FAILURE: "audit_failure",
        }
        return type_map.get(event_type, "unknown")
    
    @staticmethod
    def get_severity(event_type: int, event_id: int) -> str:
        """Determine severity based on event type and ID"""
        if not WINDOWS_AVAILABLE:
            return "info"
        
        # Audit failures are high severity
        if event_type == win32evtlog.EVENTLOG_AUDIT_FAILURE:
            return "high"
        
        # Errors
        if event_type == win32evtlog.EVENTLOG_ERROR_TYPE:
            return "medium"
        
        # Warnings
        if event_type == win32evtlog.EVENTLOG_WARNING_TYPE:
            return "low"
        
        # Security-related events
        if event_id in [4625, 4740, 4726]:  # Failed logon, lockout, deletion
            return "high"
        if event_id in [4724, 4738]:  # Password reset, account change
            return "medium"
        
        return "info"
    
    @classmethod
    def parse_event(cls, event, log_name: str, hostname: str) -> Optional[Dict]:
        """Parse a Windows event log entry"""
        if not WINDOWS_AVAILABLE:
            return None
        
        try:
            event_id = event.EventID & 0xFFFF  # Mask to get actual event ID
            event_type = event.EventType
            
            # Get event metadata
            event_info = SECURITY_EVENT_MAP.get(event_id, ("other", ""))
            event_type_name, description = event_info
            
            # Get message
            try:
                message = win32evtlogutil.SafeFormatMessage(event, log_name)
            except Exception:
                message = " | ".join(event.StringInserts) if event.StringInserts else ""
            
            # Build parsed data
            parsed = {
                "event_id": event_id,
                "event_type": cls.get_event_type_name(event_type),
                "source_name": event.SourceName,
                "category": event.EventCategory,
                "record_number": event.RecordNumber,
            }
            
            # Extract strings from event
            if event.StringInserts:
                strings = event.StringInserts
                parsed["strings"] = strings[:10]  # Limit to first 10
                
                # Try to extract username and domain
                if len(strings) >= 6 and log_name == "Security":
                    parsed["user"] = strings[5] if strings[5] else None
                    parsed["domain"] = strings[6] if len(strings) > 6 else None
                
                # Try to extract IP for logon events
                if event_id in [4624, 4625] and len(strings) >= 19:
                    parsed["source_ip"] = strings[18] if strings[18] else None
            
            # Extract SID if available
            if event.Sid:
                try:
                    parsed["sid"] = win32security.ConvertSidToStringSid(event.Sid)
                except Exception:
                    pass
            
            return {
                "timestamp": event.TimeGenerated.isoformat(),
                "source": f"windows_{log_name.lower()}",
                "host": hostname,
                "event_type": event_type_name,
                "message": message[:2000] if message else description,
                "severity": cls.get_severity(event_type, event_id),
                "raw": str(event.StringInserts),
                "parsed": parsed,
                "tags": [log_name.lower(), f"event_{event_id}"],
            }
            
        except Exception as e:
            logger.error(f"Failed to parse event: {e}")
            return None


class SecureSightWindowsAgent:
    """Main Windows agent class"""
    
    def __init__(self, config: AgentConfig):
        self.config = config
        self.log_buffer: List[Dict] = []
        self.running = True
        self.last_record_numbers: Dict[str, int] = {}
        
        # Load state if exists
        self.load_state()
    
    def load_state(self):
        """Load agent state from file"""
        try:
            state_path = Path(self.config.state_file)
            if state_path.exists():
                with open(state_path, 'r') as f:
                    data = json.load(f)
                    self.last_record_numbers = data.get('last_record_numbers', {})
                logger.info("Loaded agent state")
        except Exception as e:
            logger.warning(f"Failed to load state: {e}")
    
    def save_state(self):
        """Save agent state to file"""
        try:
            state_path = Path(self.config.state_file)
            state_path.parent.mkdir(parents=True, exist_ok=True)
            with open(state_path, 'w') as f:
                json.dump({
                    'last_record_numbers': self.last_record_numbers
                }, f)
        except Exception as e:
            logger.warning(f"Failed to save state: {e}")
    
    async def read_event_log(self, log_config: EventLogConfig):
        """Read events from a Windows Event Log"""
        log_name = log_config.name
        
        if not WINDOWS_AVAILABLE:
            logger.warning("Windows Event Log API not available")
            return
        
        logger.info(f"Starting to read: {log_name}")
        
        while self.running:
            try:
                # Open event log
                handle = win32evtlog.OpenEventLog(None, log_name)
                
                try:
                    # Get flags
                    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                    
                    # Get last processed record
                    last_record = self.last_record_numbers.get(log_name, 0)
                    
                    events = []
                    while True:
                        event_batch = win32evtlog.ReadEventLog(handle, flags, 0)
                        if not event_batch:
                            break
                        
                        for event in event_batch:
                            # Skip already processed events
                            if event.RecordNumber <= last_record:
                                continue
                            
                            # Filter by event type
                            if event.EventType not in log_config.event_types:
                                continue
                            
                            # Parse event
                            parsed = WindowsEventParser.parse_event(
                                event, log_name, self.config.hostname
                            )
                            if parsed:
                                events.append(parsed)
                            
                            # Update last record
                            if event.RecordNumber > self.last_record_numbers.get(log_name, 0):
                                self.last_record_numbers[log_name] = event.RecordNumber
                        
                        # Limit batch size
                        if len(events) >= self.config.batch_size:
                            break
                    
                    # Add to buffer
                    self.log_buffer.extend(events)
                    
                    if events:
                        logger.debug(f"Read {len(events)} events from {log_name}")
                    
                finally:
                    win32evtlog.CloseEventLog(handle)
                
                # Flush if buffer is full
                if len(self.log_buffer) >= self.config.batch_size:
                    await self.flush_buffer()
                
                await asyncio.sleep(self.config.poll_interval)
                
            except Exception as e:
                logger.error(f"Error reading {log_name}: {e}")
                await asyncio.sleep(5)
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10)
    )
    async def send_logs(self, logs: List[Dict]) -> bool:
        """Send logs to the API with retry"""
        if not logs:
            return True
        
        url = f"{self.config.api_url}/api/v1/logs/ingest/bulk"
        headers = {
            "X-API-Key": self.config.api_key,
            "Content-Type": "application/json",
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                url,
                headers=headers,
                json={"events": logs},
                timeout=aiohttp.ClientTimeout(total=30),
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    logger.info(f"Sent {result.get('accepted', len(logs))} logs")
                    return True
                elif response.status == 429:
                    logger.warning("Rate limited, will retry")
                    raise Exception("Rate limited")
                else:
                    text = await response.text()
                    logger.error(f"API error: {response.status} - {text}")
                    raise Exception(f"API error: {response.status}")
    
    async def flush_buffer(self):
        """Flush log buffer to API"""
        if not self.log_buffer:
            return
        
        logs_to_send = self.log_buffer[:self.config.batch_size]
        self.log_buffer = self.log_buffer[self.config.batch_size:]
        
        try:
            await self.send_logs(logs_to_send)
            self.save_state()
        except Exception as e:
            logger.error(f"Failed to send logs: {e}")
            self.log_buffer = logs_to_send + self.log_buffer
    
    async def periodic_flush(self):
        """Periodically flush the log buffer"""
        while self.running:
            await asyncio.sleep(self.config.flush_interval)
            await self.flush_buffer()
    
    async def run(self):
        """Run the agent"""
        logger.info(f"Starting SecureSight Windows Agent on {self.config.hostname}")
        logger.info(f"API URL: {self.config.api_url}")
        logger.info(f"Monitoring {len(self.config.event_logs)} event logs")
        
        # Start event log readers
        tasks = []
        for log_config in self.config.event_logs:
            task = asyncio.create_task(self.read_event_log(log_config))
            tasks.append(task)
        
        # Start periodic flush
        tasks.append(asyncio.create_task(self.periodic_flush()))
        
        # Wait for shutdown
        try:
            while self.running:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            self.running = False
        
        # Cancel all tasks
        for task in tasks:
            task.cancel()
        
        # Final flush
        await self.flush_buffer()
        self.save_state()
        
        logger.info("Agent stopped")


def main():
    parser = argparse.ArgumentParser(description="SecureSight Windows Log Agent")
    parser.add_argument(
        "-c", "--config",
        default="C:\\ProgramData\\SecureSight\\agent.yaml",
        help="Path to configuration file"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Load configuration
    try:
        config = AgentConfig.from_file(args.config)
    except FileNotFoundError:
        logger.error(f"Configuration file not found: {args.config}")
        logger.info("Creating example configuration...")
        create_example_config(args.config)
        sys.exit(1)
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        sys.exit(1)
    
    # Run agent
    agent = SecureSightWindowsAgent(config)
    asyncio.run(agent.run())


def create_example_config(path: str):
    """Create an example configuration file"""
    example = """# SecureSight Windows Agent Configuration

# API Configuration  
api_url: "http://localhost:8000"
api_key: "your-agent-api-key"

# Optional: Override hostname (defaults to system hostname)
# hostname: "my-windows-server"

# Event logs to monitor
event_logs:
  - name: Security
  - name: System  
  - name: Application

# Batching configuration
batch_size: 100
flush_interval: 5  # seconds

# How often to poll for new events (seconds)
poll_interval: 1

# Retry configuration
retry_attempts: 3

# State file for tracking last processed events
state_file: C:\\ProgramData\\SecureSight\\agent_state.json
"""
    
    try:
        path_obj = Path(path)
        path_obj.parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'w') as f:
            f.write(example)
        logger.info(f"Example configuration written to: {path}")
    except Exception as e:
        logger.error(f"Failed to create example config: {e}")
        print(example)


if __name__ == "__main__":
    main()
