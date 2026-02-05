#!/usr/bin/env python3
"""
SecureSight Linux Log Agent

Collects logs from Linux systems and sends them to the SecureSight API.

Features:
- Tails multiple log files
- Parses common log formats (syslog, auth, etc.)
- Batches and sends logs to API
- Retry mechanism with exponential backoff
- Configuration via YAML file
"""

import os
import sys
import time
import json
import signal
import asyncio
import logging
import argparse
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
import re
import hashlib

import yaml
import aiohttp
import aiofiles
from tenacity import retry, stop_after_attempt, wait_exponential

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('securesight-agent')


@dataclass
class LogFile:
    """Represents a log file to monitor"""
    path: str
    log_type: str = "syslog"
    encoding: str = "utf-8"
    position: int = 0
    inode: int = 0


@dataclass
class AgentConfig:
    """Agent configuration"""
    api_url: str
    api_key: str
    hostname: str = ""
    log_files: List[LogFile] = field(default_factory=list)
    batch_size: int = 100
    flush_interval: int = 5
    retry_attempts: int = 3
    state_file: str = "/var/lib/securesight/agent_state.json"
    
    @classmethod
    def from_file(cls, path: str) -> "AgentConfig":
        """Load configuration from YAML file"""
        with open(path, 'r') as f:
            data = yaml.safe_load(f)
        
        log_files = [
            LogFile(**lf) for lf in data.get('log_files', [])
        ]
        
        # Get hostname - use platform module which works on all platforms
        import platform
        default_hostname = platform.node() or os.environ.get('HOSTNAME', 'unknown')
        
        return cls(
            api_url=data['api_url'],
            api_key=data['api_key'],
            hostname=data.get('hostname', default_hostname),
            log_files=log_files,
            batch_size=data.get('batch_size', 100),
            flush_interval=data.get('flush_interval', 5),
            retry_attempts=data.get('retry_attempts', 3),
            state_file=data.get('state_file', '/var/lib/securesight/agent_state.json'),
        )


class LogParser:
    """Parses various log formats"""
    
    # Syslog pattern: Jan  1 00:00:00 hostname process[pid]: message
    SYSLOG_PATTERN = re.compile(
        r'^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
        r'(?P<hostname>\S+)\s+'
        r'(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s+'
        r'(?P<message>.*)$'
    )
    
    # Auth log patterns
    AUTH_FAILED_PATTERN = re.compile(
        r'(?:Failed password|authentication failure|FAILED LOGIN|Invalid user)'
    )
    AUTH_SUCCESS_PATTERN = re.compile(
        r'(?:Accepted password|Accepted publickey|session opened)'
    )
    SUDO_PATTERN = re.compile(
        r'sudo:\s+(?P<user>\S+)\s+:.*COMMAND=(?P<command>.+)$'
    )
    SSH_PATTERN = re.compile(
        r'(?:from|for)\s+(?:user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)'
    )
    
    @classmethod
    def parse_syslog(cls, line: str, log_type: str = "syslog") -> Optional[Dict]:
        """Parse a syslog-format line"""
        match = cls.SYSLOG_PATTERN.match(line)
        if not match:
            return None
        
        groups = match.groupdict()
        
        # Convert timestamp to ISO format
        timestamp_str = groups['timestamp']
        year = datetime.now().year
        try:
            dt = datetime.strptime(f"{year} {timestamp_str}", "%Y %b %d %H:%M:%S")
            timestamp = dt.isoformat()
        except ValueError:
            timestamp = datetime.now().isoformat()
        
        message = groups['message']
        
        # Determine event type
        event_type = cls.determine_event_type(message, log_type)
        
        # Extract additional context
        parsed = {
            "process": groups.get('process'),
            "pid": groups.get('pid'),
        }
        
        # Extract user and IP for auth events
        ssh_match = cls.SSH_PATTERN.search(message)
        if ssh_match:
            parsed['user'] = ssh_match.group('user')
            parsed['source_ip'] = ssh_match.group('ip')
        
        # Extract sudo info
        sudo_match = cls.SUDO_PATTERN.search(message)
        if sudo_match:
            parsed['sudo_user'] = sudo_match.group('user')
            parsed['command'] = sudo_match.group('command')
        
        return {
            "timestamp": timestamp,
            "source": log_type,
            "host": groups['hostname'],
            "event_type": event_type,
            "message": message,
            "severity": cls.determine_severity(event_type, message),
            "raw": line,
            "parsed": parsed,
        }
    
    @classmethod
    def determine_event_type(cls, message: str, log_type: str) -> str:
        """Determine the event type based on message content"""
        message_lower = message.lower()
        
        if cls.AUTH_FAILED_PATTERN.search(message):
            return "auth_failure"
        if cls.AUTH_SUCCESS_PATTERN.search(message):
            return "auth_success"
        if "sudo" in message_lower:
            return "privilege_escalation"
        if any(word in message_lower for word in ['error', 'failed', 'failure']):
            return "error"
        if any(word in message_lower for word in ['warning', 'warn']):
            return "warning"
        if any(word in message_lower for word in ['started', 'stopped', 'restart']):
            return "service_event"
        if "cron" in message_lower:
            return "scheduled_task"
        
        return log_type
    
    @classmethod
    def determine_severity(cls, event_type: str, message: str) -> str:
        """Determine severity level"""
        if event_type in ['auth_failure', 'privilege_escalation', 'error']:
            if 'root' in message.lower():
                return "high"
            return "medium"
        if event_type == 'warning':
            return "low"
        return "info"


class SecureSightAgent:
    """Main agent class"""
    
    def __init__(self, config: AgentConfig):
        self.config = config
        self.log_buffer: List[Dict] = []
        self.running = True
        self.watchers: Dict[str, asyncio.Task] = {}
        self.file_positions: Dict[str, Dict] = {}
        
        # Load state if exists
        self.load_state()
        
        # Setup signal handlers
        signal.signal(signal.SIGTERM, self.handle_signal)
        signal.signal(signal.SIGINT, self.handle_signal)
    
    def handle_signal(self, signum, frame):
        """Handle shutdown signals"""
        logger.info(f"Received signal {signum}, shutting down...")
        self.running = False
    
    def load_state(self):
        """Load agent state from file"""
        try:
            state_path = Path(self.config.state_file)
            if state_path.exists():
                with open(state_path, 'r') as f:
                    self.file_positions = json.load(f)
                logger.info("Loaded agent state")
        except Exception as e:
            logger.warning(f"Failed to load state: {e}")
            self.file_positions = {}
    
    def save_state(self):
        """Save agent state to file"""
        try:
            state_path = Path(self.config.state_file)
            state_path.parent.mkdir(parents=True, exist_ok=True)
            with open(state_path, 'w') as f:
                json.dump(self.file_positions, f)
        except Exception as e:
            logger.warning(f"Failed to save state: {e}")
    
    async def tail_file(self, log_file: LogFile):
        """Tail a log file and parse new lines"""
        path = log_file.path
        
        # Check if file exists
        if not os.path.exists(path):
            logger.warning(f"Log file not found: {path}")
            return
        
        # Get current file position
        state = self.file_positions.get(path, {})
        position = state.get('position', 0)
        last_inode = state.get('inode', 0)
        
        logger.info(f"Starting to tail: {path} from position {position}")
        
        while self.running:
            try:
                # Check for file rotation
                stat = os.stat(path)
                current_inode = stat.st_ino
                
                if current_inode != last_inode:
                    logger.info(f"File rotated: {path}")
                    position = 0
                    last_inode = current_inode
                
                # Read new lines
                async with aiofiles.open(path, 'r', encoding=log_file.encoding) as f:
                    await f.seek(position)
                    
                    async for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        
                        # Parse the log line
                        parsed = LogParser.parse_syslog(line, log_file.log_type)
                        if parsed:
                            # Override hostname with configured value
                            parsed['host'] = self.config.hostname
                            self.log_buffer.append(parsed)
                    
                    # Update position
                    position = await f.tell()
                    self.file_positions[path] = {
                        'position': position,
                        'inode': current_inode
                    }
                
                # Flush buffer if needed
                if len(self.log_buffer) >= self.config.batch_size:
                    await self.flush_buffer()
                
                await asyncio.sleep(0.5)
                
            except FileNotFoundError:
                logger.warning(f"File disappeared: {path}")
                await asyncio.sleep(5)
            except Exception as e:
                logger.error(f"Error tailing {path}: {e}")
                await asyncio.sleep(1)
    
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
        
        # Take current buffer and reset
        logs_to_send = self.log_buffer[:self.config.batch_size]
        self.log_buffer = self.log_buffer[self.config.batch_size:]
        
        try:
            await self.send_logs(logs_to_send)
            self.save_state()
        except Exception as e:
            logger.error(f"Failed to send logs: {e}")
            # Put logs back in buffer
            self.log_buffer = logs_to_send + self.log_buffer
    
    async def periodic_flush(self):
        """Periodically flush the log buffer"""
        while self.running:
            await asyncio.sleep(self.config.flush_interval)
            await self.flush_buffer()
    
    async def run(self):
        """Run the agent"""
        logger.info(f"Starting SecureSight Agent on {self.config.hostname}")
        logger.info(f"API URL: {self.config.api_url}")
        logger.info(f"Monitoring {len(self.config.log_files)} log files")
        
        # Start file watchers
        tasks = []
        for log_file in self.config.log_files:
            task = asyncio.create_task(self.tail_file(log_file))
            tasks.append(task)
        
        # Start periodic flush
        tasks.append(asyncio.create_task(self.periodic_flush()))
        
        # Wait for shutdown
        while self.running:
            await asyncio.sleep(1)
        
        # Cancel all tasks
        for task in tasks:
            task.cancel()
        
        # Final flush
        await self.flush_buffer()
        self.save_state()
        
        logger.info("Agent stopped")


def main():
    parser = argparse.ArgumentParser(description="SecureSight Linux Log Agent")
    parser.add_argument(
        "-c", "--config",
        default="/etc/securesight/agent.yaml",
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
    agent = SecureSightAgent(config)
    asyncio.run(agent.run())


def create_example_config(path: str):
    """Create an example configuration file"""
    example = """# SecureSight Agent Configuration

# API Configuration
api_url: "http://localhost:8000"
api_key: "your-agent-api-key"

# Optional: Override hostname (defaults to system hostname)
# hostname: "my-server"

# Log files to monitor
log_files:
  - path: /var/log/syslog
    log_type: syslog
  
  - path: /var/log/auth.log
    log_type: auth
  
  - path: /var/log/secure
    log_type: auth
  
  - path: /var/log/messages
    log_type: syslog
  
  # Add custom log files
  # - path: /var/log/myapp/app.log
  #   log_type: application

# Batching configuration
batch_size: 100
flush_interval: 5  # seconds

# Retry configuration
retry_attempts: 3

# State file for tracking file positions
state_file: /var/lib/securesight/agent_state.json
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
