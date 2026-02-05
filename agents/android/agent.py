#!/usr/bin/env python3
"""
SecureSight Android Log Agent

Collects logs from Android devices (via ADB) and sends them to the SecureSight API.

Features:
- Connects to Android devices via ADB
- Collects logcat, events, and system logs
- Parses Android log formats
- Batches and sends logs to API
- Retry mechanism with exponential backoff
- Configuration via YAML file

Requirements:
- ADB (Android Debug Bridge) must be installed and in PATH
- Device must have USB debugging enabled
- For wireless: adb tcpip must be configured
"""

import os
import sys
import time
import json
import asyncio
import logging
import argparse
import subprocess
import re
from pathlib import Path
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, AsyncIterator
import platform

import yaml
import aiohttp
from tenacity import retry, stop_after_attempt, wait_exponential

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('securesight-android-agent')


@dataclass
class DeviceConfig:
    """Configuration for an Android device"""
    device_id: str  # ADB device ID or IP:port for wireless
    friendly_name: str = ""
    include_apps: List[str] = field(default_factory=list)  # Filter by app package
    exclude_apps: List[str] = field(default_factory=list)
    log_buffers: List[str] = field(default_factory=lambda: ["main", "system", "events", "crash"])


@dataclass
class AgentConfig:
    """Agent configuration"""
    api_url: str
    api_key: str
    hostname: str = ""
    devices: List[DeviceConfig] = field(default_factory=list)
    batch_size: int = 100
    flush_interval: int = 5
    poll_interval: int = 1
    retry_attempts: int = 3
    adb_path: str = "adb"  # Path to ADB binary
    state_file: str = ""
    
    def __post_init__(self):
        if not self.state_file:
            if platform.system() == "Windows":
                self.state_file = "C:\\ProgramData\\SecureSight\\android_agent_state.json"
            else:
                self.state_file = "/var/lib/securesight/android_agent_state.json"
    
    @classmethod
    def from_file(cls, path: str) -> "AgentConfig":
        """Load configuration from YAML file"""
        with open(path, 'r') as f:
            data = yaml.safe_load(f)
        
        devices = [
            DeviceConfig(**dev) for dev in data.get('devices', [])
        ]
        
        return cls(
            api_url=data['api_url'],
            api_key=data['api_key'],
            hostname=data.get('hostname', platform.node()),
            devices=devices,
            batch_size=data.get('batch_size', 100),
            flush_interval=data.get('flush_interval', 5),
            poll_interval=data.get('poll_interval', 1),
            retry_attempts=data.get('retry_attempts', 3),
            adb_path=data.get('adb_path', 'adb'),
            state_file=data.get('state_file', ''),
        )


# Android Security Event Types
ANDROID_SECURITY_EVENTS = {
    # Authentication
    "unlock_success": ("auth_success", "Device unlocked successfully"),
    "unlock_failed": ("auth_failure", "Device unlock failed"),
    "biometric_success": ("auth_success", "Biometric authentication successful"),
    "biometric_failure": ("auth_failure", "Biometric authentication failed"),
    
    # App Events
    "app_installed": ("app_install", "Application installed"),
    "app_uninstalled": ("app_uninstall", "Application uninstalled"),
    "app_updated": ("app_update", "Application updated"),
    "permission_granted": ("permission_change", "Permission granted to app"),
    "permission_denied": ("permission_change", "Permission denied to app"),
    
    # System Events
    "boot_completed": ("system_start", "Device boot completed"),
    "shutdown": ("system_shutdown", "Device shutting down"),
    "battery_low": ("system_warning", "Battery low"),
    "storage_low": ("system_warning", "Storage space low"),
    
    # Security Events
    "selinux_denial": ("security_violation", "SELinux denial"),
    "root_detected": ("security_violation", "Root access detected"),
    "developer_mode": ("config_change", "Developer options changed"),
    "usb_debugging": ("config_change", "USB debugging state changed"),
}


class AndroidLogParser:
    """Parses Android logcat output"""
    
    # Logcat pattern: 01-01 00:00:00.000 PID TID LEVEL TAG: message
    LOGCAT_PATTERN = re.compile(
        r'^(?P<month>\d{2})-(?P<day>\d{2})\s+'
        r'(?P<time>\d{2}:\d{2}:\d{2}\.\d{3})\s+'
        r'(?P<pid>\d+)\s+(?P<tid>\d+)\s+'
        r'(?P<level>[VDIWEF])\s+'
        r'(?P<tag>[^:]+):\s*'
        r'(?P<message>.*)$'
    )
    
    # Threadtime format (more detailed)
    THREADTIME_PATTERN = re.compile(
        r'^(?P<date>\d{4}-\d{2}-\d{2})\s+'
        r'(?P<time>\d{2}:\d{2}:\d{2}\.\d{3})\s+'
        r'(?P<pid>\d+)\s+(?P<tid>\d+)\s+'
        r'(?P<level>[VDIWEF])\s+'
        r'(?P<tag>[^:]+):\s*'
        r'(?P<message>.*)$'
    )
    
    # Event log pattern
    EVENT_PATTERN = re.compile(
        r'^(?P<timestamp>\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3})\s+'
        r'(?P<pid>\d+)\s+(?P<tid>\d+)\s+'
        r'I\s+(?P<tag>[^:]+):\s*'
        r'\[(?P<event_id>\d+),(?P<event_data>.*)\]$'
    )
    
    LEVEL_MAP = {
        'V': 'verbose',
        'D': 'debug',
        'I': 'info',
        'W': 'warning',
        'E': 'error',
        'F': 'fatal',
    }
    
    SEVERITY_MAP = {
        'V': 'info',
        'D': 'info',
        'I': 'info',
        'W': 'low',
        'E': 'medium',
        'F': 'high',
    }
    
    # Security-related tags that warrant higher attention
    SECURITY_TAGS = {
        'SELinux', 'PackageManager', 'ActivityManager', 'KeyguardManager',
        'FingerprintService', 'BiometricService', 'CryptdConnector',
        'Vold', 'SecurityManager', 'DevicePolicyManager', 'Magisk', 'SuperSU',
    }
    
    @classmethod
    def parse_line(cls, line: str, device_id: str, buffer: str = "main") -> Optional[Dict]:
        """Parse a single logcat line"""
        line = line.strip()
        if not line:
            return None
        
        # Try threadtime format first (year included)
        match = cls.THREADTIME_PATTERN.match(line)
        if match:
            data = match.groupdict()
            timestamp = f"{data['date']}T{data['time']}"
        else:
            # Try standard logcat format
            match = cls.LOGCAT_PATTERN.match(line)
            if match:
                data = match.groupdict()
                year = datetime.now().year
                timestamp = f"{year}-{data['month']}-{data['day']}T{data['time']}"
            else:
                # Unrecognized format - still log it
                return {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "source": f"android_{buffer}",
                    "host": device_id,
                    "event_type": "raw_log",
                    "message": line[:2000],
                    "severity": "info",
                    "raw": line,
                    "parsed": {},
                }
        
        level = data.get('level', 'I')
        tag = data.get('tag', '').strip()
        message = data.get('message', '').strip()
        
        # Determine severity
        severity = cls.SEVERITY_MAP.get(level, 'info')
        
        # Boost severity for security-related tags
        if tag in cls.SECURITY_TAGS:
            if severity == 'info':
                severity = 'low'
            elif severity == 'low':
                severity = 'medium'
        
        # Check for security events in message
        event_type = "android_log"
        for event_key, (evt_type, _) in ANDROID_SECURITY_EVENTS.items():
            if event_key.lower() in message.lower() or event_key.lower() in tag.lower():
                event_type = evt_type
                if severity == 'info':
                    severity = 'low'
                break
        
        return {
            "timestamp": timestamp,
            "source": f"android_{buffer}",
            "host": device_id,
            "event_type": event_type,
            "message": message[:2000],
            "severity": severity,
            "raw": line,
            "parsed": {
                "pid": int(data.get('pid', 0)),
                "tid": int(data.get('tid', 0)),
                "level": cls.LEVEL_MAP.get(level, 'unknown'),
                "tag": tag,
                "buffer": buffer,
            },
        }


class ADBClient:
    """Client for interacting with Android devices via ADB"""
    
    def __init__(self, adb_path: str = "adb"):
        self.adb_path = adb_path
        self._verify_adb()
    
    def _verify_adb(self):
        """Verify ADB is available"""
        try:
            result = subprocess.run(
                [self.adb_path, "version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode != 0:
                raise RuntimeError(f"ADB error: {result.stderr}")
            logger.info(f"ADB available: {result.stdout.split()[4] if len(result.stdout.split()) > 4 else 'unknown version'}")
        except FileNotFoundError:
            raise RuntimeError(f"ADB not found at '{self.adb_path}'. Please install Android SDK Platform-Tools.")
    
    def list_devices(self) -> List[Dict[str, str]]:
        """List connected Android devices"""
        result = subprocess.run(
            [self.adb_path, "devices", "-l"],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        devices = []
        for line in result.stdout.strip().split('\n')[1:]:  # Skip header
            if line.strip() and 'device' in line:
                parts = line.split()
                device_id = parts[0]
                model = ""
                for part in parts:
                    if part.startswith("model:"):
                        model = part.split(":")[1]
                        break
                devices.append({"id": device_id, "model": model})
        
        return devices
    
    def get_device_info(self, device_id: str) -> Dict[str, str]:
        """Get device information"""
        info = {}
        
        props = ["ro.product.model", "ro.product.brand", "ro.build.version.release", 
                 "ro.build.version.sdk", "ro.serialno"]
        
        for prop in props:
            result = subprocess.run(
                [self.adb_path, "-s", device_id, "shell", "getprop", prop],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                info[prop.split(".")[-1]] = result.stdout.strip()
        
        return info
    
    async def stream_logcat(
        self, 
        device_id: str, 
        buffer: str = "main",
        format: str = "threadtime"
    ) -> AsyncIterator[str]:
        """Stream logcat output from device"""
        cmd = [
            self.adb_path, "-s", device_id, "logcat",
            "-b", buffer,
            "-v", format,
        ]
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        try:
            while True:
                line = await process.stdout.readline()
                if not line:
                    break
                yield line.decode('utf-8', errors='replace')
        finally:
            process.terminate()
            await process.wait()
    
    def clear_logcat(self, device_id: str, buffer: str = "all"):
        """Clear logcat buffer"""
        subprocess.run(
            [self.adb_path, "-s", device_id, "logcat", "-b", buffer, "-c"],
            capture_output=True,
            timeout=10
        )
    
    def get_recent_logs(self, device_id: str, buffer: str = "main", lines: int = 1000) -> List[str]:
        """Get recent log lines (non-streaming)"""
        result = subprocess.run(
            [self.adb_path, "-s", device_id, "logcat", "-b", buffer, 
             "-v", "threadtime", "-d", "-t", str(lines)],
            capture_output=True,
            text=True,
            timeout=60
        )
        
        if result.returncode != 0:
            logger.error(f"Failed to get logs: {result.stderr}")
            return []
        
        return result.stdout.strip().split('\n')


class SecureSightAndroidAgent:
    """SecureSight agent for Android device monitoring"""
    
    def __init__(self, config: AgentConfig):
        self.config = config
        self.adb = ADBClient(config.adb_path)
        self.running = True
        self.log_buffer: List[Dict] = []
        self.last_flush = time.time()
        self.session: Optional[aiohttp.ClientSession] = None
        self.state: Dict[str, Any] = {}
    
    def load_state(self):
        """Load agent state from file"""
        state_path = Path(self.config.state_file)
        if state_path.exists():
            try:
                with open(state_path, 'r') as f:
                    self.state = json.load(f)
                logger.info(f"Loaded state from {state_path}")
            except Exception as e:
                logger.warning(f"Failed to load state: {e}")
                self.state = {}
    
    def save_state(self):
        """Save agent state to file"""
        state_path = Path(self.config.state_file)
        try:
            state_path.parent.mkdir(parents=True, exist_ok=True)
            with open(state_path, 'w') as f:
                json.dump(self.state, f, indent=2)
        except Exception as e:
            logger.warning(f"Failed to save state: {e}")
    
    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=10))
    async def send_logs(self, logs: List[Dict]) -> bool:
        """Send logs to SecureSight API"""
        if not logs:
            return True
        
        if not self.session:
            self.session = aiohttp.ClientSession()
        
        headers = {
            "X-API-Key": self.config.api_key,
            "Content-Type": "application/json",
        }
        
        try:
            async with self.session.post(
                f"{self.config.api_url}/api/v1/logs/ingest/bulk",
                json={"events": logs},
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=30)
            ) as response:
                if response.status == 200:
                    logger.info(f"Successfully sent {len(logs)} logs")
                    return True
                else:
                    error = await response.text()
                    logger.error(f"Failed to send logs: {response.status} - {error}")
                    return False
        except Exception as e:
            logger.error(f"Error sending logs: {e}")
            raise
    
    async def flush_buffer(self):
        """Flush log buffer to API"""
        if not self.log_buffer:
            return
        
        logs_to_send = self.log_buffer[:self.config.batch_size]
        self.log_buffer = self.log_buffer[self.config.batch_size:]
        
        try:
            await self.send_logs(logs_to_send)
            self.last_flush = time.time()
        except Exception as e:
            # On failure, put logs back in buffer (at the front)
            self.log_buffer = logs_to_send + self.log_buffer
            logger.error(f"Failed to flush buffer: {e}")
    
    async def process_device(self, device: DeviceConfig):
        """Process logs from a single device"""
        device_id = device.device_id
        logger.info(f"Starting log collection for device: {device_id}")
        
        try:
            # Get device info
            device_info = self.adb.get_device_info(device_id)
            logger.info(f"Device info: {device_info}")
            
            # Process each log buffer
            for buffer in device.log_buffers:
                try:
                    # Get recent logs
                    lines = self.adb.get_recent_logs(device_id, buffer, lines=500)
                    
                    for line in lines:
                        parsed = AndroidLogParser.parse_line(line, device_id, buffer)
                        if parsed:
                            # Apply filters
                            if device.include_apps:
                                tag = parsed.get("parsed", {}).get("tag", "")
                                if not any(app in tag for app in device.include_apps):
                                    continue
                            
                            if device.exclude_apps:
                                tag = parsed.get("parsed", {}).get("tag", "")
                                if any(app in tag for app in device.exclude_apps):
                                    continue
                            
                            # Add device info
                            parsed["device_info"] = device_info
                            
                            self.log_buffer.append(parsed)
                            
                            # Flush if buffer is full
                            if len(self.log_buffer) >= self.config.batch_size:
                                await self.flush_buffer()
                    
                    logger.info(f"Processed {len(lines)} lines from {buffer} buffer")
                    
                except Exception as e:
                    logger.error(f"Error processing buffer {buffer}: {e}")
            
        except Exception as e:
            logger.error(f"Error processing device {device_id}: {e}")
    
    async def run(self):
        """Main agent loop"""
        logger.info("Starting SecureSight Android Agent")
        self.load_state()
        
        # Verify devices
        connected = self.adb.list_devices()
        logger.info(f"Connected devices: {connected}")
        
        if not connected and not self.config.devices:
            logger.error("No devices connected and no devices configured")
            return
        
        # Use configured devices or auto-detect
        devices = self.config.devices
        if not devices:
            devices = [DeviceConfig(device_id=d["id"], friendly_name=d.get("model", "")) 
                      for d in connected]
        
        try:
            while self.running:
                # Process all devices
                for device in devices:
                    if not self.running:
                        break
                    await self.process_device(device)
                
                # Flush remaining logs
                await self.flush_buffer()
                
                # Save state
                self.save_state()
                
                # Wait before next poll
                if self.running:
                    await asyncio.sleep(self.config.poll_interval)
                
        except asyncio.CancelledError:
            logger.info("Agent cancelled")
        finally:
            # Final flush
            await self.flush_buffer()
            self.save_state()
            
            if self.session:
                await self.session.close()
            
            logger.info("Android Agent stopped")
    
    def stop(self):
        """Stop the agent"""
        self.running = False


async def main():
    parser = argparse.ArgumentParser(description='SecureSight Android Log Agent')
    parser.add_argument('-c', '--config', required=True, help='Path to configuration file')
    parser.add_argument('--list-devices', action='store_true', help='List connected devices and exit')
    args = parser.parse_args()
    
    if args.list_devices:
        adb = ADBClient()
        devices = adb.list_devices()
        print("\nConnected Android Devices:")
        print("-" * 50)
        for device in devices:
            info = adb.get_device_info(device["id"])
            print(f"  ID: {device['id']}")
            print(f"  Model: {info.get('model', 'Unknown')}")
            print(f"  Brand: {info.get('brand', 'Unknown')}")
            print(f"  Android: {info.get('release', 'Unknown')}")
            print(f"  SDK: {info.get('sdk', 'Unknown')}")
            print("-" * 50)
        return
    
    config = AgentConfig.from_file(args.config)
    agent = SecureSightAndroidAgent(config)
    
    # Handle signals
    import signal
    def signal_handler(sig, frame):
        logger.info("Shutdown signal received")
        agent.stop()
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    await agent.run()


if __name__ == "__main__":
    asyncio.run(main())
