# SecureSight Android Agent

Collect security logs from Android devices and send them to the SecureSight SIEM platform.

## Features

- **ADB-based Collection**: Connects to Android devices via USB or wireless ADB
- **Multiple Log Buffers**: Collects from main, system, events, and crash buffers
- **Android Log Parsing**: Parses logcat format with tag, priority, and message extraction
- **Security Event Detection**: Identifies authentication, app install/uninstall, and security violations
- **App Filtering**: Include or exclude specific applications from monitoring
- **Batch Processing**: Efficient batched log transmission
- **Retry Mechanism**: Automatic retry with exponential backoff
- **State Persistence**: Remembers position across restarts

## Requirements

- Python 3.9+
- ADB (Android Debug Bridge) installed and in PATH
- Android device with USB debugging enabled

## Installation

1. Install ADB (Android SDK Platform-Tools):
   - Windows: Download from https://developer.android.com/studio/releases/platform-tools
   - Linux: `sudo apt install adb`
   - macOS: `brew install android-platform-tools`

2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Configure the agent:
   ```bash
   cp agent.yaml.example agent.yaml
   # Edit agent.yaml with your settings
   ```

## Device Setup

### USB Connection

1. Enable Developer Options on Android device:
   - Go to Settings > About Phone
   - Tap "Build Number" 7 times

2. Enable USB Debugging:
   - Go to Settings > Developer Options
   - Enable "USB Debugging"

3. Connect device and authorize:
   ```bash
   adb devices
   # Accept the authorization prompt on the device
   ```

### Wireless Connection

1. Connect device via USB first
2. Enable wireless debugging:
   ```bash
   adb tcpip 5555
   adb connect 192.168.1.100:5555  # Replace with device IP
   ```

## Usage

### List Connected Devices

```bash
python agent.py --list-devices
```

### Run the Agent

```bash
python agent.py -c agent.yaml
```

### Run as Service (Windows)

Use NSSM (Non-Sucking Service Manager):
```cmd
nssm install SecureSightAndroidAgent python.exe "C:\path\to\agent.py" -c "C:\path\to\agent.yaml"
nssm start SecureSightAndroidAgent
```

### Run as Service (Linux)

Create systemd service file `/etc/systemd/system/securesight-android.service`:
```ini
[Unit]
Description=SecureSight Android Agent
After=network.target

[Service]
Type=simple
User=securesight
ExecStart=/usr/bin/python3 /opt/securesight/agents/android/agent.py -c /etc/securesight/android-agent.yaml
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable securesight-android
sudo systemctl start securesight-android
```

## Configuration

| Setting | Description | Default |
|---------|-------------|---------|
| `api_url` | SecureSight API URL | Required |
| `api_key` | API authentication key | Required |
| `hostname` | Agent hostname identifier | System hostname |
| `devices` | List of devices to monitor | Auto-detect |
| `batch_size` | Logs per batch | 100 |
| `flush_interval` | Seconds between flushes | 5 |
| `poll_interval` | Seconds between full collections | 10 |

### Device Configuration

```yaml
devices:
  - device_id: "emulator-5554"      # ADB device ID
    friendly_name: "Test Device"     # Display name
    include_apps:                    # Only these apps (empty = all)
      - "com.mycompany.app"
    exclude_apps:                    # Skip these apps
      - "com.android.launcher"
    log_buffers:                     # Which buffers to collect
      - "main"
      - "system"
      - "events"
      - "crash"
```

## Collected Events

### Security Events
- Authentication success/failure
- Biometric authentication
- Device lock/unlock attempts

### App Events
- App install/uninstall/update
- Permission grants/denials

### System Events
- Boot/shutdown
- Configuration changes
- SELinux denials
- Developer mode changes

## Troubleshooting

### "ADB not found"
Ensure ADB is installed and in your PATH:
```bash
adb version
```

### "Device unauthorized"
Accept the USB debugging authorization on the Android device.

### "Device offline"
Reconnect the device:
```bash
adb kill-server
adb devices
```

### High CPU usage
Increase `poll_interval` to reduce collection frequency.

## Security Considerations

- Store API keys securely (use environment variables in production)
- Use encrypted connections (HTTPS) for API communication
- Limit USB debugging to trusted computers
- Consider using wireless ADB only on trusted networks

## License

See main project LICENSE file.
