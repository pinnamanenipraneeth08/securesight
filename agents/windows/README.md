# SecureSight Windows Agent

Collect Windows Event Logs and send them to the SecureSight SIEM platform.

## Features

- **Windows Event Log Collection**: Security, System, Application, and custom logs
- **Rich Event Parsing**: Extracts user, IP, SID, and event-specific data
- **Security Event Mapping**: Maps Windows Security Event IDs to readable types
- **Severity Classification**: Automatic severity based on event type and ID
- **Batch Processing**: Efficient batched log transmission
- **Retry Mechanism**: Automatic retry with exponential backoff
- **State Persistence**: Remembers last event record across restarts

## Requirements

- Windows 7+ / Windows Server 2012+
- Python 3.9+
- Administrator privileges (for Security log access)

## Installation

1. Install Python dependencies:
   ```cmd
   pip install -r requirements.txt
   ```

2. Configure the agent:
   ```cmd
   copy agent.yaml.example agent.yaml
   REM Edit agent.yaml with your settings
   ```

## Usage

### Run Manually

```cmd
python agent.py -c agent.yaml
```

### Run as Windows Service

Using NSSM (Non-Sucking Service Manager):

1. Download NSSM from https://nssm.cc/

2. Install service:
   ```cmd
   nssm install SecureSightAgent "C:\Python313\python.exe" "C:\SecureSight\agents\windows\agent.py" -c "C:\SecureSight\agents\windows\agent.yaml"
   ```

3. Configure service:
   ```cmd
   nssm set SecureSightAgent AppDirectory "C:\SecureSight\agents\windows"
   nssm set SecureSightAgent DisplayName "SecureSight Windows Agent"
   nssm set SecureSightAgent Description "Collects Windows Event Logs for SecureSight SIEM"
   nssm set SecureSightAgent Start SERVICE_AUTO_START
   ```

4. Start service:
   ```cmd
   nssm start SecureSightAgent
   ```

## Configuration

| Setting | Description | Default |
|---------|-------------|---------|
| `api_url` | SecureSight API URL | Required |
| `api_key` | API authentication key | Required |
| `hostname` | Agent hostname identifier | System hostname |
| `event_logs` | List of event logs to monitor | Security, System, Application |
| `batch_size` | Events per batch | 100 |
| `flush_interval` | Seconds between flushes | 5 |
| `poll_interval` | Seconds between event log polls | 1 |

## Monitored Security Events

### Logon/Logoff
| Event ID | Description |
|----------|-------------|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4634 | Logoff |
| 4647 | User initiated logoff |
| 4648 | Logon with explicit credentials |

### Account Management
| Event ID | Description |
|----------|-------------|
| 4720 | User account created |
| 4722 | User account enabled |
| 4723 | Password change attempt |
| 4724 | Password reset attempt |
| 4725 | User account disabled |
| 4726 | User account deleted |
| 4740 | Account locked out |

### Privilege Use
| Event ID | Description |
|----------|-------------|
| 4672 | Special privileges assigned |
| 4673 | Privileged service called |

### Process Events
| Event ID | Description |
|----------|-------------|
| 4688 | New process created |
| 4689 | Process exited |

### System Events
| Event ID | Description |
|----------|-------------|
| 4608 | Windows starting |
| 4609 | Windows shutting down |
| 4616 | System time changed |

## Troubleshooting

### "Access Denied" for Security log
Run the agent as Administrator or as a service under LocalSystem account.

### Missing pywin32
```cmd
pip install pywin32
python -m pywin32_postinstall -install
```

### High memory usage
Reduce `batch_size` or increase `flush_interval`.

### Events being missed
- Decrease `poll_interval`
- Check that the Windows Event Log service is running

## Security Considerations

- Run agent under a dedicated service account
- Use HTTPS for API communication
- Store API key in encrypted configuration
- Limit Event Log access to required logs only

## License

See main project LICENSE file.
