# SecureSight Email Monitoring Agents

Monitor email systems for security threats, phishing attempts, and suspicious activity.

## Available Agents

### 1. Office 365 Agent (`office365_agent.py`)

Monitors Microsoft 365 environments using Microsoft Graph API:
- **Sign-in Logs**: Track successful/failed logins, risky sign-ins
- **Security Alerts**: Microsoft 365 Defender alerts (phishing, malware)
- **Audit Logs**: Admin activities, privilege changes
- **Message Trace**: Email flow tracking

#### Setup

1. **Create Azure AD App Registration**:
   - Go to [Azure Portal](https://portal.azure.com) > Azure Active Directory > App Registrations
   - New registration → Name: "SecureSight SIEM"
   - Add API Permissions (Application type):
     - `AuditLog.Read.All`
     - `SecurityEvents.Read.All`
     - `Directory.Read.All`
   - Grant admin consent
   - Create client secret, note the values

2. **Configure the agent**:
   ```cmd
   copy office365_config.yaml.example office365_config.yaml
   # Edit with your Azure AD app credentials
   ```

3. **Run**:
   ```cmd
   pip install -r requirements.txt
   python office365_agent.py -c office365_config.yaml
   ```

---

### 2. IMAP Agent (`imap_agent.py`)

Monitors any IMAP-compatible email server:
- Gmail, Outlook, Yahoo
- Microsoft 365
- Exchange Server
- Any IMAP mail server

**Features**:
- Phishing detection (keyword analysis, sender spoofing)
- Suspicious attachment detection (executables, macros)
- Link extraction and logging
- Multi-mailbox monitoring

#### Setup

1. **For Gmail**:
   - Enable 2-Factor Authentication
   - Go to Google Account > Security > App Passwords
   - Generate password for "Mail"

2. **For Microsoft 365**:
   - Use OAuth (recommended) or App Password
   - Enable IMAP in Exchange Admin Center

3. **Configure the agent**:
   ```cmd
   copy imap_config.yaml.example imap_config.yaml
   # Edit with your mailbox credentials
   ```

4. **Run**:
   ```cmd
   pip install -r requirements.txt
   python imap_agent.py -c imap_config.yaml
   ```

---

## Event Types Generated

| Event Type | Description | Severity |
|------------|-------------|----------|
| `email_signin_success` | Successful email/Azure AD sign-in | low |
| `email_signin_failed` | Failed sign-in attempt | medium |
| `email_signin_risky` | Sign-in with risk indicators | high |
| `email_phishing_detected` | Microsoft Defender phishing alert | critical |
| `email_phishing_suspected` | IMAP agent phishing detection | high/medium |
| `email_malware_detected` | Malware detected in email | critical |
| `email_suspicious_attachment` | Dangerous attachment type | high |
| `email_dlp_violation` | Data Loss Prevention policy match | high |
| `email_admin_activity` | Admin action in email system | low |
| `email_admin_high_risk` | High-risk admin action | high |
| `email_security_alert` | Generic security alert | varies |
| `email_received` | Normal email received | info |

---

## Running as a Service

### Windows

Using NSSM:
```cmd
nssm install SecureSightEmail "C:\Python313\python.exe" "C:\SecureSight\agents\email\office365_agent.py" -c "C:\SecureSight\agents\email\office365_config.yaml"
nssm start SecureSightEmail
```

### Linux

Using systemd:
```bash
sudo cat > /etc/systemd/system/securesight-email.service << EOF
[Unit]
Description=SecureSight Email Monitor
After=network.target

[Service]
Type=simple
User=securesight
WorkingDirectory=/opt/securesight/agents/email
ExecStart=/usr/bin/python3 office365_agent.py -c office365_config.yaml
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable securesight-email
sudo systemctl start securesight-email
```

---

## Detection Rules

Add these rules in SecureSight to detect email threats:

```yaml
# Multiple failed sign-ins
- name: "Email Brute Force"
  condition: "event_type == 'email_signin_failed' AND count() > 5 within 5m group by user.email"
  severity: "high"

# Phishing detected
- name: "Phishing Email Detected"
  condition: "event_type == 'email_phishing_suspected' AND parsed.phishing_score >= 50"
  severity: "critical"
  
# Suspicious attachment
- name: "Dangerous Attachment"
  condition: "event_type == 'email_suspicious_attachment'"
  severity: "high"

# Admin privilege change
- name: "Email Admin Privilege Change"
  condition: "event_type == 'email_admin_high_risk' AND 'role' in message"
  severity: "critical"
```
