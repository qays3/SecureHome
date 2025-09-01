# SecureHome Lab - Wazuh SIEM Setup

## Architecture Overview

![Diagram](imgs/diagram.png)

**Note**: Replace `192.168.1.44` with your actual server IP address throughout this guide.

<details>
<summary><strong>📊 Click here to see detailed data collection from Windows Agent</strong></summary>

## Data Collection Overview

### Standard Agent Data

**System Information:**
- Hardware inventory (CPU, RAM, storage, network adapters)
- Operating system details and patch levels
- Installed software and packages
- Network configuration and active connections
- Running processes and services

**File Integrity Monitoring:**
- Changes to critical system directories (`C:\Windows`, `C:\Windows\System32`)
- Modifications to executable files (`.exe`, `.dll`, `.bat`, `.cmd`)
- Registry key modifications (startup entries, security policies, services)
- File creation/deletion/modification in monitored paths
- Hash calculations (MD5, SHA1, SHA256) for changed files

**Windows Event Logs:**
- **Security Events**: Logons, logoffs, privilege usage, account management
- **System Events**: Service starts/stops, system crashes, hardware changes
- **Application Events**: Software installations, crashes, errors

### EDR-Enhanced Data (via Sysmon)

**Process Monitoring:**
- Process creation and termination (Event ID 1)
- Command line arguments and parent processes
- Process image loads and DLL injections (Event ID 7)
- Process and thread access attempts (Event ID 8, 10)

**Network Activity:**
- Network connections and communications (Event ID 3)
- Source/destination IPs, ports, and protocols
- DNS queries and responses (Event ID 22)

**File System Activity:**
- File creation, modification, and deletion timestamps
- File stream creations (Event ID 15)
- Registry modifications with specific keys and values (Event ID 12, 13, 14)

**PowerShell Monitoring:**
- PowerShell script executions and commands
- PowerShell module loads and function calls
- Encoded/obfuscated command detection

### Specific Event IDs Being Monitored

**Security Log Events:**
- **4624**: Successful account logon
- **4625**: Failed account logon
- **4648**: Logon using explicit credentials
- **4688**: New process creation
- **4689**: Process termination
- **4768**: Kerberos authentication ticket requested

**Sysmon Events:**
- **Event ID 1**: Process creation
- **Event ID 3**: Network connection
- **Event ID 7**: Image loaded (DLLs)
- **Event ID 8**: CreateRemoteThread
- **Event ID 10**: ProcessAccess
- **Event ID 12-14**: Registry events
- **Event ID 15**: FileCreateStreamHash
- **Event ID 22**: DNS query

### Data Enrichment

**Contextual Information:**
- User account details and group memberships
- Geographic IP location data
- Process reputation and digital signatures
- File hash reputation checking
- Vulnerability assessments

**Behavioral Analysis:**
- Logon patterns and anomalies
- Process execution chains
- Network communication patterns
- File access patterns

### Data Storage and Retention

The collected data is:
- Indexed in Wazuh's Elasticsearch-based indexer
- Stored with timestamps and correlation IDs
- Available for real-time analysis and historical queries
- Compressed and managed according to retention policies

This comprehensive monitoring provides visibility into system activities, potential threats, and security incidents across your Windows environment while maintaining detailed audit trails for compliance and forensic analysis.

</details>

## Lab Environment

- **Host Platform**: VirtualBox
- **Server OS**: Ubuntu 22.04.5 LTS Server
- **Agent OS**: Windows with EDR capabilities
- **Wazuh Version**: 4.12.0

## Prerequisites

### Ubuntu Server Requirements
- **RAM**: Minimum 4GB (8GB recommended)
- **Storage**: 50GB minimum
- **CPU**: 2 cores minimum
- **Network**: Connectivity required

### Windows Agent Requirements
- **OS**: Any supported Windows version
- **Network**: Connectivity to Wazuh Manager
- **Access**: Administrator privileges

### VM Configuration Example
- **Hostname**: `wazuh-server`
- **Username**: `qays`
- **ISO**: [`ubuntu-22.04.5-live-server-amd64.iso`](https://releases.ubuntu.com/jammy/)



---

## VirtualBox Setup

### Resource Allocation
Configure your VM with adequate resources:

 
![VM Resources](imgs/1.png)
 
![RAM Configuration](imgs/2.png)
 
![CPU](imgs/3.png)
 
![Display settings](imgs/4.png)
 
![Sorage](imgs/5.png)
 
![Network Configuration](imgs/6.png)

### Initial Server Setup
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y net-tools curl git
ip addr show
```

---

## Installation Guide

### Phase 1: Wazuh Server Installation

#### Step 1: Download Installation Files
```bash
curl -sO https://packages.wazuh.com/4.12/wazuh-install.sh
curl -sO https://packages.wazuh.com/4.12/config.yml
```

#### Step 2: Get Server IP Address
```bash
ip addr show
```

#### Step 3: Configure Installation File
```bash
nano config.yml
```

Update with your server IP:
```yaml
nodes:
  indexer:
    - name: node-1
      ip: "192.168.1.44"
  server:
    - name: wazuh-1
      ip: "192.168.1.44"
  dashboard:
    - name: dashboard
      ip: "192.168.1.44"
```

#### Step 4: Verify System Resources
```bash
free -h  # Check RAM
df -h    # Check disk space
```

#### Step 5: Generate Security Certificates
```bash
sudo bash wazuh-install.sh --generate-config-files
```

#### Step 6: Install All Components
```bash
sudo bash wazuh-install.sh --all-in-one
```

**Installation Notes:**
- Process takes approximately 15 minutes
- UFW firewall warning expected
- Save admin credentials from output

#### Step 7: Configure Firewall
```bash
sudo ufw allow 1515/tcp  # Agent communication
sudo ufw allow 1514/tcp  # Agent data
sudo ufw allow 443/tcp   # Web interface
sudo ufw reload
```

#### Step 8: Verify Service Status
```bash
sudo systemctl status wazuh-manager
sudo systemctl status wazuh-indexer
sudo systemctl status wazuh-dashboard
sudo systemctl status filebeat
```

#### Step 9: Access Dashboard
1. Navigate to: `https://192.168.1.44:443`
2. Accept self-signed certificate
3. Login with installation credentials

**Default Credentials:**
```
Username: admin
Password: yy+kseVU0Ktn0032QXQYVTSo1g8Ee5YN
```

---

### Phase 2: Windows Agent Deployment

#### Step 1: Obtain Agent Installer
1. Access Wazuh Dashboard
2. Navigate to **Server Management > Endpoints Summary**
3. Click **Add Agent**
4. Select **Windows** platform
5. Configure:
   - Server IP: `192.168.1.44`
   - Agent Name: `Windows-Agent`
6. Copy installation command

#### Step 2: Install Agent
Run in PowerShell as Administrator:
```powershell
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.12.0-1.msi -OutFile $env:tmp\wazuh-agent; msiexec.exe /i $env:tmp\wazuh-agent /q WAZUH_MANAGER='192.168.1.44' WAZUH_AGENT_GROUP='default' WAZUH_AGENT_NAME='Windows-Agent'
```

#### Step 3: Start Agent Service
```cmd
NET START WazuhSvc
```

#### Step 4: Verify Connection
Check server for agent registration:
```bash
sudo /var/ossec/bin/agent_control -l
```

### Troubleshooting Agent Connection

#### Network Connectivity Issues
Test connection from Windows:
```powershell
Test-NetConnection -ComputerName 192.168.1.44 -Port 1514
```

#### Windows Firewall Configuration
```powershell
New-NetFirewallRule -DisplayName "Wazuh Agent" -Direction Outbound -Protocol TCP -RemotePort 1514,1515 -Action Allow
```

#### Ubuntu Firewall Verification
```bash
sudo ufw allow 1514/tcp
sudo ufw allow 1515/tcp
sudo ufw reload
```

#### Agent Service Management
```cmd
NET STOP WazuhSvc
NET START WazuhSvc
```

---

### Phase 3: EDR Configuration

#### Step 1: Install Sysmon
Download and configure Sysmon for enhanced monitoring:
```powershell
Invoke-WebRequest -Uri https://download.sysinternals.com/files/Sysmon.zip -OutFile $env:tmp\Sysmon.zip
Expand-Archive $env:tmp\Sysmon.zip $env:tmp\Sysmon
cd $env:tmp\Sysmon
.\sysmon64.exe -accepteula -i -n -l -h md5,sha256
```

#### Step 2: Configure Agent Monitoring
Create enhanced monitoring configuration:
```bash
sudo nano /var/ossec/etc/shared/default/agent.conf
```

Add monitoring configuration:
```xml
<agent_config>
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
  
  <localfile>
    <location>Microsoft-Windows-PowerShell/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
  
  <localfile>
    <location>Security</location>
    <log_format>eventchannel</log_format>
    <query>Event/System[EventID=4688 or EventID=4689 or EventID=4624 or EventID=4625 or EventID=4648 or EventID=4768]</query>
  </localfile>
</agent_config>
```

#### Step 3: Install Network Monitoring (Suricata)
Install Suricata for comprehensive network monitoring:
```bash
sudo apt update
sudo apt install suricata
sudo systemctl enable suricata
sudo systemctl start suricata
```

#### Step 4: Configure Network Log Collection
Add network monitoring to Wazuh configuration:
```bash
sudo nano /var/ossec/etc/ossec.conf
```

Add network monitoring configurations before `</ossec_config>`:
```xml
<!-- Network traffic monitoring -->
<localfile>
  <location>/var/log/suricata/eve.json</location>
  <log_format>json</log_format>
</localfile>

<!-- Syslog receiver for router logs -->
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>udp</protocol>
  <allowed-ips>192.168.1.0/24</allowed-ips>
</remote>
```

#### Step 5: Configure Router Logging (Optional)
If your router supports syslog:
1. Access router admin panel
2. Enable syslog/logging features  
3. Set syslog server to: `192.168.1.44:514`
4. Configure desired log types (connections, blocks, DHCP, etc.)

#### Step 6: Apply All Configurations
Restart services to apply changes:
```bash
sudo systemctl restart wazuh-manager
sudo systemctl restart suricata
```

#### Step 7: Update Agent Configuration
Restart Windows agent to pull new monitoring settings:
```cmd
NET STOP WazuhSvc
NET START WazuhSvc
```

#### Step 8: Verify Network Monitoring
Check if Suricata is generating logs:
```bash
ls -la /var/log/suricata/
tail -f /var/log/suricata/eve.json
```

---

## Testing and Validation

### Dashboard Verification
1. Access **Security Events** section
2. Monitor **Agents** status
3. Review **Vulnerability Detection**
4. Test **File Integrity Monitoring**

### Event Generation Testing
- Execute PowerShell commands
- Create/modify files in monitored directories
- Install/uninstall applications
- Monitor network connections

### Log Analysis
Monitor real-time events:
```bash
sudo tail -f /var/ossec/logs/ossec.log
```

---

## Maintenance and Operations

### Service Management
Check service status:
```bash
sudo systemctl status wazuh-manager wazuh-indexer wazuh-dashboard filebeat
```

### Agent Management
List all agents:
```bash
sudo /var/ossec/bin/agent_control -l
```
![Result](imgs/10.png)
![Result](imgs/11.png)


### System Recovery
After VM restart, verify all services are running. Most components auto-start, but manual intervention may be needed if:
- IP addresses change
- Services fail startup order
- Memory constraints cause issues
- Time synchronization problems occur

### Performance Monitoring
Monitor system resources:
```bash
htop
df -h
free -h
```

---

## Security Considerations

- Change default admin password
- Configure SSL certificates properly
- Implement network segmentation
- Regular backup of configuration
- Monitor system performance
- Update Wazuh components regularly

This lab provides a comprehensive SIEM solution with EDR capabilities for learning security operations, threat hunting, and incident response in a controlled environment.
