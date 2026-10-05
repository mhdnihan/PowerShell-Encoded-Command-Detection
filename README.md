# PowerShell-Encoded-Command-Detection
Investigation -- PowerShell Encoded Command Detection


**PowerShell Encoded Command Detection**

Objective

To simulate and investigate encoded PowerShell execution on a Windows 11 endpoint using Wazuh and Sysmon.

Lab Environment

* SIEM: Wazuh
* Endpoint: Windows 11
* Telemetry: Sysmon
* Detection: Sysmon Event ID 1 — Process Creation

Test Activity

A harmless PowerShell command was encoded using Base64 and executed with PowerShell’s -EncodedCommand parameter.

The test command decoded to:

Write-Host "Wazuh SOC Test"

The encoded command was executed using:

powershell.exe -EncodedCommand <Base64_String>

Detection

Wazuh monitored the PowerShell process creation through Sysmon.

Alert details:

Field	                               Value
Rule ID	                             92057
Rule Level                          	12
Event ID                             	1
Process	                      powershell.exe
Command Line	                powershell.exe -EncodedCommand ...

Investigation

The command line was examined for the use of the -EncodedCommand parameter.

Encoded PowerShell commands can be used to obscure the actual commands being executed. Therefore, the presence of -EncodedCommand is a useful indicator for further investigation.

The investigation should include:

* Decode the Base64 command
* Identify the actual command being executed
* Examine the parent process
* Identify the user account
* Check the process tree
* Review related network connections
* Review other events generated around the same timestamp

Triage

The activity was classified based on the decoded command and surrounding telemetry, rather than treating encoded PowerShell as automatically malicious.

In this controlled lab, the decoded command was a harmless test command.

SOC Workflow

Log → Detection → Alert → Triage → Decode → Investigation → Evidence → Classification → Response

Key Learning

This exercise demonstrated how Wazuh and Sysmon can be used to identify PowerShell execution and investigate potentially obfuscated command lines. It also reinforced the importance of examining the actual command, process ancestry, user context, and related telemetry before determining the significance of an alert.
