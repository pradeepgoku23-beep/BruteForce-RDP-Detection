# RDP Brute-Force Detection (Windows Security + Splunk)

## Summary
Detect repeated failed RDP logons (Event ID 4625) on a Windows VM and visualize them in Splunk. Evidence includes Event Viewer, PowerShell queries, and a Splunk dashboard panel.

## Lab Topology
- Windows 11 VM (victim): RDP enabled, logs to Security.
- Kali Linux VM (attacker): sends RDP auth attempts via xfreerdp.
- Splunk on Windows (trial): used for search and a simple dashboard panel.

## Detection Logic
- Windows records failed RDP logons as **Event ID 4625** (and sometimes 4771).
- We query Security logs and count attempts by Account / IP / Host to spot brute-force patterns.

## How I Verified
- **Event Viewer**: 4625 entries show Account, Workstation, Source IP, Status.
- **PowerShell** (sample):
  ```powershell
  Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} |
    Select-Object TimeCreated,
                  @{Name="Account";Expression={$_.Properties[5].Value}},
                  @{Name="IP";Expression={$_.Properties[19].Value}},
                  @{Name="FailureReason";Expression={$_.Properties[23].Value}} |
    Sort-Object TimeCreated -Desc | Select -First 10

Splunk search (example):

index=* sourcetype="WinEventLog:Security" EventCode=4625
| stats count by Account_Name, Workstation_Name, source_network_address
| sort - count


Files & Screenshots

query.txt – SPL used.

rdp_watch.ps1, rdp_alerts.log (optional local detector and log).

screenshots/

eventviewer_4625_detail.png – single 4625 with IP, account, status.

eventviewer_4625_list.png – many 4625s in list view.

splunk_failed_logons_4625.png or splunk_4625.png – Splunk results.

brute_force_dashboard.png – dashboard panel.

powershell_4625.png – PowerShell query output.

splunk_broad_winlogs.png – proof Windows logs are indexed.



How to Reproduce (short)

1. Enable RDP on Windows; ensure Security logging is enabled.


2. From Kali, attempt RDP auth with wrong password:

xfreerdp /v:<Windows-IP> /u:TEST /p:WrongPass123 /cert-ignore


3. Confirm 4625 in Event Viewer / PowerShell.


4. In Splunk, run the 4625 search and view the panel.



Notes / Limitations

Splunk trial may limit alerting; this project focuses on detection & visibility.


All activity performed in an isolated lab VM network.

**Highlights**
- Detects repeated failed RDP logons (**Event ID 4625**).
- PowerShell watcher script + sample alert log.
- Splunk search and dashboard panel with screenshots.
- Fully reproducible steps in a home lab (Windows VM + Kali).
