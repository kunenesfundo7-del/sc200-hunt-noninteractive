# SC-200 Hunt → Detection: Non-Interactive Sign-In Anomaly

**Lab:** sc200-law | **Date:** 2026-10-20 | **Analyst:** Sfundo Kunene

## Executive Summary
Pivot from empty `SigninLogs` (5 logs/24h) to `AADNonInteractiveUserSignInLogs` revealed 2650 successful anomalous non-interactive logins from `41.24.136.73` peaking at 431/hr across 17 apps. Built and deployed scheduled detection with MITRE mapping and SOC-grade incident handling.

## Hunt Findings
- **Table:** `AADNonInteractiveUserSignInLogs` (139 logs last 24h, 2650 last 7d)
- **Anomaly:** IP 41.24.136.73 = 2650 success | 41.24.136.86 = correlated | Peak 431/hr | AppCount 17
- **Hypothesis:** Service principal / cloud account abuse - possible token abuse / brute force bypass

## KQL - Hunt Queries
```kusto
// Discovery - Volume by IP
AADNonInteractiveUserSignInLogs
| where ResultType == 0
| summarize HourlyCount=count(), Apps=dcount(AppDisplayName) by IPAddress, bin(TimeGenerated, 1h)
| where HourlyCount > 100
| sort by HourlyCount desc

// Final Detection Logic
AADNonInteractiveUserSignInLogs
| where ResultType == 0
| summarize HourlyCount=count() by IPAddress, UserPrincipalName, bin(TimeGenerated, 1h)
| where HourlyCount > 100
