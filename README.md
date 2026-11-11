# Thread Hijacking Injection: Eliminating the Last Sysmon Detection Signal

A hands-on detection engineering lab exploring thread execution hijacking (MITRE ATT&CK [T1055.003](https://attack.mitre.org/techniques/T1055/003/)). Building on a [previous Early Bird APC injection lab](https://github.com/jfisay/earlybird-detection-lab), I tested whether injecting into an *already-running* process eliminates the parent-child mismatch that was the only detection clue Sysmon caught.

**Result:** Thread hijacking into RuntimeBroker.exe produced zero actionable Sysmon detection signals — down from two with Early Bird. Defender caught nothing. But injecting into svchost.exe triggered Defender's behavioral engine, proving that target process selection is itself a detection variable.

## Why this follows Early Bird

In the Early Bird lab, Sysmon logged two ID 1 events: the injector starting and RuntimeBroker.exe spawning with the wrong parent (earlybird.exe instead of svchost.exe). That parent-child mismatch was the **only** actionable detection signal across Sysmon and Defender.

Thread hijacking eliminates it by never creating a new process. Instead of spawning RuntimeBroker.exe, you open one that's already running — started legitimately by svchost.exe — hijack one of its threads, and inject there.

## The technique

```
CreateToolhelp32Snapshot → find running RuntimeBroker.exe
    → OpenProcess + OpenThread
    → SuspendThread
    → VirtualAllocEx(PAGE_EXECUTE_READWRITE)
    → WriteProcessMemory(shellcode)
    → GetThreadContext → save original RIP
    → SetThreadContext → redirect RIP to shellcode
    → ResumeThread
    → Injector exits. C2 lives in the hijacked thread.
```

No new process. No new thread. No CreateRemoteThread. The target process's parent stays svchost.exe.

## Lab setup

| Role | Details |
|------|---------|
| Attacker | Kali Linux, Sliver C2 with HTTPS listener |
| Target | Windows LTSC 2024, Sysmon (SwiftOnSecurity config), Defender ON |
| Network | Isolated virtual network, no internet |
| Shellcode | Sliver beacon, `--format shellcode` (~36 MB raw .bin) |
| Injector | Custom C, compiled with MinGW ([source](src/threadhijack.c)) |

## Sysmon results — RuntimeBroker.exe

| Sysmon Event | Early Bird | Thread Hijack |
|---|---|---|
| ID 1 — injector process | Logged | Logged |
| ID 1 — target with wrong parent | **Logged** | **Gone** — no new process |
| ID 8 — CreateRemoteThread | Absent | Absent |
| ID 10 — ProcessAccess | Absent | Absent |
| ID 3 — NetworkConnect (C2) | Absent | Absent |

### The injector's ID 1 event

Sysmon logged threadhijack.exe starting — same blank PE metadata as earlybird.exe (no FileVersion, Description, Product, Company, OriginalFileName). But unlike Early Bird, this event reveals **nothing about the injection target**. There's no child process, no parent-child link to RuntimeBroker.exe. A defender sees a mystery exe run for under a second and exit.

### No new RuntimeBroker.exe process creation

This is the key result. The RuntimeBroker.exe Sysmon logs show only the old Early Bird entries with their telltale wrong parents. No ID 1 event was generated for the thread-hijacked RuntimeBroker instance — because no new process was created.

### Process tree evidence

From the target's process listing after injection:

```
PID    PPID   Process
 584    452   RuntimeBroker.exe    ← legitimate (parent svchost.exe)
1304   1908   RuntimeBroker.exe    ← Early Bird (parent earlybird.exe) ⚠️
3008   7660   RuntimeBroker.exe    ← Early Bird (parent earlybird.exe) ⚠️
7680    452   RuntimeBroker.exe    ← legitimate (parent svchost.exe)
7632    452   RuntimeBroker.exe    ← THREAD HIJACK C2 (parent svchost.exe) ✓
```

PID 7632 is running our C2 beacon and is **indistinguishable** from the legitimate instances. A defender examining the process tree would see nothing suspicious. The old Early Bird beacons (PIDs 1304, 3008) still have their telltale wrong parents.

### Network events

The only ID 3 events after injection time were PowerShell downloading files from the attacker's HTTP server — the file transfer, not C2 traffic. The SwiftOnSecurity config excludes RuntimeBroker.exe from network monitoring, so the C2 beacon traffic on port 443 was invisible, same as Early Bird.

## Defender results — RuntimeBroker

- `Get-MpThreatDetection`: empty
- Defender event IDs 1116/1117: empty
- threadhijack.exe on disk: not flagged
- Shellcode .bin on disk: not flagged
- Injection execution: not blocked
- C2 beacon check-in: not detected

**Zero detections.** Same result as Early Bird — the evasion is structural, not signature-based.

## Defender results — svchost.exe (behavioral catch)

I ran the same injection against svchost.exe to compare detection outcomes across target processes. svchost.exe runs as SYSTEM, so an elevated shell was required (the first attempt as a regular user returned error 5 — Access Denied).

**Defender's behavioral engine caught this one:**

```
DetectionSourceTypeID:  0 (behavioral — not signature)
ProcessName:            svchost.exe
ThreatID:               2147842377
ActionSuccess:          True
ThreatStatusID:         4 (remediated)
```

The beacon did check in briefly (running as the SYSTEM machine account rather than a user), but Defender identified and remediated the behavioral anomaly.

### Target process comparison

| | RuntimeBroker.exe | svchost.exe |
|---|---|---|
| Files on disk | Not flagged | Not flagged |
| Injection execution | Not detected | Not detected |
| **Behavioral post-injection** | **Not detected** | **CAUGHT** |
| Remediation | None | Threat cleaned |
| Privilege level | User | SYSTEM |
| Sysmon ID 3 (C2 traffic) | Not logged | Not logged |

Same technique. Same shellcode. Same injector. Different detection outcome based **solely on target process choice**.

Defender's behavioral engine monitors svchost.exe more aggressively because it's a critical SYSTEM process. RuntimeBroker.exe, as a lower-priority user-session process, receives less behavioral scrutiny.

This explains a trend in real-world threat intelligence: sophisticated actors have moved away from svchost.exe injection toward less-monitored processes like RuntimeBroker, dllhost, and backgroundTaskHost.

## Detection guidance

### 1. ProcessAccess (ID 10) is the critical gap

OpenProcess + VirtualAllocEx + WriteProcessMemory + GetThreadContext + SetThreadContext on a remote process should generate ProcessAccess events. The SwiftOnSecurity config's filters suppress them. Hardening ID 10 to log access with `PROCESS_VM_WRITE` (0x0020) targeting system binaries would catch both Early Bird and thread hijacking.

### 2. Thread context manipulation

`SetThreadContext` / `GetThreadContext` on a remote process is highly suspicious behavior. Sysmon has no native event for this, but ETW providers and kernel callbacks can detect it. This is a gap that kernel-level EDR products fill.

### 3. RWX memory allocation in remote processes

`VirtualAllocEx` with `PAGE_EXECUTE_READWRITE` in a remote process is a strong injection indicator. Sysmon doesn't log this natively, but ETW (`Microsoft-Windows-Kernel-Memory`) can.

### 4. Anomalous thread instruction pointer

After injection, the hijacked thread's RIP points to a heap allocation instead of a legitimate code section. Memory forensics tools (Volatility, pe-sieve) can detect this, but no real-time Sysmon event covers it.

### 5. Target process selection matters for detection

Defenders should be aware that behavioral detection coverage varies by process. High-value SYSTEM processes like svchost.exe may receive more behavioral monitoring, while user-session processes like RuntimeBroker.exe may not. Detection rules should cover both tiers.

### 6. Blank PE metadata remains a signal

The injector had empty FileVersion, Description, Product, Company, and OriginalFileName fields — the same red flag as Early Bird. This is still detectable, though it only reveals the injector ran, not what it targeted.

## Bonus: process hollowing failed — and that's a finding

I also attempted classic process hollowing (T1055.012) against the same target, three ways:

1. **Raw shellcode + suspended process** — Unmapped RuntimeBroker's image, wrote shellcode at image base, resumed. Crash. The Windows loader fires kernel-mode APCs that need a valid PE for import resolution and TLS setup. Raw shellcode has no PE structure.

2. **Raw shellcode + running process** — Found a running RuntimeBroker, suspended it, unmapped its image, wrote shellcode. Silent crash. Other threads in the live process reference the original image — unmapping it destroys their exception handlers and function pointers.

3. **PE replacement + suspended process** — Built a proper PE mapper (parse headers, map 8 sections, apply relocations, update PEB ImageBaseAddress). Sliver PE allocated at its preferred base, PEB updated. Still crashed: access violation at an offset in the **original** image base range, not the new one. Modern Windows 10+ loader references the original base from kernel-mode structures that survive PEB modification.

**Detection lesson:** Simple PEB-based process hollowing that worked on Windows 7/8 no longer works reliably against modern Windows. The OS loader has structural defenses. Production tools (Cobalt Strike, Donut) use advanced techniques like transacted or phantom hollowing. For defenders: `NtUnmapViewOfSection` on a process's own image section is highly abnormal and worth alerting on.

## SYSTEM escalation: service-based injection bypasses Defender entirely

After discovering that svchost injection was caught, I explored whether SYSTEM execution could be achieved without touching svchost's memory. The answer: **yes**.

**Technique chain:**
1. `sc.exe create` — create a Windows service (legitimate admin API)
2. Service runs `suspended-ctx.exe` as NT AUTHORITY\SYSTEM
3. `suspended-ctx.exe` creates RuntimeBroker.exe suspended — inheriting the SYSTEM token
4. Shellcode injected into suspended RuntimeBroker via SetThreadContext
5. Beacon checks in as **NT AUTHORITY\SYSTEM** with full privileges

**Result:** Full SYSTEM shell inside RuntimeBroker.exe — SeDebugPrivilege, SeImpersonatePrivilege, SeTcbPrivilege, the complete set — and **zero Defender detections**.

### Comparison: three paths to SYSTEM

| Approach | Target process | SYSTEM? | Defender |
|----------|---------------|---------|----------|
| Thread hijack → svchost.exe | svchost (direct) | Yes | **CAUGHT** |
| Thread hijack → spoolsv/SearchIndexer | SYSTEM services | Injection OK, no beacon | Not detected |
| Service → suspended RuntimeBroker | RuntimeBroker (new) | Yes | **NOT DETECTED** |

### Why SYSTEM services didn't beacon

Thread hijacking into spoolsv.exe, SearchIndexer.exe, and qemu-ga.exe succeeded (all three processes survived), but no beacons checked in. These SYSTEM service threads are deep in kernel I/O wait states — the redirected RIP can't cleanly take over. RuntimeBroker's idle message-pump threads handle hijacking cleanly; active service threads don't.

### Token theft is hardened

Attempted `OpenProcessToken` on SYSTEM processes (svchost, spoolsv) with SeDebugPrivilege enabled — all returned Access Denied (error 5). Modern Windows 10+ hardens token DACLs even against admin. Service creation achieves SYSTEM through a different, auditable path.

### Detection lesson

Defender's behavioral engine is **process-name-specific, not privilege-level-specific**. A RuntimeBroker.exe running as NT AUTHORITY\SYSTEM is inherently anomalous (it normally runs as the logged-in user at Medium integrity), but Defender doesn't flag it. Defenders should monitor: service creation events (Security 4697, Sysmon 12/13) for unusual binpaths, and process tokens that don't match the expected integrity level for that process name.

## Key takeaway

Thread hijacking into RuntimeBroker.exe eliminated the **only** detection signal that Early Bird left behind (the parent-child mismatch), achieving zero actionable Sysmon events and zero Defender detections. Combining this with service-based SYSTEM escalation produces a full NT AUTHORITY\SYSTEM shell with zero detections — same result as svchost injection, which Defender caught immediately.

**Defender's behavioral monitoring is process-name-specific.** svchost.exe gets heavy scrutiny; RuntimeBroker.exe does not, even at SYSTEM integrity. For attackers, this means target process selection determines detection outcome. For defenders, it means behavioral rules must cover all process contexts, not just known high-value targets.

For defenders: if your detection strategy relies on parent-child process relationships, thread hijacking bypasses it entirely. Layer your detections across ProcessAccess (ID 10), memory allocation patterns, kernel-level thread context monitoring, and anomalous token/integrity combinations per process.

## Files

- [`src/threadhijack.c`](src/threadhijack.c) — Thread execution hijacking injector (T1055.003)
- [`src/suspended-ctx.c`](src/suspended-ctx.c) — Suspended process + SetThreadContext injection
- [`src/tokensteal.c`](src/tokensteal.c) — Token theft tool (blocked by Win10+ token hardening)
- [`src/hollow.c`](src/hollow.c) — Process hollowing, suspended process + raw shellcode (crashed)
- [`src/hollow2.c`](src/hollow2.c) — Process hollowing, running process + raw shellcode (crashed)
- [`src/pehollow.c`](src/pehollow.c) — PE hollowing with section mapping and relocations (crashed on Win10+)

## Related

- [Early Bird APC Injection Lab](https://github.com/jfisay/earlybird-detection-lab) — The predecessor lab that this one builds on

## Disclaimer

All testing was performed on owned, isolated virtual machines in a home lab for educational purposes. No traffic left the lab environment. Thread execution hijacking is publicly documented and cataloged in MITRE ATT&CK as T1055.003.
