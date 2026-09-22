# SOC Detection Engineering Lab - Project Report

Author: Sanika Mahamulkar, MSc Cybersecurity, University of Bristol
Repository: https://github.com/SanikaMahamulkar/soc-detection-lab
Date: September 2026

## Executive Summary

This project builds a working Security Operations Center (SOC) blue-team environment: a live SIEM, a monitored target host, real simulated attacker behaviour, and custom detection rules written, tested, and validated against that behaviour - each backed by real alert data rather than assumed coverage. It complements a separate cloud security project (aws-cloud-security-baseline) by focusing on the analyst and detection-engineering side of security operations: log analysis, rule authoring, false-positive reasoning, and structured incident response, rather than infrastructure provisioning.

Four custom, MITRE ATT&CK-mapped detection rules were built and confirmed working through live testing: unauthorized modification of /etc/passwd (persistence via account manipulation), tampering with /etc/sudoers (privilege escalation), tampering with /etc/shadow (credential access), and SSH authorized_keys tampering (persistence). The SSH key rule initially failed live testing due to a genuine configuration gap - the monitored directory list did not include /root/.ssh - which was identified and fixed before the rule was re-tested and confirmed. An attempted separate detection approach - real-time command-execution monitoring - hit a genuine platform constraint (Docker on Apple Silicon lacking kernel audit access) and is documented honestly as a limitation rather than concealed.

## Objectives

1. Deploy a working SIEM (Wazuh) via Docker Compose, with a manager, indexer, and dashboard.
2. Connect a monitored target host and verify the full logging pipeline end-to-end with real data.
3. Simulate real attacker behaviour on the target host, mapped to MITRE ATT&CK techniques.
4. Author custom detection rules for the simulated behaviour, and validate them against live testing rather than assuming they work from the rule syntax alone.
5. Document detection gaps and false-positive sources honestly, including approaches that did not work.
6. Produce structured incident response runbooks for the scenarios the detection rules cover.

## Architecture

- Wazuh 4.9.2 (manager, indexer, dashboard) deployed via Docker Compose (wazuh/) - the SIEM platform.
- A separate Ubuntu 22.04 container (soc-target) runs the Wazuh agent and acts as the monitored/attacked host, connected to the Wazuh Docker network.
- File Integrity Monitoring (FIM) on the target host watches /etc in real time (inotify-based), providing the detection substrate for the custom rules.
- Custom rules (wazuh-rules/local_rules.xml) layer MITRE ATT&CK-mapped, high-severity alerts on top of Wazuh's built-in FIM base rules for specific sensitive files: /etc/passwd, /etc/shadow, /etc/sudoers, and SSH authorized_keys files.

## Methodology

The environment was built incrementally and evidenced at each step via real command output: SIEM deployment was verified via HTTP status checks and container health; agent connectivity was verified via the manager's own agent_control tool; the logging pipeline was verified by directly querying the Wazuh indexer's API for indexed alert counts rather than trusting the dashboard UI alone.

Detection rules were not considered complete once written - each was tested against a real, live-triggered event (a genuine file modification on the target host) and confirmed present in the indexer with the correct rule ID, severity, and MITRE mapping before being considered validated.

## Detection Results

### Rule 100110: /etc/passwd tampering (T1136.001, T1098)

Triggered by appending a new account line to /etc/passwd on the target host. Confirmed alert: severity level 12, correct description, and MITRE enrichment automatically resolved by Wazuh to technique names "Local Account" and "Account Manipulation" under the Persistence tactic.

### Rule 100112: /etc/sudoers tampering (T1548.003)

Triggered by modifying /etc/sudoers on the target host. Confirmed alert: severity level 13 (the highest in this rule set), MITRE enrichment resolved to "Sudo and Sudo Caching" under both Privilege Escalation and Defense Evasion tactics.

### Rule 100111: /etc/shadow tampering (T1003.008)

Triggered by appending an entry to /etc/shadow on the target host. Confirmed alert: severity level 13, MITRE enrichment resolved to "/etc/passwd and /etc/shadow" under the Credential Access tactic.

### Rule 100113: SSH authorized_keys tampering (T1098.004)

Initial testing revealed a genuine configuration gap: /root/.ssh was not included in Wazuh's monitored directories at all (only /etc, /usr/bin, /usr/sbin, /bin, /sbin, /boot were), so this rule could never have fired regardless of its own correctness. This was fixed by adding /root/.ssh as a real-time-monitored FIM directory. After the fix, the rule was re-tested and confirmed working: severity level 12, MITRE enrichment resolved to "SSH Authorized Keys" under the Persistence tactic. All four custom rules in this project are now independently verified against live-triggered events.

## Known Limitation: Command-Execution Monitoring

A significant portion of this project's effort went into attempting real-time command-execution monitoring, to detect discovery techniques like T1087 (Account Discovery) at the moment a command runs, rather than only when a file changes as a result.

Three approaches were attempted:
1. auditd (Linux's kernel audit framework) - failed. Docker Desktop on Apple Silicon runs containers inside a lightweight Linux VM that does not expose the kernel audit netlink socket to individual containers, even with AUDIT_CONTROL and AUDIT_WRITE capabilities added at container creation. This is a platform-level constraint rather than a configuration mistake.
2. Wazuh's full_command wodle polling ps every 10 seconds - technically functioning (confirmed via agent logs) but structurally unsuited to catching short-lived commands that complete faster than the polling interval.
3. A custom bash trap DEBUG-based command logger, writing to a monitored log file - the logging mechanism itself was verified working (commands correctly captured with timestamps), and an initial timestamp-format collision with Wazuh's built-in windows-date-format decoder was identified and fixed via wazuh-logtest. Despite this, custom rules written to match the resulting log content did not produce alerts in the indexer within multiple observation windows, for reasons not fully root-caused within this project's timeframe.

This is documented in full in detection-notes.md. Rather than continuing to debug an increasingly narrow technical issue indefinitely, the decision was made to document the attempt honestly and pivot detection-engineering effort to Wazuh's natively reliable FIM capability - a deliberate engineering trade-off between chasing one blocked approach and delivering validated, working detection coverage elsewhere.

## Incident Response Runbooks

Three structured runbooks were produced, each following a standard Detection -> Triage -> Investigation -> Containment -> Eradication -> Recovery -> Lessons Learned format, directly tied to the detection rules built in this project:

1. Unauthorized Account Creation / /etc/passwd Tampering (T1136.001, T1098)
2. Privilege Escalation via /etc/sudoers Tampering (T1548.003)
3. SSH Persistence via authorized_keys Tampering (T1098.004)

See incident-response-runbooks/ for the full documents.

## False-Positive Considerations

Full reasoning is in false-positive-tuning-notes.md. Key findings: an initial rule design choice (matching only "file modified" events) produced a false negative when a monitored file did not previously exist on the host, corrected by matching the broader syscheck event group instead. Real deployment of these rules would need UID- and shell-based filtering on /etc/passwd changes specifically, since legitimate package installation routinely creates new system accounts and would otherwise generate frequent, low-value alerts alongside genuine findings.

## Conclusion

This project delivers a working SOC detection environment with real, validated evidence at each stage: a live SIEM with a connected agent, custom detection rules confirmed to fire correctly against live-triggered attacker behaviour with accurate MITRE ATT&CK enrichment, and structured incident response documentation grounded in what those rules actually detect. Where an approach did not work - command-execution monitoring without kernel audit access - that is documented plainly rather than glossed over, consistent with how a real detection engineering function should operate: distinguishing validated coverage from assumed coverage, and being explicit about the difference.

## Skills Demonstrated

- SIEM deployment and administration (Wazuh: manager, indexer, dashboard, agent architecture)
- Docker and Docker Compose for multi-service infrastructure
- Detection engineering: custom rule authoring in Wazuh's rule syntax, MITRE ATT&CK mapping
- Live validation methodology: treating "the rule is written" and "the rule is confirmed working" as distinct claims requiring separate evidence
- Systematic technical troubleshooting across a multi-layer pipeline (agent, manager, indexer, decoder, rule engine)
- Recognizing when to document a limitation and redirect effort, rather than pursuing a blocked approach indefinitely
- Incident response documentation: structured runbooks mapped to real detection capability
- False-positive analysis and detection tuning reasoning
- Clear technical writing for both technical and non-technical audiences
