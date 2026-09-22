# Detection Engineering Notes

## Command-execution monitoring: attempted approach and known limitation

**Goal:** detect real-time command execution (e.g., `cat /etc/passwd`) to catch MITRE ATT&CK discovery techniques like T1087 (Account Discovery).

**Approach attempted:**
1. `auditd` (Linux audit framework) — failed. Docker containers on Apple Silicon (Docker Desktop's Linux VM) do not expose the kernel audit netlink socket to containers, even with `--cap-add=AUDIT_CONTROL --cap-add=AUDIT_WRITE`. This is a platform-level constraint, not a configuration error.
2. Wazuh `full_command` wodle polling `ps` every 10s — technically functional (confirmed running via agent logs), but unreliable for fast, short-lived commands that complete between polling intervals. Structurally unsuited to catching single-shot commands like `cat /etc/passwd`.
3. Bash `trap DEBUG` command logging to a custom log file, monitored by Wazuh as a `localfile` — the logging mechanism itself was verified working (commands correctly captured with timestamps in `/var/log/bash_command.log`). However, custom rules written to match this log content did not produce alerts in the indexer, despite: rules loading without XML errors, the manager restarting cleanly, and the underlying log file confirmed to contain the expected content. Initial timestamp format collided with Wazuh's built-in `windows-date-format` decoder (confirmed via `wazuh-logtest`); reformatting the log line avoided that specific collision, but alerts still did not appear in the indexer within multiple 20-30 second observation windows.

**Conclusion:** command-execution monitoring without kernel-level audit access (auditd) is a genuine constraint of this Docker-based lab environment on Apple Silicon. This is documented here as an honest limitation rather than worked around indefinitely. A production Wazuh deployment on bare-metal or a VM with full kernel access would not face the auditd restriction and could use Wazuh's audit log integration directly.

**Pivot:** detection engineering for this project instead focuses on Wazuh's natively reliable capability — File Integrity Monitoring (FIM) — which was already confirmed working end-to-end (382+ real alerts generated and indexed). FIM-based rules are used to detect tampering with sensitive files (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, SSH authorized_keys, cron files), which maps to real MITRE ATT&CK techniques around persistence and privilege escalation.
