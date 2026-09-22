# Detection Engineering Notes

## Command-execution monitoring: root cause found and resolved

**Goal:** detect real-time command execution (e.g., `cat /etc/passwd`) to catch MITRE ATT&CK discovery techniques like T1087 (Account Discovery).

**Approaches attempted before resolution:**
1. `auditd` (Linux audit framework) - failed. Docker containers on Apple Silicon (Docker Desktop's Linux VM) do not expose the kernel audit netlink socket to containers, even with `--cap-add=AUDIT_CONTROL --cap-add=AUDIT_WRITE`. This is a platform-level constraint, not a configuration error, and remains unresolved by design (not pursued further, since the approach below succeeded).
2. Wazuh `full_command` wodle polling `ps` every 10s - technically functional, but unreliable for fast, short-lived commands that complete between polling intervals.
3. Bash `trap DEBUG` command logging to a custom log file, monitored by Wazuh as a `localfile` - the logging mechanism itself was verified working from the start. Custom rules matching this log content initially did not produce alerts despite the underlying data being confirmed present, correctly formatted, and reaching the manager (verified via `logall` and `archives.log`).

**Root cause, found via systematic isolation:** Wazuh's default `<match>` rule syntax does not treat `.` and `*` as regex metacharacters the way standard PCRE does. A rule matching a literal substring (e.g. `<match>CMDLOG</match>`) worked correctly, but a rule using wildcard patterns (`<match>CMDLOG.*cmd=cat /etc/passwd</match>`) silently failed to match, with no error or warning anywhere in the pipeline. This was isolated by testing progressively: a minimal always-matching debug rule confirmed the pipeline and rule engine both worked; a plain-substring match confirmed basic `<match>` rules fired correctly; only the wildcard-containing pattern failed - which narrowed the fault to Wazuh's pattern-matching dialect specifically, not the data pipeline, decoder, or rule-loading process (all of which had already been separately confirmed correct in earlier debugging).

**Fix:** add the `type="pcre2"` attribute to any `<match>` rule using real regex wildcards, e.g. `<match type="pcre2">CMDLOG.*cmd=cat /etc/passwd</match>`. This switches Wazuh to standard PCRE2 regex evaluation. Re-tested and confirmed working immediately.

**Result:** three command-execution detection rules are now live and confirmed working:
- Rule 100120 (T1087.001 - Account Discovery): detects `cat /etc/passwd` via command logging
- Rule 100121 (T1082 - System Information Discovery): detects `uname -a`, `cat /etc/os-release`, `hostnamectl`
- Rule 100122 (T1069.001 - Permission Groups Discovery): detects `cat /etc/sudoers`, `sudo -l`, `getent group sudo`

Combined with the four FIM-based rules (100110-100113), this project now has seven working, MITRE ATT&CK-mapped detection rules spanning both file-integrity and command-execution detection surfaces.

**Remaining limitation:** `auditd`-based, kernel-level command auditing still does not work in this Docker-on-Apple-Silicon lab environment, for the platform reasons described above. The bash `trap DEBUG` approach used here is a practical, working substitute for this lab context, but a production deployment on bare-metal or a VM with full kernel access would more typically use `auditd` directly for more comprehensive and tamper-resistant command auditing.
