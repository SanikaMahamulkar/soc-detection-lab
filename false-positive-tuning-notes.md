# False-Positive Tuning Notes

Observations from building and testing the custom detection rules in wazuh-rules/local_rules.xml, and the tuning decisions made as a result.

## Observed sources of false positives

### 1. File-added vs file-modified events (rules 100110-100113)

Initial versions of the custom rules used if_sid 550 (Wazuh's "Integrity checksum changed" base rule), which only fires on modification of an existing file. When /etc/sudoers did not previously exist on the test host and was created fresh, the event was correctly logged by Wazuh but under base rule 554 ("File added to the system") instead - meaning the custom rule silently failed to fire, a false negative rather than a false positive, but discovered through the same testing process.

Fix: rules were changed to use if_group syscheck instead of if_sid 550, which matches both added and modified events. This is the correct approach for any file that might not exist on every host (e.g. sudoers is not present on systems without sudo installed) versus files guaranteed to exist (e.g. /etc/passwd).

### 2. Legitimate package installations creating system accounts

/etc/passwd is modified any time a package is installed that creates a system/service account as part of its post-install script (this was observed directly: installing lsb-release's dependency chain during agent setup triggered several new low-UID service accounts). A real deployment of rule 100110 would need either:
- A allowlist/suppression window during known maintenance periods, or
- A secondary check on the UID range and shell of the new account (service accounts are typically UID less than 1000 with a nologin shell, while a suspicious addition often uses UID 0 or an interactive shell) to distinguish routine package-management activity from a genuine persistence attempt.

This project's rules do not yet implement that UID-based filtering; it is noted here as the clear next tuning step rather than implemented, since doing so accurately requires a larger sample of legitimate baseline activity than a short-lived lab environment provides.

### 3. Command-execution monitoring produced no usable signal at all

As documented in detection-notes.md, the attempted command-log-based detection rules (matching CMDLOG-prefixed log lines for T1087, T1082, T1069) did not generate any alerts despite the underlying log data being confirmed present and correctly formatted. Rather than a false-positive problem, this was a false-negative/non-functioning-detection problem, and is documented and set aside as a known limitation rather than tuned further within this project's timeframe.

## Tuning approach going forward

For a longer-running deployment, the recommended process would be:
1. Run the ruleset against genuine baseline activity for at least several days before enabling alerting, to characterize what "normal" file-change activity looks like on a given host class (e.g. a package-management-heavy host vs a static production server).
2. Layer in field-level filtering (UID, shell, specific added lines) rather than triggering on any change to a monitored file, to reduce alert volume for high-noise files.
3. Track a false-positive rate per rule over time and adjust severity levels or add suppression logic for rules that generate disproportionate noise relative to genuine findings.
