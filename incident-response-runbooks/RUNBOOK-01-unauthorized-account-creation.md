# Runbook 01: Unauthorized Account Creation / /etc/passwd Tampering

**MITRE ATT&CK:** T1136.001 (Create Account: Local Account), T1098 (Account Manipulation)
**Tactic:** Persistence
**Triggering rule:** Wazuh custom rule 100110 (level 12)
**Detection source:** File Integrity Monitoring (real-time) on /etc/passwd

## 1. Detection

Wazuh's FIM module monitors /etc/passwd in real time via inotify. Any write to this file (a new account, a modified UID/GID, a changed shell or home directory) generates an alert at severity 12 - high enough to require immediate analyst attention, not a routine informational log.

What a real alert looks like:

Rule: 100110 (level 12)
Description: CRITICAL: /etc/passwd was modified - possible unauthorized account creation or persistence attempt (T1136.001 / T1098)
MITRE: T1136.001, T1098 | Tactic: Persistence
syscheck.path: /etc/passwd

## 2. Triage

On receiving this alert, the analyst should immediately answer:

- Was this a legitimate, expected change? Check for a corresponding change ticket, a known package install (useradd runs as part of some apt package post-install scripts), or a system administrator action in the same time window.
- What changed, specifically? Compare old vs new content of the file. Look for a new username you do not recognize, a UID of 0 (root-equivalent) on a non-root-named account, or an interactive shell (/bin/bash or /bin/sh) on an account that should be a service account (/usr/sbin/nologin).
- Who or what made the change? Cross-reference the alert timestamp against other logs from the same window: SSH logins, sudo usage, any other process activity on the host around that time.

Escalate immediately if: the new or modified account has UID 0, an interactive shell, and was not accompanied by any known administrative action.

## 3. Investigation

- Pull the full FIM event and compare the file's before/after content.
- Check last and lastlog for any login activity from the new account.
- Check /etc/shadow for whether the new account also has a password hash set.
- Review recent authentication logs for any successful or failed logins in the period immediately before the file change.
- Check for other persistence indicators on the same host around the same time: new SSH keys, new cron jobs, new systemd services, unexpected running processes.

## 4. Containment

- If the account is confirmed unauthorized: disable it immediately and force-close any active sessions under that account.
- If root-equivalent access is suspected to have been achieved by any legitimate route, rotate credentials for any account that could have created this entry.
- Isolate the host from the network if there is evidence of active, ongoing attacker interaction rather than a single historical file write.

## 5. Eradication

- Remove the unauthorized account and any artifacts it created (home directory, cron entries, SSH keys).
- Identify and close the initial access vector that allowed the attacker to reach a point where they could modify /etc/passwd.

## 6. Recovery

- Restore /etc/passwd from a known-good backup or golden image if extensive tampering is found.
- Re-enable monitoring and confirm FIM is still active and correctly configured on the restored system.

## 7. Lessons Learned / Follow-up

- Was the initial access vector identified and closed?
- Does the alerting threshold need adjustment for false positives from legitimate package installs that create system accounts?
- Should /etc/passwd changes require a documented change-ticket correlation step in the SOC's standard triage process?
