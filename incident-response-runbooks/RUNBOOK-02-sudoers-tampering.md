# Runbook 02: Privilege Escalation via /etc/sudoers Tampering

**MITRE ATT&CK:** T1548.003 (Abuse Elevation Control Mechanism: Sudo and Sudo Caching)
**Tactic:** Privilege Escalation, Defense Evasion
**Triggering rule:** Wazuh custom rule 100112 (level 13)
**Detection source:** File Integrity Monitoring (real-time) on /etc/sudoers

## 1. Detection

Wazuh's FIM module monitors /etc/sudoers in real time. Any addition or modification to this file generates a level-13 alert - the highest severity in this project's rule set, since this file directly controls which users and commands can run with elevated privileges.

What a real alert looks like:

Rule: 100112 (level 13)
Description: CRITICAL: /etc/sudoers was modified - possible privilege escalation attempt (T1548.003)
MITRE: T1548.003 | Tactic: Privilege Escalation, Defense Evasion

## 2. Triage

- Was this an expected, documented administrative change (e.g. adding a new sudo user as part of onboarding)? Check for a corresponding change ticket.
- What specifically changed? Pull the file diff. Look for: a new user or group granted NOPASSWD access, a wildcard rule (ALL=(ALL) NOPASSWD: ALL) added for an unexpected account, or a rule granting access to a specific dangerous binary (e.g. a shell, a text editor that can spawn a shell).
- Which user account made the edit? sudoers edits are normally made via visudo by an administrator with existing sudo access - identify who was authenticated on the host at the time.

Escalate immediately if: a NOPASSWD or ALL=(ALL) rule was added for an account that did not previously have sudo access, especially if that account was itself recently created or recently the subject of another alert (e.g. Runbook 01).

## 3. Investigation

- Compare the current sudoers file against the last known-good version.
- Check whether the editing user's own account shows signs of compromise (unusual login time, login source IP, or authentication method).
- Check sudo's own log (typically in syslog/auth.log) for any sudo commands run immediately before or after the file change - this can reveal whether the elevated access was already used.
- Correlate with any other alerts on the host in the same session: a sudoers change is rarely an isolated event in a genuine attack chain, and is commonly preceded by initial access and reconnaissance activity.

## 4. Containment

- Immediately revert the unauthorized sudoers change, ideally via a known-good backup rather than manual editing (a corrupted sudoers file can lock out all sudo access).
- Suspend the account that made the unauthorized change, and any account it granted elevated access to.
- If elevated access is confirmed to have been used, treat the host as compromised at the root level and begin broader incident response (not just this single file).

## 5. Eradication

- Remove any unauthorized sudo grants.
- Rotate credentials for the account that made the change and any account it granted access to.
- Review all other privilege-related configuration on the host (group memberships, SUID binaries, other sudoers.d fragment files) for further tampering.

## 6. Recovery

- Restore sudoers to a validated, known-good state using visudo -c to check syntax before applying.
- Confirm normal sudo functionality is restored for legitimate users.

## 7. Lessons Learned / Follow-up

- How was the account that made the change obtained or compromised?
- Should sudoers changes require dual-control (a second admin's review) going forward?
- Was the alert triaged and escalated within an acceptable time window given its severity?
