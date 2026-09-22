# Runbook 03: SSH Persistence via authorized_keys Tampering

**MITRE ATT&CK:** T1098.004 (Account Manipulation: SSH Authorized Keys)
**Tactic:** Persistence
**Triggering rule:** Wazuh custom rule 100113 (level 12)
**Detection source:** File Integrity Monitoring (real-time) on files matching authorized_keys

## 1. Detection

Wazuh's FIM module monitors changes to any file whose path contains authorized_keys. Attackers who gain any level of access to a host commonly add their own SSH public key to a user's authorized_keys file as a durable, easy-to-use persistence mechanism that survives password resets and does not require re-exploiting the original vulnerability.

What a real alert looks like:

Rule: 100113 (level 12)
Description: CRITICAL: SSH authorized_keys file was modified - possible unauthorized SSH access persistence (T1098.004)
MITRE: T1098.004 | Tactic: Persistence

## 2. Triage

- Which user's authorized_keys file changed? Root and service accounts are higher priority than a personal user account, but any addition should be reviewed.
- Was a new key added, or was an existing key removed/replaced? An added key is a classic persistence indicator; a removed key can indicate an attacker locking out the legitimate owner.
- Does the added key have an identifiable comment (many SSH keys are generated with a user@host comment)? An unfamiliar comment, or no comment at all, is a stronger indicator of an unauthorized addition.

Escalate immediately if: a new key was added to a privileged account (root, a service account, or an account with sudo access) and the addition cannot be attributed to a known administrative action.

## 3. Investigation

- Pull the full file diff to see exactly which key was added or changed.
- Check SSH authentication logs for any successful logins using key-based authentication in the period after the file was modified - this tells you whether the new key has already been used.
- Check for the source IP of any such login and assess whether it is consistent with the organization's expected access patterns.
- Review how the attacker likely gained the initial access needed to write to this file: a prior compromised password, an exposed misconfigured service, or a separate vulnerability.

## 4. Containment

- Remove the unauthorized key from the authorized_keys file immediately.
- If the key has already been used to log in, treat the account as compromised: force a password reset, invalidate any active sessions, and review everything that account has done since the key was added.
- Consider temporarily disabling SSH access for the affected account while investigation continues, if business impact allows.

## 5. Eradication

- Confirm no other authorized_keys files on the host (or related hosts, if key reuse across a fleet is a risk) contain similar unauthorized entries.
- Identify and close the access vector that allowed the attacker to write to this file in the first place.

## 6. Recovery

- Restore the authorized_keys file to contain only verified, legitimate keys.
- Re-issue credentials or keys to the legitimate user if their access was disrupted during containment.

## 7. Lessons Learned / Follow-up

- Could file permissions on the .ssh directory or authorized_keys file have been tightened to prevent unauthorized writes even with a lower-privilege foothold?
- Should SSH key additions require a documented approval step, similar to sudoers changes?
- Is there a case for disabling password authentication entirely, or requiring key rotation on a schedule, to reduce the value of stolen credentials?
