# Runbook: Account Lockout (RB-ACCT-001)

## Symptoms
A standard user reports "account locked", "locked out", or repeated sign-in failures after a password
change or too many bad password attempts. Sign-in logs show a lockout status for the account.

## Diagnosis
1. Confirm the account is a standard user account (not an administrator, break-glass, or service account).
2. Check the account status and confirm it is currently locked.
3. Ask whether the user recently changed their password on another device (stale saved credentials are the common cause).

## Remediation
Unlock the account. The user must then sign in with their current password; do not reset passwords from this runbook.
ACTION check_account_status user={affected_user}
ACTION unlock_account user={affected_user}

## Verification
Account status shows unlocked and the user can sign in. Ask the user to remove stale saved credentials on other devices.

## Escalation
If the account re-locks within one hour, escalate to Identity and Access Management: repeated lockouts can indicate
a password-spray attempt. Administrator, break-glass, and service accounts are never handled by this runbook.
