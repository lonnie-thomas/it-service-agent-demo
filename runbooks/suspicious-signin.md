# Runbook: Suspicious Sign-in or Possible Compromised Session (RB-AUTH-002)

## Symptoms
User or security tooling reports an unfamiliar sign-in, impossible travel alert, unexpected multi-factor authentication
prompts, or a sign-in risk alert in the security monitoring queue. The user suspects someone else is using their session.

## Diagnosis
1. Check the account status.
2. Review recent sign-in locations in the identity logs (read-only, performed by a human analyst).
3. Do not reset the password or multi-factor authentication methods from this runbook.

## Remediation
Revoke active sessions so the user must sign in again. This is a medium-risk change and needs a service desk lead or higher.
ACTION check_account_status user={affected_user}
ACTION revoke_user_sessions user={affected_user}

## Verification
Sessions show zero. The user signs in again and confirms the multi-factor prompt is expected.

## Escalation
Open a security incident with Security Operations for any confirmed unauthorized access. Preserve logs.
