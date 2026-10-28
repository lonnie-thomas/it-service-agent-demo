# Runbook: Reported Phishing Email (RB-SEC-006)

## Symptoms
A user forwards or reports a suspicious email, a possible phishing message, a fake invoice, or a link asking for credentials.

## Diagnosis
1. Do not open links or attachments.
2. Ask whether the user clicked the link or entered credentials.

## Remediation
No automated action is permitted. This runbook is guidance for a human analyst only: report the message to Security
Operations, ask the user to delete it, and if credentials were entered follow the suspicious sign-in runbook.

## Verification
Security Operations confirms the message was triaged and, if needed, blocked tenant-wide.

## Escalation
Any click-through or credential entry becomes a security incident immediately.
