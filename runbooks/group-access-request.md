# Runbook: Standard Software Group Access Request (RB-ACC-005)

## Symptoms
A user asks for access to standard software or collaboration tools, requests to be added to a software group,
or asks for a group membership change with manager approval.

## Diagnosis
1. The request must name an approved standard group in the structured "group" field of the ticket.
2. Only non-privileged groups SG-Software-Standard and SG-Collab-Basic are in scope.
3. Privileged, administrative, or security groups are never handled here.

## Remediation
Add the user to the requested standard group. High-risk change: requires approval from an IT operations manager.
ACTION add_user_to_group user={affected_user} group={group}

## Verification
User appears in the group and the application becomes available after the next sign-in.

## Escalation
Requests for privileged groups go to Identity and Access Management through the formal access review process.
