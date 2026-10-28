# Runbook: Shared Service Unresponsive (RB-SVC-003)

## Symptoms
Users report the print spooler is stopped, the file share is slow, unavailable, or degraded, or a service is hung.
Monitoring shows the service as stopped or degraded.

## Diagnosis
1. Check the service status first.
2. Confirm only a non-critical shared service is affected (print-spooler or file-share).
3. Mail relay and VPN gateway are never restarted from this runbook.

## Remediation
Restart the affected non-critical service after checking its status.
ACTION check_service_status service={service}
ACTION restart_service service={service}

## Verification
Service status returns to running and a test user can reach the resource.

## Escalation
If the service fails again within 24 hours, open a problem record with the infrastructure team.
