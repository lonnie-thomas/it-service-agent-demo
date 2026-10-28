# Runbook: Stuck Print Queue (RB-PRN-004)

## Symptoms
A printer shows many pending jobs, documents are stuck in the print queue, or nothing prints from a specific printer.

## Diagnosis
1. Identify the printer name (format PRN-xxxx on the device label).
2. Confirm the print spooler service is running.

## Remediation
Purge the stuck jobs from the single affected printer queue. Users will need to resubmit their jobs.
ACTION clear_print_queue printer={printer}

## Verification
Queue length is zero and a test page prints.

## Escalation
If jobs stick again, check the print driver version and open a problem record.
