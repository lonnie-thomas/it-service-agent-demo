# Runbook: VPN Connectivity Troubleshooting (RB-VPN-007)

## Symptoms
User cannot connect to the virtual private network, VPN connection drops, or remote access is slow.

## Diagnosis
1. Check the VPN gateway service status. If it is running, the issue is likely local to the user's device or network.
2. Ask the user to restart the VPN client and confirm internet connectivity.

## Remediation
Read-only status check only. The VPN gateway is never restarted from this runbook.
ACTION check_service_status service=vpn-gateway

## Verification
User connects successfully after restarting the client.

## Escalation
If the gateway status is not running, page the network on-call engineer.
