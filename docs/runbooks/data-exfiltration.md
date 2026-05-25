# Data Exfiltration

## Symptoms

Synthetic detections indicate data exfiltration behavior.

## Detection Logic

Review matched Sigma-style rule metadata and correlated evidence records.

## Investigation Steps

1. Validate entity, asset, and timestamp.
2. Review correlated alerts and timeline.
3. Check blast radius and sensitive data exposure.
4. Contact the recommended owner if severity is high or critical.

## Containment Steps

Disable sessions, isolate affected assets, block suspicious destinations, or revoke risky permissions as applicable.

## Recovery Steps

Rotate credentials, restore safe configuration, and confirm no continued suspicious activity.

## Evidence To Collect

Authentication events, endpoint process tree, cloud audit records, network flows, SaaS audit entries, AI app prompts, and analyst notes.

## Escalation Owner

SOC Tier 2

## False Positive Checks

Validate approved admin changes, known travel, test accounts, scheduled jobs, and expected bulk operations.

## Prevention Recommendations

Improve MFA controls, least privilege, network egress controls, SaaS sharing policies, and security awareness.
