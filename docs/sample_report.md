# Alert Triage Report

- **Generated:** 2026-10-08 15:32 UTC
- **Intel mode:** mock
- **Alerts:** 8  |  CRITICAL: 2  |  HIGH: 2  |  MEDIUM: 1  |  LOW: 3

## Triage queue

| Pri | Verdict | Score | Alert | Rule | Host | SLA |
|---|---|---|---|---|---|---|
| P1 | CRITICAL | 100 | A-1001 | Outbound connection to known C2 infrastructure | FIN-DB-01 | 15 min |
| P1 | CRITICAL | 82 | A-1002 | Suspicious PowerShell encoded command | WS-HR-17 | 15 min |
| P2 | HIGH | 65 | A-1004 | Multiple failed logins (possible brute force) | VPN-GW-01 | 1 hour |
| P2 | HIGH | 63 | A-1003 | User clicked phishing URL | WS-FIN-03 | 1 hour |
| P3 | MEDIUM | 48 | A-1006 | DNS query to newly registered domain | WS-DEV-22 | 4 hours |
| P4 | LOW | 13 | A-1008 | Internal port scan detected | SCANNER-01 | 24 hours |
| P4 | LOW | 8 | A-1005 | Admin login from new country | AD-DC-02 | 24 hours |
| P4 | LOW | 0 | A-1007 | Software update check | WS-DEV-05 | 24 hours |

## A-1001 - Outbound connection to known C2 infrastructure

> P1 CRITICAL (100/100): 'Outbound connection to known C2 infrastructure' on FIN-DB-01 by svc_backup. Top factor: SIEM rated this alert high.

**Score breakdown**

- `+40` Rule severity: SIEM rated this alert high
- `+24` IP reputation: 203.0.113.45 abuse confidence 97% (412 reports)
- `+30` Malicious detections: 203.0.113.45 flagged by 14/90 engines
- `+12` Asset criticality: FIN-DB-01 is critical value
- `+5` ATT&CK technique: high-impact technique(s): T1071
- `+5` Event volume: 120 events

**Indicators**

| Type | Value | Source | Verdict data |
|---|---|---|---|
| ip | `203.0.113.45` | mock | 14/90 engines, abuse 97% (412 reports), RU, Example Bulletproof Hosting |

**Recommended actions**

- [ ] Escalate to L2/IR lead now and open an incident ticket
- [ ] Block 203.0.113.45 at the perimeter and hunt for other internal hosts that contacted it

## A-1002 - Suspicious PowerShell encoded command

> P1 CRITICAL (82/100): 'Suspicious PowerShell encoded command' on WS-HR-17 by jdoe. Top factor: SIEM rated this alert high.

**Score breakdown**

- `+40` Rule severity: SIEM rated this alert high
- `+30` Malicious detections: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f flagged by 66/72 engines
- `+7` Asset criticality: WS-HR-17 is high value
- `+5` ATT&CK technique: high-impact technique(s): T1059

**Indicators**

| Type | Value | Source | Verdict data |
|---|---|---|---|
| hash | `275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f` | mock | 66/72 engines, EICAR test file |

**Recommended actions**

- [ ] Escalate to L2/IR lead now and open an incident ticket
- [ ] Isolate WS-HR-17 via EDR; collect the file and hunt hash 275a021bbfb6489e... fleet-wide

## A-1004 - Multiple failed logins (possible brute force)

> P2 HIGH (65/100): 'Multiple failed logins (possible brute force)' on VPN-GW-01 by admin. Top factor: SIEM rated this alert medium.

**Score breakdown**

- `+25` Rule severity: SIEM rated this alert medium
- `+14` IP reputation: 198.51.100.23 abuse confidence 58% (31 reports)
- `+9` Malicious detections: 198.51.100.23 flagged by 3/90 engines
- `+7` Asset criticality: VPN-GW-01 is high value
- `+5` ATT&CK technique: high-impact technique(s): T1110
- `+5` Event volume: 340 events

**Indicators**

| Type | Value | Source | Verdict data |
|---|---|---|---|
| ip | `198.51.100.23` | mock | 3/90 engines, abuse 58% (31 reports), NL, Example VPS Provider |

**Recommended actions**

- [ ] Block 198.51.100.23 at the perimeter and hunt for other internal hosts that contacted it
- [ ] Review auth logs for a successful login after the failures; enforce MFA / lockout

## A-1003 - User clicked phishing URL

> P2 HIGH (63/100): 'User clicked phishing URL' on WS-FIN-03 by asmith. Top factor: login-micros0ft-secure.example flagged by 18/90 engines.

**Score breakdown**

- `+25` Rule severity: SIEM rated this alert medium
- `+30` Malicious detections: login-micros0ft-secure.example flagged by 18/90 engines
- `+3` Asset criticality: WS-FIN-03 is medium value
- `+5` ATT&CK technique: high-impact technique(s): T1566

**Indicators**

| Type | Value | Source | Verdict data |
|---|---|---|---|
| domain | `login-micros0ft-secure.example` | mock | 18/90 engines, newly registered, lookalike |

**Recommended actions**

- [ ] Sinkhole/block login-micros0ft-secure.example in DNS and proxy; search proxy logs for other users who visited it
- [ ] Check whether asmith entered credentials; force a password reset if so

## A-1006 - DNS query to newly registered domain

> P3 MEDIUM (48/100): 'DNS query to newly registered domain' on WS-DEV-22 by rkumar. Top factor: SIEM rated this alert medium.

**Score breakdown**

- `+25` Rule severity: SIEM rated this alert medium
- `+18` Malicious detections: cdn.updates-check.example flagged by 6/90 engines
- `+5` ATT&CK technique: high-impact technique(s): T1071

**Indicators**

| Type | Value | Source | Verdict data |
|---|---|---|---|
| domain | `cdn.updates-check.example` | mock | 6/90 engines, registered 3 days ago |

**Recommended actions**

- [ ] Sinkhole/block cdn.updates-check.example in DNS and proxy; search proxy logs for other users who visited it
- [ ] Check whether rkumar entered credentials; force a password reset if so

## A-1008 - Internal port scan detected

> P4 LOW (13/100): 'Internal port scan detected' on SCANNER-01. Top factor: SIEM rated this alert low.

**Score breakdown**

- `+10` Rule severity: SIEM rated this alert low
- `+3` Event volume: 15 events

**Recommended actions**

- [ ] Document the reasoning and close as benign / tune the rule if it recurs

## A-1005 - Admin login from new country

> P4 LOW (8/100): 'Admin login from new country' on AD-DC-02 by admin. Top factor: SIEM rated this alert low.

**Score breakdown**

- `+10` Rule severity: SIEM rated this alert low
- `+3` Asset criticality: AD-DC-02 is medium value
- `+5` ATT&CK technique: high-impact technique(s): T1078
- `-10` All IOCs clean: no reputation hits on any enriched indicator

**Indicators**

| Type | Value | Source | Verdict data |
|---|---|---|---|
| ip | `192.0.2.77` | mock | 0/90 engines, DE, Example Telecom |

**Recommended actions**

- [ ] Document the reasoning and close as benign / tune the rule if it recurs

## A-1007 - Software update check

> P4 LOW (0/100): 'Software update check' on WS-DEV-05 by priya. Top factor: SIEM rated this alert low.

**Score breakdown**

- `+10` Rule severity: SIEM rated this alert low
- `-10` All IOCs clean: no reputation hits on any enriched indicator

**Indicators**

| Type | Value | Source | Verdict data |
|---|---|---|---|
| domain | `github.com` | mock | 0/90 engines, GitHub, Inc. |
| hash | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | mock | 0/72 engines, empty file |

**Recommended actions**

- [ ] Document the reasoning and close as benign / tune the rule if it recurs
