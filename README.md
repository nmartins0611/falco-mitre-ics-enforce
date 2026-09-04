# FALCO\_MITRE — EDA-Driven ATT&CK ICS Enforcement Loop

An Ansible collection that closes the loop between **runtime threat detection** (Falco) and **automated mitigation enforcement** (Ansible) on Linux OT hosts, orchestrated by **Event-Driven Ansible**.

```
Falco syscall alert → Falcosidekick webhook → EDA event stream
  → dispatcher resolves ATT&CK technique IDs → attack_map.yml lookup
  → include matching enforcement roles → generate HTML report
```

## How It Works

1. **Falco** monitors syscalls on OT hosts and tags alerts with [ATT&CK ICS](https://attack.mitre.org/techniques/ics/) technique IDs.
2. **Falcosidekick** forwards critical/error alerts as webhooks to an AAP **Event-Driven Ansible** event stream.
3. The **EDA rulebook** matches the event and dispatches a job template on the AAP controller.
4. The **dispatcher playbook** loads `attack_map.yml`, resolves incoming technique IDs to mitigations, and runs the corresponding enforcement roles.
5. An **HTML enforcement report** is regenerated on the report host after each run.

## Collection Structure

```
falco_mitre.ics_enforce/
├── galaxy.yml                          # Collection metadata
├── ansible.cfg                         # roles_path = roles
├── data/
│   ├── attack_map.yml                  # Technique → mitigation → role mapping (generated)
│   └── ics-attack-19.2.json           # Vendored ATT&CK ICS STIX bundle
├── tools/
│   └── generate_attack_map.py         # STIX parser — regenerates attack_map.yml
├── extensions/eda/rulebooks/
│   └── falco_enforcement.yml          # EDA rulebook (4 rules)
├── playbooks/
│   ├── dispatcher.yml                 # Core: technique → mitigation → role resolver
│   ├── deploy_falco.yml               # Install Falco + Falcosidekick on OT hosts
│   └── deploy_report.yml             # Deploy HTML dashboard to report host
├── roles/
│   ├── m0927_password_policies/       # M0927 — pwquality, pam_faillock, login.defs
│   ├── m0938_execution_prevention/    # M0938 — fapolicyd, SELinux enforcing
│   ├── m0942_disable_unused_services/ # M0942 — mask/disable unnecessary services
│   ├── m0947_audit/                   # M0947 — auditd, AIDE, Falco rule deploy
│   ├── falco_install/                 # Install Falco + Falcosidekick on RHEL 9
│   └── enforcement_report/            # HTML dashboard generation + httpd deploy
├── files/falco/
│   └── t1059_shell_detection.yaml     # Falco rules for T0807/T0853/T1059
└── inventory/
    └── hosts.yml                      # Lab inventory (rhel01, rhel02, rhel03)
```

## Attack Map

The `attack_map.yml` file is the central mapping layer. It is generated from the MITRE ATT&CK ICS STIX v19.2 bundle and maps every ICS technique to its mitigations, classified by enforceability on Linux:

| Class       | Meaning                                      | Count |
|-------------|----------------------------------------------|-------|
| **enforce** | Full host control via Ansible role            | 165   |
| **partial** | Host slice only (IdP/DPI/vendor out of band)  | —     |
| **detect**  | Falco/auditd detection, no preventive control | —     |
| **skip**    | Physical, PLC, or process control — no role   | —     |

**97 techniques** mapped across **51 unique mitigations**.

Regenerate after a new ATT&CK release:

```bash
# Download new STIX bundle
curl -Lo data/ics-attack-XX.Y.json \
  https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack-XX.Y.json

# Regenerate mapping
python tools/generate_attack_map.py
```

## Enforcement Roles

Each role maps 1:1 to a MITRE mitigation ID and is self-contained:

| Role | Mitigation | What It Enforces |
|------|------------|-----------------|
| `m0927_password_policies` | M0927 | pwquality complexity, pam_faillock lockout, password aging |
| `m0938_execution_prevention` | M0938 | fapolicyd application whitelisting, SELinux enforcing |
| `m0942_disable_unused_services` | M0942 | Mask cups, avahi, bluetooth, rpcbind, ctrl-alt-del, debug-shell |
| `m0947_audit` | M0947 | auditd OT rules, AIDE file integrity, Falco rule deployment |
| `falco_install` | — | Falco 0.44.1 (modern-bpf) + Falcosidekick 2.35.0 |
| `enforcement_report` | — | HTML dashboard on report host (httpd, port 8088) |

## EDA Rulebook

The rulebook (`extensions/eda/rulebooks/falco_enforcement.yml`) handles four event types:

| Rule | Trigger | Action |
|------|---------|--------|
| Falco critical/error | `priority in [Critical, Error]` + syscall source | Full enforcement — all matching roles run |
| Falco warning | `priority in [Warning]` + syscall source | Detection only — deploy Falco rules, skip enforce |
| Insights compliance | `compliance_score < 80` | Re-apply baseline enforcement for host |
| Insights advisory | Critical/Important severity | Deploy compensating Falco rules + queue patch |

## Quick Start

### Prerequisites

- AAP 2.5+ with EDA controller
- RHEL 9 target hosts with SSH access
- Falco repository access (RPM)

### 1. Deploy Falco + Falcosidekick to OT hosts

```bash
ansible-playbook -i inventory/hosts.yml playbooks/deploy_falco.yml \
  -e falcosidekick_eda_url=https://aap.example.com/eda-event-streams/api/eda/v1/external_event_stream/<uuid>/post/ \
  -e falcosidekick_eda_token=<your-token>
```

### 2. Deploy the enforcement report dashboard

```bash
ansible-playbook -i inventory/hosts.yml playbooks/deploy_report.yml
```

The dashboard is served at `http://<report-host>:8088/`.

### 3. Configure AAP

1. **Controller**: Create a project pointing to this repository, an inventory with the OT hosts, and a job template named `FALCO_MITRE — Enforce` running `playbooks/dispatcher.yml`.
2. **EDA**: Create a project from this repository, an event stream for Falcosidekick webhooks (with token credential), and an activation using `falco_enforcement.yml` with source mappings to the event stream.

### 4. Test the loop

Trigger a Falco alert on an OT host:

```bash
ssh root@rhel01.example.com "sudo -u nobody bash -c 'echo test'"
```

Watch the chain: Falco alert → Falcosidekick → EDA → controller job → roles enforce M0938 + M0942 → report updates.

## Closed-Loop Flow

```
┌─────────────┐    webhook    ┌──────────┐   job_template   ┌────────────┐
│   Falco     │──────────────▶│   EDA    │─────────────────▶│ Controller │
│ (OT hosts)  │               │ rulebook │                  │ dispatcher │
└─────────────┘               └──────────┘                  └─────┬──────┘
       ▲                                                          │
       │ Falco rules                        ┌─────────────────────┼─────────────┐
       │ deployed by                        │                     │             │
       │ m0947_audit                   ┌────▼─────┐    ┌─────────▼──┐   ┌──────▼──────┐
       └───────────────────────────────│ Enforce  │    │  Detect    │   │   Report    │
                                       │ Roles    │    │  (Falco)   │   │  (HTML)     │
                                       │ M0927…   │    │  rules     │   │  rhel02     │
                                       └──────────┘    └────────────┘   └─────────────┘
```

## Falco Rules

Rules live in `files/falco/` and are tagged with ATT&CK ICS technique IDs:

- **Shell spawned on OT host by non-operator process** — T0807, T0853 — `CRITICAL`
- **Script interpreter invoked on OT host** — T0853 — `ERROR`
- **Suspicious command-line tool on OT host** — T0807, T1105 — `WARNING`

## License

Apache-2.0

## Author

Nuno Martins
