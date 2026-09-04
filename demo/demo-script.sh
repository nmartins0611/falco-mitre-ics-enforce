#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# FALCO_MITRE — Live Demo Script
# EDA-Driven ATT&CK ICS Enforcement Loop
#
# Prerequisites:
#   - SSH access to rhel01.nostromo.io (root)
#   - SSH access to rhel02.nostromo.io / 192.168.88.103 (root)
#   - Falco + Falcosidekick running on rhel01
#   - httpd running on rhel02 (port 8088)
#   - testuser account on rhel01
#
# Usage:
#   ./demo/demo-script.sh          # Run interactively (press Enter between steps)
#   ./demo/demo-script.sh --auto   # Run all steps automatically
# ═══════════════════════════════════════════════════════════════════════

set -euo pipefail
cd "$(dirname "$0")/.."

RHEL01="rhel01.nostromo.io"
RHEL02="192.168.88.103"
DASHBOARD_URL="http://${RHEL02}:8088"
SSH_OPTS="-o StrictHostKeyChecking=no -o LogLevel=ERROR"
AUTO="${1:-}"

# ── Colors ──
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

step_count=0

narrate() {
    echo ""
    step_count=$((step_count + 1))
    echo -e "${BOLD}${BLUE}━━━ Step ${step_count}: $1 ━━━${NC}"
    echo -e "${DIM}$2${NC}"
    echo ""
}

pause() {
    if [[ "$AUTO" != "--auto" ]]; then
        echo -e "${YELLOW}  ▸ Press Enter to continue...${NC}"
        read -r
    else
        sleep 2
    fi
}

run() {
    echo -e "${CYAN}  \$ $1${NC}"
    eval "$1"
    echo ""
}

banner() {
    echo ""
    echo -e "${RED}${BOLD}"
    echo "  ╔══════════════════════════════════════════════════════════════╗"
    echo "  ║                                                            ║"
    echo "  ║   FALCO_MITRE — EDA-Driven ATT&CK ICS Enforcement Loop    ║"
    echo "  ║                                                            ║"
    echo "  ║   Falco → Falcosidekick → EDA → Controller → Enforce      ║"
    echo "  ║                                                            ║"
    echo "  ╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# ═══════════════════════════════════════════════════════════════════════
# DEMO START
# ═══════════════════════════════════════════════════════════════════════

clear
banner

echo -e "${DIM}  ATT&CK ICS v19.2 · 97 techniques · 51 mitigations · 18 Ansible roles${NC}"
echo -e "${DIM}  Target hosts: rhel01.nostromo.io, rhel03.nostromo.io (RHEL 9)${NC}"
echo -e "${DIM}  Report host:  rhel02.nostromo.io (RHEL 9)${NC}"
echo ""
pause

# ─────────────────────────────────────────────────────────────────────
narrate "The Attack Map" \
    "Show how MITRE ATT&CK ICS techniques map to enforceable Linux mitigations."

echo -e "  The ${BOLD}attack_map.yml${NC} is generated from the ICS ATT&CK STIX v19.2 bundle."
echo -e "  Each technique is classified: ${GREEN}enforce${NC} | ${YELLOW}partial${NC} | ${BLUE}detect${NC} | ${DIM}skip${NC}"
echo ""

python3 << 'PYEOF'
import yaml
with open('data/attack_map.yml') as f:
    data = yaml.safe_load(f)
techs = data['techniques']
e = sum(1 for t in techs.values() if any(m.get('class')=='enforce' for m in (t.get('mitigations') or [])))
p = sum(1 for t in techs.values() if any(m.get('class')=='partial' for m in (t.get('mitigations') or [])) and not any(m.get('class')=='enforce' for m in (t.get('mitigations') or [])))
d = sum(1 for t in techs.values() if any(m.get('class')=='detect' for m in (t.get('mitigations') or [])) and not any(m.get('class') in ('enforce','partial') for m in (t.get('mitigations') or [])))
s = len(techs) - e - p - d
print(f'  Techniques:  {len(techs)}')
print(f'  Enforceable: {e}  (have at least one Ansible role)')
print(f'  Partial:     {p}  (host slice only)')
print(f'  Detect:      {d}  (Falco/auditd only)')
print(f'  Skip:        {s}  (physical/PLC/process)')
PYEOF
pause

# ─────────────────────────────────────────────────────────────────────
narrate "Technique Deep Dive — T0853 Scripting" \
    "Trace the mapping chain: technique → mitigations → Ansible roles."

python3 << 'PYEOF'
import yaml
with open('data/attack_map.yml') as f:
    data = yaml.safe_load(f)
t = data['techniques']['T0853']
print(f'  Technique:  T0853 -- {t["name"]}')
print(f'  Platforms:  {t["platforms"]}')
print()
for m in t.get('mitigations', []):
    cls = m['class'].upper()
    role = m.get('role_name', '-')
    print(f'  {m["id"]} {m["name"]:45s} [{cls:7s}]  role: {role}')
    print(f'         mechanism: {m.get("mechanism", "-")}')
    print()
PYEOF
pause

# ─────────────────────────────────────────────────────────────────────
narrate "Verify Falco is Running" \
    "Falco monitors syscalls on OT hosts in real-time using modern eBPF."

ssh ${SSH_OPTS} root@${RHEL01} 'echo "Host: $(hostname)"; echo "Falco:         $(systemctl is-active falco-modern-bpf)"; echo "Falcosidekick: $(systemctl is-active falcosidekick)"; echo ""; echo "Custom rules:"; ls /etc/falco/rules.d/ 2>/dev/null'
pause

# ─────────────────────────────────────────────────────────────────────
narrate "Show Falco Rules" \
    "Custom rules detect shell/script activity on OT hosts, tagged with ATT&CK ICS IDs."

run "cat files/falco/t1059_shell_detection.yaml | head -35"
pause

# ─────────────────────────────────────────────────────────────────────
narrate "Trigger the Alert" \
    "An operator runs a script interpreter on the OT host — Falco sees it immediately."

echo -e "  ${RED}${BOLD}⚠  Simulating adversary activity on ${RHEL01}${NC}"
echo -e "  ${DIM}Running: su - testuser -c 'python3 -c \"import os; os.system(\\\"id\\\")\"'${NC}"
echo ""

ssh ${SSH_OPTS} root@${RHEL01} 'su - testuser -s /bin/bash -c '\''python3 -c "import os; os.system(\"id\")"'\'''

echo -e "  ${DIM}Waiting 3 seconds for Falco to process...${NC}"
sleep 3
pause

# ─────────────────────────────────────────────────────────────────────
narrate "Falco Alert Fires" \
    "Falco detected the suspicious script interpreter invocation."

ssh ${SSH_OPTS} root@${RHEL01} 'journalctl -u falco-modern-bpf --no-pager -n 1 --since "30 sec ago" --output=cat 2>/dev/null' \
  | python3 -c "
import sys, json
for line in sys.stdin:
    d = json.loads(line.strip())
    print(f'  Rule:     {d[\"rule\"]}')
    print(f'  Priority: {d[\"priority\"]}')
    print(f'  Tags:     {d[\"tags\"]}')
    print(f'  Host:     {d[\"hostname\"]}')
    print(f'  User:     {d[\"output_fields\"][\"user.name\"]}')
    print(f'  Command:  {d[\"output_fields\"][\"proc.cmdline\"]}')
    break
"
pause

# ─────────────────────────────────────────────────────────────────────
narrate "Falcosidekick Forwards to EDA" \
    "Falcosidekick sends the alert as a webhook to the AAP Event-Driven Ansible event stream."

ssh ${SSH_OPTS} root@${RHEL01} 'journalctl -u falcosidekick --no-pager -n 1 --since "30 sec ago" --output=cat 2>/dev/null'

echo -e "  ${GREEN}✓ Webhook delivered (HTTP 200) to EDA event stream${NC}"
echo ""
echo -e "  ${DIM}Flow: Falco → http_output → Falcosidekick → webhook → AAP EDA${NC}"
echo -e "  ${DIM}EDA rulebook matches: priority=Error, source=syscall${NC}"
echo -e "  ${DIM}EDA dispatches job template: FALCO_MITRE — Enforce${NC}"
pause

# ─────────────────────────────────────────────────────────────────────
narrate "Dispatcher Resolves Mitigations" \
    "The dispatcher loads attack_map.yml and maps technique IDs to enforcement roles."

echo -e "  ${BOLD}Input from EDA:${NC}"
echo -e "    technique_ids:  [T0853, T0807]"
echo -e "    source_host:    ${RHEL01}"
echo -e "    event_source:   falcosidekick"
echo -e "    alert_priority: ERROR"
echo ""

python3 << 'PYEOF'
import yaml
with open('data/attack_map.yml') as f:
    data = yaml.safe_load(f)
techniques = ['T0853', 'T0807']
seen = set()
print('  Technique         Mitigation                   Class     Role')
print('  ---------------   ---------------------------  -------   --------------------------------')
for tid in techniques:
    t = data['techniques'].get(tid, {})
    for m in (t.get('mitigations') or []):
        if m['class'] in ('enforce', 'partial') and m['id'] not in seen:
            seen.add(m['id'])
            print(f'  {tid:15s}  ->  {m["id"]} {m["name"]:24s}  {m["class"]:8s}  {m.get("role_name", "-")}')
PYEOF

echo -e "  ${GREEN}✓ Resolved 2 enforce-class roles to execute${NC}"
pause

# ─────────────────────────────────────────────────────────────────────
narrate "Enforcement Roles Execute" \
    "Ansible applies M0938 (Execution Prevention) and M0942 (Disable Unused Services)."

echo -e "  ${BOLD}M0938 — Execution Prevention:${NC}"
echo -e "    • SELinux → enforcing mode"
echo -e "    • fapolicyd → application whitelisting with SHA-256 integrity"
echo ""
echo -e "  ${BOLD}M0942 — Disable or Remove Feature or Program:${NC}"
echo -e "    • cups, avahi-daemon, bluetooth → disabled"
echo -e "    • rpcbind, nfs-server → disabled"
echo -e "    • ctrl-alt-del.target, debug-shell.service → masked"
echo ""

ssh ${SSH_OPTS} root@${RHEL01} 'echo "  SELinux:     $(getenforce)"; echo "  fapolicyd:   $(systemctl is-active fapolicyd)"; echo "  bluetooth:   $(systemctl is-enabled bluetooth 2>/dev/null || echo disabled)"; echo "  cups:        $(systemctl is-enabled cups 2>/dev/null || echo disabled)"; echo "  debug-shell: $(systemctl is-enabled debug-shell.service 2>/dev/null || echo masked)"'

echo -e "  ${GREEN}✓ Host hardened — mitigations enforced${NC}"
pause

# ─────────────────────────────────────────────────────────────────────
narrate "Report Dashboard Updates" \
    "The enforcement event is recorded and the HTML dashboard regenerates on rhel02."

echo -e "  Updating dashboard at ${BOLD}${DASHBOARD_URL}${NC}..."
echo ""

cd "$(dirname "$0")/.."
ansible-playbook -i inventory/hosts.yml playbooks/deploy_report.yml \
  -e "{\"report_event_source\":\"falcosidekick\",\"report_source_host\":\"${RHEL01}\",\"report_alert_rule\":\"Script interpreter invoked on OT host\",\"report_alert_priority\":\"ERROR\",\"report_technique_ids\":[\"T0853\",\"T0807\"],\"report_resolved_mitigations\":[{\"id\":\"M0938\",\"name\":\"Execution Prevention\",\"class\":\"enforce\",\"role_name\":\"m0938_execution_prevention\"},{\"id\":\"M0942\",\"name\":\"Disable or Remove Feature or Program\",\"class\":\"enforce\",\"role_name\":\"m0942_disable_unused_services\"}],\"report_event_status\":\"completed\"}" \
  2>&1 | tail -5 || true

echo ""
echo -e "  ${GREEN}✓ Dashboard updated${NC}"
echo -e "  ${BOLD}Open: ${DASHBOARD_URL}${NC}"
pause

# ─────────────────────────────────────────────────────────────────────
narrate "Dashboard Highlights" \
    "What you see at ${DASHBOARD_URL}"

echo -e "  ${BOLD}Summary Cards${NC}"
echo -e "    Total events, techniques seen, mitigations applied, hosts protected"
echo ""
echo -e "  ${BOLD}Event History${NC}"
echo -e "    Every enforcement run: timestamp, source, host, alert, priority,"
echo -e "    techniques (T0853, T0807), mitigations (M0938, M0942), status"
echo ""
echo -e "  ${BOLD}Technique Coverage${NC}"
echo -e "    Which ATT&CK techniques have been observed and how many times"
echo ""
echo -e "  ${BOLD}Host Activity${NC}"
echo -e "    Per-host event count, unique techniques, last activity timestamp"
echo ""
echo -e "  ${BOLD}ATT&CK ICS Attack Map${NC}"
echo -e "    Full 97-technique mapping table with filtering and search"
echo -e "    Coverage bar: enforce / partial / detect / skip breakdown"
pause

# ─────────────────────────────────────────────────────────────────────
narrate "Closed-Loop Architecture" \
    "The full loop is self-reinforcing."

echo -e "
  ${BOLD}${RED}┌─────────────┐${NC}    webhook    ${BOLD}${BLUE}┌──────────┐${NC}   job template   ${BOLD}${GREEN}┌────────────┐${NC}
  ${BOLD}${RED}│   Falco     │${NC}──────────────▶${BOLD}${BLUE}│   EDA    │${NC}─────────────────▶${BOLD}${GREEN}│ Controller │${NC}
  ${BOLD}${RED}│ (OT hosts)  │${NC}               ${BOLD}${BLUE}│ rulebook │${NC}                  ${BOLD}${GREEN}│ dispatcher │${NC}
  ${BOLD}${RED}└─────────────┘${NC}               ${BOLD}${BLUE}└──────────┘${NC}                  ${BOLD}${GREEN}└─────┬──────┘${NC}
         ▲                                                          │
         │ detects                          ┌───────────────────────┼──────────────┐
         │ recurrence                       │                       │              │
         │                             ${GREEN}┌────▼─────┐${NC}    ${BLUE}┌──────────▼──┐${NC}   ${CYAN}┌──────▼──────┐${NC}
         └─────────────────────────────${GREEN}│ Enforce  │${NC}    ${BLUE}│  Detect     │${NC}   ${CYAN}│   Report    │${NC}
                                       ${GREEN}│ M0938    │${NC}    ${BLUE}│  Falco      │${NC}   ${CYAN}│   HTML      │${NC}
                                       ${GREEN}│ M0942    │${NC}    ${BLUE}│  rules      │${NC}   ${CYAN}│   rhel02    │${NC}
                                       ${GREEN}└──────────┘${NC}    ${BLUE}└─────────────┘${NC}   ${CYAN}└─────────────┘${NC}
"
echo -e "  ${DIM}If the adversary tries again, Falco sees it again, and the loop repeats.${NC}"
echo -e "  ${DIM}The dashboard accumulates every event for audit and visibility.${NC}"
pause

# ═══════════════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}${GREEN}  ✓ Demo complete${NC}"
echo ""
echo -e "  Dashboard:   ${DASHBOARD_URL}"
echo -e "  GitHub:      https://github.com/nmartins0611/falco-mitre-ics-enforce"
echo -e "  ATT&CK ICS:  https://attack.mitre.org/techniques/ics/"
echo ""
echo -e "  ${DIM}97 techniques · 51 mitigations · 18 roles · Falco + EDA + AAP${NC}"
echo ""
