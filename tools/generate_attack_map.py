#!/usr/bin/env python3
"""Generate attack_map.yml from ICS ATT&CK STIX bundle.

Reads the vendored ics-attack-19.2.json, extracts techniques,
mitigations, and their relationships, then classifies each
mitigation as enforce/partial/detect/skip for Linux OT hosts.

Usage:
    python tools/generate_attack_map.py

Output:
    data/attack_map.yml
"""

import json
import sys
from pathlib import Path
from typing import Any


STIX_PATH = Path(__file__).resolve().parent.parent / "data" / "ics-attack-19.2.json"
OUTPUT_PATH = Path(__file__).resolve().parent.parent / "data" / "attack_map.yml"

# Platforms that are exclusively non-Linux (exclude these techniques)
# ICS ATT&CK uses "None" for 73+ platform-agnostic techniques — include those.
NON_LINUX_ONLY_PLATFORMS: set[str] = {
    "Field Controller/RTU/PLC/IED",
    "Safety Instrumented System/Protection Relay",
}

# Mitigations that can be enforced on a Linux host via Ansible
ENFORCE_MITIGATIONS: dict[str, dict[str, str]] = {
    "M0807": {
        "role": "m0807_network_allowlists",
        "mechanism": "firewalld/nftables allowlist rules",
    },
    "M0918": {
        "role": "m0918_user_account_mgmt",
        "mechanism": "useradd policy, shell restrictions, account expiry",
    },
    "M0922": {
        "role": "m0922_restrict_registry",
        "mechanism": "sysctl hardening, /proc restrictions",
    },
    "M0926": {
        "role": "m0926_privileged_account_mgmt",
        "mechanism": "sudoers policy, PAM su restrictions",
    },
    "M0927": {
        "role": "m0927_password_policies",
        "mechanism": "pwquality, pam_faillock, password age",
    },
    "M0928": {
        "role": "m0928_os_configuration",
        "mechanism": "sshd hardening, kernel params, service disablement",
    },
    "M0930": {
        "role": "m0930_network_segmentation",
        "mechanism": "firewalld zones, nftables zone isolation",
    },
    "M0932": {
        "role": "m0932_mfa",
        "mechanism": "PAM MFA module (TOTP/FIDO2 where host can demand it)",
    },
    "M0935": {
        "role": "m0935_host_firewall",
        "mechanism": "firewalld/nftables baseline rules",
    },
    "M0936": {
        "role": "m0936_account_access_policies",
        "mechanism": "PAM session limits, login.defs, idle timeout",
    },
    "M0938": {
        "role": "m0938_execution_prevention",
        "mechanism": "fapolicyd, SELinux confined domains",
    },
    "M0942": {
        "role": "m0942_disable_unused_services",
        "mechanism": "systemctl mask/disable, socket deactivation",
    },
    "M0945": {
        "role": "m0945_code_signing",
        "mechanism": "RPM GPG verification, fapolicyd trust",
    },
    "M0946": {
        "role": "m0946_boot_integrity",
        "mechanism": "Secure Boot, GRUB password, kernel lockdown",
    },
    "M0947": {
        "role": "m0947_audit",
        "mechanism": "auditd rules, AIDE, Falco deploy",
    },
    "M0951": {
        "role": "m0951_update_software",
        "mechanism": "dnf security advisory, satellite content view",
    },
}

# Mitigations that are detect-only (Falco provides the signal)
DETECT_MITIGATIONS: dict[str, str] = {
    "M0931": "Network Intrusion Prevention — Falco as host IDS",
    "M0919": "Threat Intelligence Program — feed into EDA",
}

# Mitigations that are partial (some enforcement, some manual)
PARTIAL_MITIGATIONS: dict[str, dict[str, str]] = {
    "M0804": {
        "role": "m0804_human_user_auth",
        "mechanism": "PAM auth stack (partial — badge/biometric is physical)",
    },
    "M0937": {
        "role": "m0937_filter_network_traffic",
        "mechanism": "nftables content filtering (partial — full DPI needs appliance)",
    },
}


def load_stix(path: Path) -> dict[str, Any]:
    """Load and return the STIX bundle."""
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def extract_objects(
    bundle: dict[str, Any],
) -> tuple[
    dict[str, dict[str, Any]],
    dict[str, dict[str, Any]],
    list[dict[str, Any]],
]:
    """Extract techniques, mitigations, and mitigates relationships."""
    techniques: dict[str, dict[str, Any]] = {}
    mitigations: dict[str, dict[str, Any]] = {}
    relationships: list[dict[str, Any]] = []

    for obj in bundle["objects"]:
        if obj.get("revoked", False) or obj.get("x_mitre_deprecated", False):
            continue

        obj_type = obj["type"]

        if obj_type == "attack-pattern":
            ext_refs = obj.get("external_references", [])
            attack_id = next(
                (r["external_id"] for r in ext_refs if r.get("source_name") == "mitre-attack"),
                None,
            )
            if attack_id:
                platforms = obj.get("x_mitre_platforms", [])
                techniques[obj["id"]] = {
                    "attack_id": attack_id,
                    "name": obj["name"],
                    "platforms": platforms,
                    "stix_id": obj["id"],
                }

        elif obj_type == "course-of-action":
            ext_refs = obj.get("external_references", [])
            mitigation_id = next(
                (r["external_id"] for r in ext_refs if r.get("source_name") == "mitre-attack"),
                None,
            )
            if mitigation_id:
                mitigations[obj["id"]] = {
                    "mitigation_id": mitigation_id,
                    "name": obj["name"],
                    "stix_id": obj["id"],
                }

        elif obj_type == "relationship" and obj.get("relationship_type") == "mitigates":
            relationships.append(obj)

    return techniques, mitigations, relationships


def build_technique_mitigation_map(
    techniques: dict[str, dict[str, Any]],
    mitigations: dict[str, dict[str, Any]],
    relationships: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Build technique → mitigations mapping, filtered to Linux OT assets."""
    tech_map: dict[str, dict[str, Any]] = {}

    for tech_stix_id, tech in techniques.items():
        attack_id = tech["attack_id"]
        platforms = set(tech["platforms"])

        # Include technique if:
        #   - platforms is empty or contains "None" (platform-agnostic ICS technique)
        #   - platforms contains at least one non-excluded platform
        # Exclude only if ALL platforms are in the non-Linux set
        is_plc_only = platforms and platforms <= NON_LINUX_ONLY_PLATFORMS
        if is_plc_only:
            continue

        linux_relevant_platforms = platforms - NON_LINUX_ONLY_PLATFORMS
        if not linux_relevant_platforms:
            linux_relevant_platforms = {"None (platform-agnostic)"}

        tech_entry: dict[str, Any] = {
            "name": tech["name"],
            "platforms": sorted(linux_relevant_platforms),
            "mitigations": [],
        }

        for rel in relationships:
            if rel.get("revoked", False) or rel.get("x_mitre_deprecated", False):
                continue

            if rel["target_ref"] != tech_stix_id:
                continue

            mit_stix_id = rel["source_ref"]
            mit = mitigations.get(mit_stix_id)
            if not mit:
                continue

            mid = mit["mitigation_id"]
            mit_entry: dict[str, Any] = {
                "id": mid,
                "name": mit["name"],
            }

            if mid in ENFORCE_MITIGATIONS:
                info = ENFORCE_MITIGATIONS[mid]
                mit_entry["class"] = "enforce"
                mit_entry["role_name"] = info["role"]
                mit_entry["mechanism"] = info["mechanism"]
            elif mid in PARTIAL_MITIGATIONS:
                info = PARTIAL_MITIGATIONS[mid]
                mit_entry["class"] = "partial"
                mit_entry["role_name"] = info["role"]
                mit_entry["mechanism"] = info["mechanism"]
            elif mid in DETECT_MITIGATIONS:
                mit_entry["class"] = "detect"
                mit_entry["mechanism"] = DETECT_MITIGATIONS[mid]
            else:
                mit_entry["class"] = "skip"
                mit_entry["mechanism"] = "physical, process, or vendor-specific — not enforceable from Linux"

            tech_entry["mitigations"].append(mit_entry)

        tech_entry["mitigations"].sort(key=lambda m: m["id"])
        tech_map[attack_id] = tech_entry

    return dict(sorted(tech_map.items()))


def emit_yaml(tech_map: dict[str, dict[str, Any]], output: Path) -> None:
    """Write the attack map as YAML without requiring PyYAML."""
    lines: list[str] = []
    lines.append("# Auto-generated from ICS ATT&CK v19.2 STIX bundle")
    lines.append("# Do not edit manually — regenerate with: python tools/generate_attack_map.py")
    lines.append("---")
    lines.append("stix_version: '19.2'")
    lines.append("domain: ics-attack")
    lines.append("generated_by: tools/generate_attack_map.py")
    lines.append("")
    lines.append("techniques:")

    for tid, tech in tech_map.items():
        lines.append(f"  {tid}:")
        lines.append(f"    name: \"{tech['name']}\"")
        platforms_str = ", ".join(tech["platforms"])
        lines.append(f"    platforms: [{platforms_str}]")
        lines.append("    mitigations:")

        for mit in tech["mitigations"]:
            lines.append(f"      - id: {mit['id']}")
            lines.append(f"        name: \"{mit['name']}\"")
            lines.append(f"        class: {mit['class']}")
            if "role_name" in mit:
                lines.append(f"        role_name: {mit['role_name']}")
            lines.append(f"        mechanism: \"{mit['mechanism']}\"")

    lines.append("")
    output.write_text("\n".join(lines), encoding="utf-8")


def print_stats(tech_map: dict[str, dict[str, Any]]) -> None:
    """Print summary statistics to stdout."""
    total_techniques = len(tech_map)
    classes: dict[str, int] = {"enforce": 0, "partial": 0, "detect": 0, "skip": 0}
    unique_mitigations: set[str] = set()

    for tech in tech_map.values():
        for mit in tech["mitigations"]:
            unique_mitigations.add(mit["id"])
            classes[mit["class"]] += 1

    print(f"Techniques targeting Linux OT assets: {total_techniques}")
    print(f"Unique mitigations referenced: {len(unique_mitigations)}")
    print(f"Mitigation assignments by class:")
    for cls, count in sorted(classes.items()):
        print(f"  {cls}: {count}")
    print(f"Output: {OUTPUT_PATH}")


def main() -> None:
    if not STIX_PATH.exists():
        print(f"ERROR: STIX bundle not found at {STIX_PATH}", file=sys.stderr)
        print("Download it first:", file=sys.stderr)
        print(f"  curl -sL -o {STIX_PATH} \\", file=sys.stderr)
        print("    https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack-19.2.json", file=sys.stderr)
        sys.exit(1)

    bundle = load_stix(STIX_PATH)
    techniques, mitigations, relationships = extract_objects(bundle)
    tech_map = build_technique_mitigation_map(techniques, mitigations, relationships)
    emit_yaml(tech_map, OUTPUT_PATH)
    print_stats(tech_map)


if __name__ == "__main__":
    main()
