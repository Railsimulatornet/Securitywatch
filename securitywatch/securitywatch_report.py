#!/usr/bin/env python3
# Copyright Roman Glos 2026
import argparse
import html
import json
import re
import shlex
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "UNKNOWN": 4,
}


TRANSLATIONS = {
    "de": {
        "report_title": "UGREEN SecurityWatch Bericht",
        "host_filesystem": "Host-Dateisystem",
        "docker_image_prefix": "Docker-Image: ",
        "unique_total": "Eindeutige Schwachstellen gesamt",
        "raw_total": "Roh-Treffer vor Deduplizierung",
        "duplicates_removed": "Entfernte Dubletten",
        "critical_total": "Kritisch gesamt",
        "high_total": "Hoch gesamt",
        "unique": "Eindeutig",
        "critical": "Kritisch",
        "high": "Hoch",
        "host_section": "Host-Dateisystem",
        "docker_section": "Docker-Images",
        "docker_baselines": "Wichtigste Docker-Basisthemen",
        "images_affected": "Images betroffen",
        "top_host_findings": "Top Host-Funde",
        "top_docker_findings": "Top Docker-Einzelfunde",
        "sources_with_findings": "Quellen mit Treffern",
        "source": "Quelle",
        "sources_preview": "Quellen (Auszug)",
        "raw": "Roh",
        "cve": "CVE",
        "cvss": "CVSS",
        "severity": "Severity",
        "package": "Paket",
        "installed": "Installiert",
        "installed_preview": "Installiert (Auszug)",
        "fix": "Fix",
        "fix_preview": "Fix (Auszug)",
        "occurrences": "Vorkommen",
        "targets_preview": "Ziele (Auszug)",
        "affected_images": "Betroffene Images",
        "no_findings": "Keine Treffer.",
        "no_docker_findings": "Keine Docker-Treffer.",
        "no_host_findings": "Keine Host-Funde.",
        "no_docker_single_findings": "Keine Docker-Funde.",
        "other_more": "weitere",
        "other_smaller_docker_sources": "Weitere {count} kleinere Docker-Quellen",
        "other_docker_sources_summary": "Weitere {count} Docker-Quellen mit zusammen {unique} eindeutigen Treffern",
        "mail_note": "Hinweis: Diese Mail ist bewusst gekürzt und priorisiert. Die vollständigen Details stehen weiterhin im JSON-Report.",
        "top_docker_heading_txt": "Wichtigste Docker-Basisthemen:",
        "top_host_heading_txt": "Top Host-Funde:",
        "top_docker_single_heading_txt": "Top Docker-Einzelfunde:",
        "sources_heading_txt": "Quellen mit Treffern:",
        "major_host_sources_html": "Quellen mit Treffern: Host-Dateisystem",
        "major_docker_sources_html": "Quellen mit Treffern: Docker-Images",
        "count_line": "- {label}: {value}",
        "major_topic_line": "- {cve} - {pkg} - {severity} - {count} Images betroffen",
        "finding_line": "{cve} - CVSS {score} - {severity} - {pkg} - {source}{occ}",
        "source_line": "- {source}: {unique} eindeutig, {raw} roh, {duplicates} Dubletten entfernt",
        "source_line_other": "- Weitere {count} Docker-Quellen mit zusammen {unique} eindeutigen Treffern",
        "summary_box_total": "Eindeutig",
        "summary_box_critical": "Kritisch",
        "summary_box_high": "Hoch",
        "severity_critical": "Kritisch",
        "severity_high": "Hoch",
        "severity_medium": "Mittel",
        "severity_low": "Niedrig",
        "severity_unknown": "Unbekannt",
        "local_images_heading": "Lokale/selbst gebaute Docker-Images",
        "local_images_intro": "Automatisch erkannte lokale Compose-Build-Images. Die Erkennung ist generisch und kann bei Bedarf ueber .env-Muster ergaenzt oder eingeschraenkt werden.",
        "local_images_none": "Keine lokalen/selbst gebauten Docker-Images erkannt.",
        "local_image_fixable": "Behebbare Funde",
        "compose_project": "Compose-Projekt",
        "compose_service": "Compose-Service",
        "container": "Container",
        "top_local_image_findings": "Behebbare Paket-Funde in lokalen Images",
        "no_local_image_findings": "Keine behebbaren Paket-Funde in lokalen Images.",
        "script_version": "Script-Version",
        "footer_generated": "Erstellt mit UGREEN SecurityWatch",
        "copyright": "Copyright Roman Glos 2026",
    },
    "en": {
        "report_title": "UGREEN SecurityWatch Report",
        "host_filesystem": "Host filesystem",
        "docker_image_prefix": "Docker image: ",
        "unique_total": "Unique vulnerabilities total",
        "raw_total": "Raw findings before deduplication",
        "duplicates_removed": "Duplicates removed",
        "critical_total": "Critical total",
        "high_total": "High total",
        "unique": "Unique",
        "critical": "Critical",
        "high": "High",
        "host_section": "Host filesystem",
        "docker_section": "Docker images",
        "docker_baselines": "Top Docker base topics",
        "images_affected": "images affected",
        "top_host_findings": "Top host findings",
        "top_docker_findings": "Top Docker single findings",
        "sources_with_findings": "Sources with findings",
        "source": "Source",
        "sources_preview": "Sources (preview)",
        "raw": "Raw",
        "cve": "CVE",
        "cvss": "CVSS",
        "severity": "Severity",
        "package": "Package",
        "installed": "Installed",
        "installed_preview": "Installed (preview)",
        "fix": "Fix",
        "fix_preview": "Fix (preview)",
        "occurrences": "Occurrences",
        "targets_preview": "Targets (preview)",
        "affected_images": "Affected images",
        "no_findings": "No findings.",
        "no_docker_findings": "No Docker findings.",
        "no_host_findings": "No host findings.",
        "no_docker_single_findings": "No Docker findings.",
        "other_more": "more",
        "other_smaller_docker_sources": "{count} additional smaller Docker sources",
        "other_docker_sources_summary": "{count} additional Docker sources with {unique} unique findings combined",
        "mail_note": "Note: This email is intentionally shortened and prioritized. Full details are still available in the JSON report.",
        "top_docker_heading_txt": "Top Docker base topics:",
        "top_host_heading_txt": "Top host findings:",
        "top_docker_single_heading_txt": "Top Docker single findings:",
        "sources_heading_txt": "Sources with findings:",
        "major_host_sources_html": "Sources with findings: Host filesystem",
        "major_docker_sources_html": "Sources with findings: Docker images",
        "count_line": "- {label}: {value}",
        "major_topic_line": "- {cve} - {pkg} - {severity} - {count} images affected",
        "finding_line": "{cve} - CVSS {score} - {severity} - {pkg} - {source}{occ}",
        "source_line": "- {source}: {unique} unique, {raw} raw, {duplicates} duplicates removed",
        "source_line_other": "- {count} additional Docker sources with {unique} unique findings combined",
        "summary_box_total": "Unique",
        "summary_box_critical": "Critical",
        "summary_box_high": "High",
        "severity_critical": "Critical",
        "severity_high": "High",
        "severity_medium": "Medium",
        "severity_low": "Low",
        "severity_unknown": "Unknown",
        "local_images_heading": "Local / self-built Docker images",
        "local_images_intro": "Automatically detected local Compose build images. Detection is generic and can be extended or restricted with .env patterns if needed.",
        "local_images_none": "No local / self-built Docker images detected.",
        "local_image_fixable": "Fixable findings",
        "compose_project": "Compose project",
        "compose_service": "Compose service",
        "container": "Container",
        "top_local_image_findings": "Fixable package findings in local images",
        "no_local_image_findings": "No fixable package findings in local images.",
        "script_version": "Script version",
        "footer_generated": "Generated by UGREEN SecurityWatch",
        "copyright": "Copyright Roman Glos 2026",
    },
}


def parse_env(path: Path) -> dict:
    data = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()

        if not value:
            data[key] = ""
            continue

        try:
            parsed = shlex.split(value, comments=False, posix=True)
            if len(parsed) == 1:
                data[key] = parsed[0]
            else:
                data[key] = value
        except ValueError:
            data[key] = value

    return data


def normalize_lang(value: Optional[str]) -> str:
    lang = (value or "de").strip().lower()
    return lang if lang in {"de", "en"} else "de"


def tr(lang: str, key: str, **kwargs: Any) -> str:
    text = TRANSLATIONS[lang].get(key, key)
    return text.format(**kwargs)


def display_severity(severity: str, lang: str) -> str:
    mapping = {
        "CRITICAL": "severity_critical",
        "HIGH": "severity_high",
        "MEDIUM": "severity_medium",
        "LOW": "severity_low",
        "UNKNOWN": "severity_unknown",
    }
    return tr(lang, mapping.get(severity, "severity_unknown"))


def display_source(source_label: str, lang: str) -> str:
    if source_label == "Host-Dateisystem":
        return tr(lang, "host_filesystem")
    if source_label.startswith("Docker-Image: "):
        return tr(lang, "docker_image_prefix") + source_label[len("Docker-Image: "):]
    return source_label


def load_json(path: Path) -> Optional[dict]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def extract_score(vuln: Dict[str, Any]) -> Optional[float]:
    best: Optional[float] = None
    cvss = vuln.get("CVSS") or {}
    if isinstance(cvss, dict):
        for _, value in cvss.items():
            if not isinstance(value, dict):
                continue
            for key in ("V3Score", "V2Score"):
                raw = value.get(key)
                if isinstance(raw, (int, float)):
                    best = max(best, float(raw)) if best is not None else float(raw)

    for key in ("CVSSScore", "Score"):
        raw = vuln.get(key)
        if isinstance(raw, (int, float)):
            best = max(best, float(raw)) if best is not None else float(raw)

    return best


def score_to_text(score: Optional[float]) -> str:
    if score is None:
        return "-"
    return f"{score:.1f}"


def sanitize_image_ref(image_ref: str) -> str:
    return re.sub(r"[/:@]", "_", image_ref)


def load_image_name_map(run_dir: Path) -> Dict[str, str]:
    mapping: Dict[str, str] = {}

    map_file = run_dir / "images_map.tsv"
    if map_file.exists():
        for raw_line in map_file.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or "	" not in line:
                continue
            safe_name, image_ref = line.split("	", 1)
            safe_name = safe_name.strip()
            image_ref = image_ref.strip()
            if safe_name and image_ref:
                mapping[safe_name] = image_ref
        if mapping:
            return mapping

    images_file = run_dir / "images_scanned.txt"
    if images_file.exists():
        buckets: Dict[str, List[str]] = {}
        for raw_line in images_file.read_text(encoding="utf-8").splitlines():
            image_ref = raw_line.strip()
            if not image_ref:
                continue
            buckets.setdefault(sanitize_image_ref(image_ref), []).append(image_ref)

        for safe_name, refs in buckets.items():
            if len(refs) == 1:
                mapping[safe_name] = refs[0]

    return mapping


def normalize_source_label(path: Path, image_name_map: Dict[str, str]) -> str:
    if path.name in ("host_fs.json", "host_rootfs.json"):
        return "Host-Dateisystem"

    safe_name = path.stem.replace("image_", "", 1)
    image_ref = image_name_map.get(safe_name, safe_name)
    return f"Docker-Image: {image_ref}"


def source_group(source_label: str) -> str:
    return "host" if source_label == "Host-Dateisystem" else "docker"


def normalize_display_target(target: str) -> str:
    if not target:
        return ""

    prefixes = [
        "overlay/upper/",
        "rootfs/base/",
        "rom/",
    ]

    out = target
    for prefix in prefixes:
        if out.startswith(prefix):
            out = out[len(prefix):]
            break

    if out.startswith("ugreen/@appstore/"):
        out = out[len("ugreen/@appstore/"):]

    return out


def target_to_short_text(target: str, source_label: str) -> str:
    if not target or target == source_label:
        return source_label
    return normalize_display_target(str(target))


def dedupe_key(source_label: str, vuln: Dict[str, Any]) -> Tuple[str, str, str, str, str]:
    return (
        source_label,
        str(vuln.get("VulnerabilityID", "-")),
        str(vuln.get("PkgName", "-")),
        str(vuln.get("InstalledVersion", "-")),
        str(vuln.get("FixedVersion") or "-"),
    )


def collect_findings(run_dir: Path) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], int]:
    deduped: Dict[Tuple[str, str, str, str, str], Dict[str, Any]] = {}
    sources: List[Dict[str, Any]] = []
    raw_total = 0
    image_name_map = load_image_name_map(run_dir)

    for path in sorted(run_dir.glob("*.json")):
        if path.name == "summary.json":
            continue

        doc = load_json(path)
        if not doc:
            continue

        source_label = normalize_source_label(path, image_name_map)
        group = source_group(source_label)
        raw_count = 0

        for result in doc.get("Results") or []:
            target = target_to_short_text(result.get("Target") or source_label, source_label)
            vulns = result.get("Vulnerabilities") or []

            for vuln in vulns:
                raw_total += 1
                raw_count += 1
                score = extract_score(vuln)
                key = dedupe_key(source_label, vuln)

                if key not in deduped:
                    deduped[key] = {
                        "group": group,
                        "source": source_label,
                        "target": target,
                        "targets": [target] if target else [],
                        "occurrences": 1,
                        "cve": vuln.get("VulnerabilityID", "-"),
                        "severity": vuln.get("Severity", "UNKNOWN"),
                        "score": score,
                        "score_text": score_to_text(score),
                        "pkg": vuln.get("PkgName", "-"),
                        "installed": vuln.get("InstalledVersion", "-"),
                        "fixed": vuln.get("FixedVersion") or "-",
                        "title": vuln.get("Title") or "",
                        "primary_url": vuln.get("PrimaryURL") or "",
                    }
                else:
                    entry = deduped[key]
                    entry["occurrences"] += 1

                    if target and target not in entry["targets"]:
                        entry["targets"].append(target)

                    existing_score = entry.get("score")
                    if score is not None and (existing_score is None or score > existing_score):
                        entry["score"] = score
                        entry["score_text"] = score_to_text(score)

                    if not entry.get("title") and vuln.get("Title"):
                        entry["title"] = vuln.get("Title")

                    if not entry.get("primary_url") and vuln.get("PrimaryURL"):
                        entry["primary_url"] = vuln.get("PrimaryURL")

        unique_count = sum(1 for item in deduped.values() if item["source"] == source_label)
        sources.append(
            {
                "group": group,
                "source": source_label,
                "file": path.name,
                "raw_findings": raw_count,
                "unique_findings": unique_count,
                "duplicates_removed": max(raw_count - unique_count, 0),
            }
        )

    findings = list(deduped.values())
    findings.sort(
        key=lambda item: (
            SEVERITY_ORDER.get(item["severity"], 5),
            -(item["score"] if item["score"] is not None else -1),
            item["source"],
            item["pkg"],
            item["cve"],
        )
    )

    sources.sort(
        key=lambda src: (
            0 if src["group"] == "host" else 1,
            -src["unique_findings"],
            src["source"],
        )
    )

    return findings, sources, raw_total


def summarize_group(findings: List[Dict[str, Any]], group: str) -> Dict[str, int]:
    selected = [f for f in findings if f["group"] == group]
    return {
        "total": len(selected),
        "critical": sum(1 for f in selected if f["severity"] == "CRITICAL"),
        "high": sum(1 for f in selected if f["severity"] == "HIGH"),
    }


def aggregate_findings(findings: List[Dict[str, Any]], group: str) -> List[Dict[str, Any]]:
    aggregated: Dict[Tuple[str, str, str], Dict[str, Any]] = {}

    for item in findings:
        if item["group"] != group:
            continue

        key = (
            item["cve"],
            item["pkg"],
            item["severity"],
        )

        if key not in aggregated:
            aggregated[key] = {
                "group": group,
                "cve": item["cve"],
                "pkg": item["pkg"],
                "severity": item["severity"],
                "score": item["score"],
                "score_text": item["score_text"],
                "primary_url": item["primary_url"],
                "sources": [item["source"]],
                "installed_versions": [item["installed"]] if item["installed"] != "-" else [],
                "fixed_versions": [item["fixed"]] if item["fixed"] != "-" else [],
                "source_count": 1,
                "occurrences": item.get("occurrences", 1),
            }
        else:
            entry = aggregated[key]
            entry["occurrences"] += item.get("occurrences", 1)

            if item["source"] not in entry["sources"]:
                entry["sources"].append(item["source"])
                entry["source_count"] = len(entry["sources"])

            if item["installed"] != "-" and item["installed"] not in entry["installed_versions"]:
                entry["installed_versions"].append(item["installed"])

            if item["fixed"] != "-" and item["fixed"] not in entry["fixed_versions"]:
                entry["fixed_versions"].append(item["fixed"])

            existing_score = entry.get("score")
            item_score = item.get("score")
            if item_score is not None and (existing_score is None or item_score > existing_score):
                entry["score"] = item_score
                entry["score_text"] = item["score_text"]

            if not entry.get("primary_url") and item.get("primary_url"):
                entry["primary_url"] = item["primary_url"]

    rows = list(aggregated.values())
    rows.sort(
        key=lambda item: (
            SEVERITY_ORDER.get(item["severity"], 5),
            -(item["score"] if item["score"] is not None else -1),
            -item["source_count"],
            -item["occurrences"],
            item["pkg"],
            item["cve"],
        )
    )
    return rows


def build_top_lines(findings: List[Dict[str, Any]], lang: str, limit: int = 15) -> List[str]:
    lines: List[str] = []
    for item in findings[:limit]:
        occ = f" ({item['occurrences']}x)" if item.get("occurrences", 1) > 1 else ""
        lines.append(
            tr(
                lang,
                "finding_line",
                cve=item["cve"],
                score=item["score_text"],
                severity=display_severity(item["severity"], lang),
                pkg=item["pkg"],
                source=display_source(item["source"], lang),
                occ=occ,
            )
        )
    return lines


def severity_badge(severity: str, lang: str) -> str:
    colors = {
        "CRITICAL": "#b91c1c",
        "HIGH": "#c2410c",
        "MEDIUM": "#a16207",
        "LOW": "#1d4ed8",
        "UNKNOWN": "#4b5563",
    }
    color = colors.get(severity, "#4b5563")
    return (
        f"<span style='display:inline-block;padding:2px 8px;border-radius:999px;"
        f"background:{color};color:#fff;font-weight:600;font-size:12px;'>{html.escape(display_severity(severity, lang))}</span>"
    )


def summarize_sources_for_mail(sources: List[Dict[str, Any]], group: str) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    selected = [s for s in sources if s["group"] == group and s["unique_findings"] > 0]

    if group == "docker":
        major = [s for s in selected if s["unique_findings"] >= 3]
        minor = [s for s in selected if s["unique_findings"] < 3]
        minor_summary = {
            "count": len(minor),
            "unique_findings": sum(s["unique_findings"] for s in minor),
            "raw_findings": sum(s["raw_findings"] for s in minor),
            "duplicates_removed": sum(s["duplicates_removed"] for s in minor),
        }
        return major, minor_summary

    return selected, {"count": 0, "unique_findings": 0, "raw_findings": 0, "duplicates_removed": 0}


def localized_target(value: str, internal_source: str, lang: str) -> str:
    return display_source(internal_source, lang) if value == internal_source else value


def localize_finding(item: Dict[str, Any], lang: str) -> Dict[str, Any]:
    out = dict(item)
    out["source_internal"] = item["source"]
    out["source"] = display_source(item["source"], lang)
    out["severity_display"] = display_severity(item["severity"], lang)
    if "target" in out:
        out["target"] = localized_target(str(out["target"]), item["source"], lang)
    out["targets"] = [localized_target(str(target), item["source"], lang) for target in item.get("targets", [])]
    return out


def localize_source(item: Dict[str, Any], lang: str) -> Dict[str, Any]:
    out = dict(item)
    out["source_internal"] = item["source"]
    out["source"] = display_source(item["source"], lang)
    return out


def localize_aggregate(item: Dict[str, Any], lang: str) -> Dict[str, Any]:
    out = dict(item)
    out["severity_display"] = display_severity(item["severity"], lang)
    out["sources_internal"] = list(item["sources"])
    out["sources"] = [display_source(source, lang) for source in item["sources"]]
    return out



def load_local_built_images(run_dir: Path) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    tsv = run_dir / "local-built-images.tsv"
    if not tsv.exists():
        return rows

    seen = set()
    for raw_line in tsv.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split("\t")
        if parts and parts[0].strip().lower() == "image":
            continue

        image = parts[0].strip() if len(parts) > 0 else ""
        container = parts[1].strip() if len(parts) > 1 else ""
        project = parts[2].strip() if len(parts) > 2 else ""
        service = parts[3].strip() if len(parts) > 3 else ""

        if not image or image in seen:
            continue

        seen.add(image)
        rows.append(
            {
                "image": image,
                "container": container,
                "project": project,
                "service": service,
            }
        )

    rows.sort(key=lambda item: item["image"])
    return rows


def local_image_finding_rows(findings: List[Dict[str, Any]], local_images: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    local_image_set = {item["image"] for item in local_images if item.get("image")}
    selected = [
        item
        for item in findings
        if item.get("group") == "docker"
        and item.get("source", "").startswith("Docker-Image: ")
        and item.get("source", "")[len("Docker-Image: "):] in local_image_set
        and item.get("fixed")
        and item.get("fixed") != "-"
    ]

    selected.sort(
        key=lambda item: (
            item.get("source", ""),
            SEVERITY_ORDER.get(item.get("severity", "UNKNOWN"), 5),
            -(item.get("score") if item.get("score") is not None else -1),
            item.get("pkg", ""),
            item.get("cve", ""),
        )
    )
    return selected


def local_image_summary(findings: List[Dict[str, Any]], local_images: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    selected = local_image_finding_rows(findings, local_images)
    by_image: Dict[str, List[Dict[str, Any]]] = {}
    for item in selected:
        image = item["source"][len("Docker-Image: "):]
        by_image.setdefault(image, []).append(item)

    rows: List[Dict[str, Any]] = []
    for image_info in local_images:
        image = image_info["image"]
        items = by_image.get(image, [])
        rows.append(
            {
                **image_info,
                "fixable": len(items),
                "critical": sum(1 for item in items if item.get("severity") == "CRITICAL"),
                "high": sum(1 for item in items if item.get("severity") == "HIGH"),
            }
        )

    rows.sort(key=lambda item: (-item["fixable"], item["image"]))
    return rows


def build_local_image_text(findings: List[Dict[str, Any]], local_images: List[Dict[str, str]], lang: str) -> List[str]:
    lines: List[str] = []
    lines.append(tr(lang, "local_images_heading") + ":")
    if not local_images:
        lines.append(tr(lang, "local_images_none"))
        lines.append("")
        return lines

    for row in local_image_summary(findings, local_images):
        details = []
        if row.get("project"):
            details.append(f"{tr(lang, 'compose_project')}: {row['project']}")
        if row.get("service"):
            details.append(f"{tr(lang, 'compose_service')}: {row['service']}")
        detail_text = f" ({', '.join(details)})" if details else ""
        lines.append(
            f"- {row['image']}: {row['fixable']} {tr(lang, 'local_image_fixable')}, "
            f"{row['critical']} {tr(lang, 'critical')}, {row['high']} {tr(lang, 'high')}{detail_text}"
        )

    local_findings = local_image_finding_rows(findings, local_images)
    lines.append("")
    lines.append(tr(lang, "top_local_image_findings") + ":")
    if not local_findings:
        lines.append(tr(lang, "no_local_image_findings"))
    else:
        for item in local_findings[:12]:
            image = item["source"][len("Docker-Image: "):]
            lines.append(
                f"- {image} - {item['cve']} - CVSS {item['score_text']} - "
                f"{display_severity(item['severity'], lang)} - {item['pkg']} - "
                f"{item['installed']} -> {item['fixed']}"
            )
        if len(local_findings) > 12:
            lines.append(f"- ... +{len(local_findings) - 12} {tr(lang, 'other_more')}")

    lines.append("")
    return lines


def build_local_image_summary_table(findings: List[Dict[str, Any]], local_images: List[Dict[str, str]], lang: str) -> str:
    if not local_images:
        return f"<p>{html.escape(tr(lang, 'local_images_none'))}</p>"

    rows = []
    for item in local_image_summary(findings, local_images):
        rows.append(
            "<tr>"
            f"<td>{html.escape(item['image'])}</td>"
            f"<td>{html.escape(item.get('container') or '-')}</td>"
            f"<td>{html.escape(item.get('project') or '-')}</td>"
            f"<td>{html.escape(item.get('service') or '-')}</td>"
            f"<td>{item['fixable']}</td>"
            f"<td>{item['critical']}</td>"
            f"<td>{item['high']}</td>"
            "</tr>"
        )

    return (
        "<table border='1' cellspacing='0' cellpadding='6' style='border-collapse:collapse;'>"
        f"<tr><th>{html.escape(tr(lang, 'source'))}</th>"
        f"<th>{html.escape(tr(lang, 'container'))}</th>"
        f"<th>{html.escape(tr(lang, 'compose_project'))}</th>"
        f"<th>{html.escape(tr(lang, 'compose_service'))}</th>"
        f"<th>{html.escape(tr(lang, 'local_image_fixable'))}</th>"
        f"<th>{html.escape(tr(lang, 'critical'))}</th>"
        f"<th>{html.escape(tr(lang, 'high'))}</th></tr>"
        + "".join(rows)
        + "</table>"
    )


def build_local_image_finding_table(findings: List[Dict[str, Any]], local_images: List[Dict[str, str]], lang: str, limit: int = 15) -> str:
    selected = local_image_finding_rows(findings, local_images)
    if not selected:
        return f"<p>{html.escape(tr(lang, 'no_local_image_findings'))}</p>"

    rows = []
    for item in selected[:limit]:
        image = item["source"][len("Docker-Image: "):]
        url = html.escape(item["primary_url"]) if item["primary_url"] else ""
        cve = html.escape(item["cve"])
        cve_html = f'<a href="{url}">{cve}</a>' if url else cve

        target_preview = ", ".join(item.get("targets", [])[:2])
        if len(item.get("targets", [])) > 2:
            target_preview += f" (+{len(item['targets']) - 2} {tr(lang, 'other_more')})"

        rows.append(
            "<tr>"
            f"<td>{html.escape(image)}</td>"
            f"<td>{cve_html}</td>"
            f"<td>{html.escape(item['score_text'])}</td>"
            f"<td>{severity_badge(item['severity'], lang)}</td>"
            f"<td>{html.escape(item['pkg'])}</td>"
            f"<td>{html.escape(item['installed'])}</td>"
            f"<td>{html.escape(item['fixed'])}</td>"
            f"<td>{html.escape(target_preview)}</td>"
            "</tr>"
        )

    if len(selected) > limit:
        rows.append(
            "<tr>"
            f"<td colspan='8'>{html.escape('+' + str(len(selected) - limit) + ' ' + tr(lang, 'other_more'))}</td>"
            "</tr>"
        )

    return (
        "<table border='1' cellspacing='0' cellpadding='6' style='border-collapse:collapse;'>"
        f"<tr><th>{html.escape(tr(lang, 'source'))}</th>"
        f"<th>{html.escape(tr(lang, 'cve'))}</th>"
        f"<th>{html.escape(tr(lang, 'cvss'))}</th>"
        f"<th>{html.escape(tr(lang, 'severity'))}</th>"
        f"<th>{html.escape(tr(lang, 'package'))}</th>"
        f"<th>{html.escape(tr(lang, 'installed'))}</th>"
        f"<th>{html.escape(tr(lang, 'fix'))}</th>"
        f"<th>{html.escape(tr(lang, 'targets_preview'))}</th></tr>"
        + "".join(rows)
        + "</table>"
    )


def footer_text(lang: str, script_version: str) -> str:
    version = script_version or "-"
    copyright_line = tr(lang, "copyright")
    return (
        f"{tr(lang, 'footer_generated')}\n"
        f"{tr(lang, 'script_version')}: {version}\n"
        f"{copyright_line}\n"
    )


def footer_html(lang: str, script_version: str) -> str:
    version = script_version or "-"
    copyright_line = tr(lang, "copyright")
    return (
        "<hr style='border:none;border-top:1px solid #d1d5db;margin-top:22px;'>"
        "<p style='font-size:12px;color:#6b7280;margin-top:10px;'>"
        f"{html.escape(tr(lang, 'footer_generated'))}<br>"
        f"{html.escape(tr(lang, 'script_version'))}: {html.escape(version)}<br>"
        f"{html.escape(copyright_line)}"
        "</p>"
    )


def build_text(findings: List[Dict[str, Any]], sources: List[Dict[str, Any]], raw_total: int, lang: str, run_dir: Path, script_version: str) -> str:
    overall_critical = sum(1 for f in findings if f["severity"] == "CRITICAL")
    overall_high = sum(1 for f in findings if f["severity"] == "HIGH")
    duplicates_removed = max(raw_total - len(findings), 0)

    host_summary = summarize_group(findings, "host")
    docker_summary = summarize_group(findings, "docker")

    host_findings = [f for f in findings if f["group"] == "host"]
    docker_findings = [f for f in findings if f["group"] == "docker"]
    docker_agg = aggregate_findings(findings, "docker")

    host_sources, _ = summarize_sources_for_mail(sources, "host")
    docker_sources, docker_minor = summarize_sources_for_mail(sources, "docker")
    local_images = load_local_built_images(run_dir)

    lines: List[str] = []
    lines.append(tr(lang, "report_title"))
    lines.append("")
    lines.append(f"{tr(lang, 'unique_total')}: {len(findings)}")
    lines.append(f"{tr(lang, 'raw_total')}: {raw_total}")
    lines.append(f"{tr(lang, 'duplicates_removed')}: {duplicates_removed}")
    lines.append(f"{tr(lang, 'critical_total')}: {overall_critical}")
    lines.append(f"{tr(lang, 'high_total')}: {overall_high}")
    lines.append("")
    lines.append(f"{tr(lang, 'host_section')}:")
    lines.append(tr(lang, "count_line", label=tr(lang, "unique"), value=host_summary["total"]))
    lines.append(tr(lang, "count_line", label=tr(lang, "critical"), value=host_summary["critical"]))
    lines.append(tr(lang, "count_line", label=tr(lang, "high"), value=host_summary["high"]))
    lines.append("")
    lines.append(f"{tr(lang, 'docker_section')}:")
    lines.append(tr(lang, "count_line", label=tr(lang, "unique"), value=docker_summary["total"]))
    lines.append(tr(lang, "count_line", label=tr(lang, "critical"), value=docker_summary["critical"]))
    lines.append(tr(lang, "count_line", label=tr(lang, "high"), value=docker_summary["high"]))
    lines.append("")

    lines.append(tr(lang, "top_docker_heading_txt"))
    if docker_agg:
        for item in docker_agg[:10]:
            lines.append(
                tr(
                    lang,
                    "major_topic_line",
                    cve=item["cve"],
                    pkg=item["pkg"],
                    severity=display_severity(item["severity"], lang),
                    count=item["source_count"],
                )
            )
    else:
        lines.append(tr(lang, "no_docker_findings"))
    lines.append("")

    if host_findings:
        lines.append(tr(lang, "top_host_heading_txt"))
        lines.append("")
        lines.extend(build_top_lines(host_findings, lang, limit=12))
        lines.append("")

    if docker_findings:
        lines.append(tr(lang, "top_docker_single_heading_txt"))
        lines.append("")
        lines.extend(build_top_lines(docker_findings, lang, limit=10))
        lines.append("")

    lines.append(tr(lang, "sources_heading_txt"))
    if not host_sources and not docker_sources and docker_minor["count"] == 0:
        lines.append(tr(lang, "no_findings"))
    for src in host_sources:
        lines.append(
            tr(
                lang,
                "source_line",
                source=display_source(src["source"], lang),
                unique=src["unique_findings"],
                raw=src["raw_findings"],
                duplicates=src["duplicates_removed"],
            )
        )

    for src in docker_sources:
        lines.append(
            tr(
                lang,
                "source_line",
                source=display_source(src["source"], lang),
                unique=src["unique_findings"],
                raw=src["raw_findings"],
                duplicates=src["duplicates_removed"],
            )
        )

    if docker_minor["count"] > 0:
        lines.append(
            tr(
                lang,
                "source_line_other",
                count=docker_minor["count"],
                unique=docker_minor["unique_findings"],
            )
        )

    lines.append("")
    lines.extend(build_local_image_text(findings, local_images, lang))
    lines.append(tr(lang, "mail_note"))
    lines.append("")
    lines.append(footer_text(lang, script_version))

    return "\n".join(lines) + "\n"


def build_source_rows(sources: List[Dict[str, Any]], group: str, lang: str) -> str:
    selected, minor = summarize_sources_for_mail(sources, group)
    if not selected and minor["count"] == 0:
        return f"<p>{html.escape(tr(lang, 'no_findings'))}</p>"

    rows = []
    for src in selected:
        rows.append(
            "<tr>"
            f"<td>{html.escape(display_source(src['source'], lang))}</td>"
            f"<td>{src['unique_findings']}</td>"
            f"<td>{src['raw_findings']}</td>"
            f"<td>{src['duplicates_removed']}</td>"
            "</tr>"
        )

    if group == "docker" and minor["count"] > 0:
        rows.append(
            "<tr>"
            f"<td>{html.escape(tr(lang, 'other_smaller_docker_sources', count=minor['count']))}</td>"
            f"<td>{minor['unique_findings']}</td>"
            f"<td>{minor['raw_findings']}</td>"
            f"<td>{minor['duplicates_removed']}</td>"
            "</tr>"
        )

    return (
        "<table border='1' cellspacing='0' cellpadding='6' style='border-collapse:collapse;'>"
        f"<tr><th>{html.escape(tr(lang, 'source'))}</th><th>{html.escape(tr(lang, 'unique'))}</th>"
        f"<th>{html.escape(tr(lang, 'raw'))}</th><th>{html.escape(tr(lang, 'duplicates_removed'))}</th></tr>"
        + "".join(rows)
        + "</table>"
    )


def build_finding_rows(findings: List[Dict[str, Any]], lang: str, limit: int) -> str:
    rows: List[str] = []

    for item in findings[:limit]:
        url = html.escape(item["primary_url"]) if item["primary_url"] else ""
        cve = html.escape(item["cve"])
        cve_html = f'<a href="{url}">{cve}</a>' if url else cve

        target_preview = ", ".join(item.get("targets", [])[:3])
        if len(item.get("targets", [])) > 3:
            target_preview += f" (+{len(item['targets']) - 3} {tr(lang, 'other_more')})"

        rows.append(
            "<tr>"
            f"<td>{cve_html}</td>"
            f"<td>{html.escape(item['score_text'])}</td>"
            f"<td>{severity_badge(item['severity'], lang)}</td>"
            f"<td>{html.escape(item['pkg'])}</td>"
            f"<td>{html.escape(item['installed'])}</td>"
            f"<td>{html.escape(item['fixed'])}</td>"
            f"<td>{html.escape(str(item.get('occurrences', 1)))}</td>"
            f"<td>{html.escape(display_source(item['source'], lang))}</td>"
            f"<td>{html.escape(target_preview)}</td>"
            "</tr>"
        )

    return "".join(rows)


def build_aggregate_rows(items: List[Dict[str, Any]], lang: str, limit: int) -> str:
    rows: List[str] = []

    for item in items[:limit]:
        url = html.escape(item["primary_url"]) if item["primary_url"] else ""
        cve = html.escape(item["cve"])
        cve_html = f'<a href="{url}">{cve}</a>' if url else cve

        source_preview = ", ".join(display_source(src, lang) for src in item["sources"][:3])
        if len(item["sources"]) > 3:
            source_preview += f" (+{len(item['sources']) - 3} {tr(lang, 'other_more')})"

        installed_preview = ", ".join(item["installed_versions"][:3]) if item["installed_versions"] else "-"
        if len(item["installed_versions"]) > 3:
            installed_preview += f" (+{len(item['installed_versions']) - 3} {tr(lang, 'other_more')})"

        fixed_preview = ", ".join(item["fixed_versions"][:3]) if item["fixed_versions"] else "-"
        if len(item["fixed_versions"]) > 3:
            fixed_preview += f" (+{len(item['fixed_versions']) - 3} {tr(lang, 'other_more')})"

        rows.append(
            "<tr>"
            f"<td>{cve_html}</td>"
            f"<td>{html.escape(item['score_text'])}</td>"
            f"<td>{severity_badge(item['severity'], lang)}</td>"
            f"<td>{html.escape(item['pkg'])}</td>"
            f"<td>{html.escape(installed_preview)}</td>"
            f"<td>{html.escape(fixed_preview)}</td>"
            f"<td>{item['source_count']}</td>"
            f"<td>{item['occurrences']}</td>"
            f"<td>{html.escape(source_preview)}</td>"
            "</tr>"
        )

    return "".join(rows)


def summary_box(title: str, total: int, critical: int, high: int, lang: str) -> str:
    return (
        "<div style='border:1px solid #d1d5db;border-radius:10px;padding:12px;min-width:220px;background:#fafafa;'>"
        f"<h3 style='margin-top:0;margin-bottom:8px'>{html.escape(title)}</h3>"
        f"<p style='margin:0'>{html.escape(tr(lang, 'summary_box_total'))}: <strong>{total}</strong><br>"
        f"{html.escape(tr(lang, 'summary_box_critical'))}: <strong>{critical}</strong><br>"
        f"{html.escape(tr(lang, 'summary_box_high'))}: <strong>{high}</strong></p>"
        "</div>"
    )


def build_html(findings: List[Dict[str, Any]], sources: List[Dict[str, Any]], raw_total: int, lang: str, run_dir: Path, script_version: str) -> str:
    overall_critical = sum(1 for f in findings if f["severity"] == "CRITICAL")
    overall_high = sum(1 for f in findings if f["severity"] == "HIGH")
    duplicates_removed = max(raw_total - len(findings), 0)

    host_summary = summarize_group(findings, "host")
    docker_summary = summarize_group(findings, "docker")

    host_findings = [f for f in findings if f["group"] == "host"]
    docker_findings = [f for f in findings if f["group"] == "docker"]
    docker_agg = aggregate_findings(findings, "docker")
    local_images = load_local_built_images(run_dir)

    host_table = build_finding_rows(host_findings, lang, limit=12)
    docker_table = build_finding_rows(docker_findings, lang, limit=10)
    docker_agg_table = build_aggregate_rows(docker_agg, lang, limit=10)

    parts: List[str] = [
        "<html><body style='font-family:Segoe UI,Arial,sans-serif;font-size:14px;color:#111827;'>",
        f"<h2 style='margin-bottom:8px'>{html.escape(tr(lang, 'report_title'))}</h2>",
        (
            f"<p>{html.escape(tr(lang, 'unique_total'))}: <strong>{len(findings)}</strong><br>"
            f"{html.escape(tr(lang, 'raw_total'))}: <strong>{raw_total}</strong><br>"
            f"{html.escape(tr(lang, 'duplicates_removed'))}: <strong>{duplicates_removed}</strong><br>"
            f"{html.escape(tr(lang, 'critical_total'))}: <strong>{overall_critical}</strong><br>"
            f"{html.escape(tr(lang, 'high_total'))}: <strong>{overall_high}</strong></p>"
        ),
        "<div style='display:flex;gap:12px;flex-wrap:wrap;margin:16px 0;'>",
        summary_box(tr(lang, 'host_section'), host_summary["total"], host_summary["critical"], host_summary["high"], lang),
        summary_box(tr(lang, 'docker_section'), docker_summary["total"], docker_summary["critical"], docker_summary["high"], lang),
        "</div>",
        f"<h3>{html.escape(tr(lang, 'major_host_sources_html'))}</h3>",
        build_source_rows(sources, "host", lang),
        f"<h3>{html.escape(tr(lang, 'major_docker_sources_html'))}</h3>",
        build_source_rows(sources, "docker", lang),
        f"<h3>{html.escape(tr(lang, 'docker_baselines'))}</h3>",
    ]

    if docker_agg_table:
        parts.extend(
            [
                "<table border='1' cellspacing='0' cellpadding='6' style='border-collapse:collapse;'>",
                f"<tr><th>{html.escape(tr(lang, 'cve'))}</th><th>{html.escape(tr(lang, 'cvss'))}</th>"
                f"<th>{html.escape(tr(lang, 'severity'))}</th><th>{html.escape(tr(lang, 'package'))}</th>"
                f"<th>{html.escape(tr(lang, 'installed_preview'))}</th><th>{html.escape(tr(lang, 'fix_preview'))}</th>"
                f"<th>{html.escape(tr(lang, 'affected_images'))}</th><th>{html.escape(tr(lang, 'occurrences'))}</th>"
                f"<th>{html.escape(tr(lang, 'sources_preview'))}</th></tr>",
                docker_agg_table,
                "</table>",
            ]
        )
    else:
        parts.append(f"<p>{html.escape(tr(lang, 'no_docker_findings'))}</p>")

    parts.append(f"<h3>{html.escape(tr(lang, 'top_host_findings'))}</h3>")
    if host_table:
        parts.extend(
            [
                "<table border='1' cellspacing='0' cellpadding='6' style='border-collapse:collapse;'>",
                f"<tr><th>{html.escape(tr(lang, 'cve'))}</th><th>{html.escape(tr(lang, 'cvss'))}</th>"
                f"<th>{html.escape(tr(lang, 'severity'))}</th><th>{html.escape(tr(lang, 'package'))}</th>"
                f"<th>{html.escape(tr(lang, 'installed'))}</th><th>{html.escape(tr(lang, 'fix'))}</th>"
                f"<th>{html.escape(tr(lang, 'occurrences'))}</th><th>{html.escape(tr(lang, 'source'))}</th>"
                f"<th>{html.escape(tr(lang, 'targets_preview'))}</th></tr>",
                host_table,
                "</table>",
            ]
        )
    else:
        parts.append(f"<p>{html.escape(tr(lang, 'no_host_findings'))}</p>")

    parts.append(f"<h3>{html.escape(tr(lang, 'top_docker_findings'))}</h3>")
    if docker_table:
        parts.extend(
            [
                "<table border='1' cellspacing='0' cellpadding='6' style='border-collapse:collapse;'>",
                f"<tr><th>{html.escape(tr(lang, 'cve'))}</th><th>{html.escape(tr(lang, 'cvss'))}</th>"
                f"<th>{html.escape(tr(lang, 'severity'))}</th><th>{html.escape(tr(lang, 'package'))}</th>"
                f"<th>{html.escape(tr(lang, 'installed'))}</th><th>{html.escape(tr(lang, 'fix'))}</th>"
                f"<th>{html.escape(tr(lang, 'occurrences'))}</th><th>{html.escape(tr(lang, 'source'))}</th>"
                f"<th>{html.escape(tr(lang, 'targets_preview'))}</th></tr>",
                docker_table,
                "</table>",
            ]
        )
    else:
        parts.append(f"<p>{html.escape(tr(lang, 'no_docker_single_findings'))}</p>")

    parts.extend(
        [
            f"<h3>{html.escape(tr(lang, 'local_images_heading'))}</h3>",
            f"<p style='color:#4b5563;'>{html.escape(tr(lang, 'local_images_intro'))}</p>",
            build_local_image_summary_table(findings, local_images, lang),
            f"<h3>{html.escape(tr(lang, 'top_local_image_findings'))}</h3>",
            build_local_image_finding_table(findings, local_images, lang, limit=15),
            "<p style='margin-top:18px;color:#4b5563;'>",
            html.escape(tr(lang, 'mail_note')),
            "</p>",
            footer_html(lang, script_version),
            "</body></html>",
        ]
    )

    return "".join(parts)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--summary-json", required=True)
    parser.add_argument("--mail-txt", required=True)
    parser.add_argument("--mail-html", required=True)
    parser.add_argument("--env-file")
    parser.add_argument("--lang")
    parser.add_argument("--script-version", default="")
    args = parser.parse_args()

    lang = normalize_lang(args.lang)
    if args.env_file:
        env = parse_env(Path(args.env_file))
        lang = normalize_lang(args.lang or env.get("OUTPUT_LANG") or env.get("LANGUAGE") or env.get("MAIL_LANG"))

    run_dir = Path(args.run_dir)
    findings, sources, raw_total = collect_findings(run_dir)

    host_summary = summarize_group(findings, "host")
    docker_summary = summarize_group(findings, "docker")

    summary = {
        "language": lang,
        "total": len(findings),
        "raw_total": raw_total,
        "duplicates_removed": max(raw_total - len(findings), 0),
        "critical": sum(1 for f in findings if f["severity"] == "CRITICAL"),
        "high": sum(1 for f in findings if f["severity"] == "HIGH"),
        "host": host_summary,
        "docker": docker_summary,
        "script_version": args.script_version,
        "local_built_images": local_image_summary(findings, load_local_built_images(run_dir)),
        "local_built_image_findings": [localize_finding(item, lang) for item in local_image_finding_rows(findings, load_local_built_images(run_dir))],
        "findings": [localize_finding(item, lang) for item in findings],
        "docker_aggregated": [localize_aggregate(item, lang) for item in aggregate_findings(findings, "docker")],
        "sources": [localize_source(item, lang) for item in sources],
    }

    Path(args.summary_json).write_text(
        json.dumps(summary, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    Path(args.mail_txt).write_text(build_text(findings, sources, raw_total, lang, run_dir, args.script_version), encoding="utf-8")
    Path(args.mail_html).write_text(build_html(findings, sources, raw_total, lang, run_dir, args.script_version), encoding="utf-8")


if __name__ == "__main__":
    main()
