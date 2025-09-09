#!/usr/bin/env python3
import argparse
import json
import os
import sys
from dataclasses import dataclass, asdict
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import yaml  # type: ignore
except Exception as exc:  # pragma: no cover
    print("Missing dependency: PyYAML. Run: pip install -r requirements.txt", file=sys.stderr)
    raise

try:
    import requests  # type: ignore
except Exception:
    requests = None  # Optional; only needed for GitHub/AI API


GATE_KEYWORDS: Dict[str, List[str]] = {
    "tests": ["pytest", "unittest", "mvn test", "gradle test", "go test", "npm test", "yarn test", "pnpm test"],
    "coverage": ["coverage", "codecov", "nyc", "jest --coverage", "pytest --cov"],
    "lint": ["eslint", "flake8", "ruff", "pylint", "golangci-lint", "stylelint", "tsc --noEmit", "mypy"],
    "sast": ["semgrep", "codeql", "bandit", "sonar-scanner", "snyk code test"],
    "dast": ["owasp-zap", "zap-baseline.py", "zap-full-scan.py", "nikto"],
    "sca": ["trivy fs", "trivy repo", "grype", "snyk test", "pip-audit", "npm audit"],
    "iac": ["tfsec", "checkov", "kics"],
    "container": ["trivy image", "grype", "dockle"],
    "secrets": ["gitleaks", "detect-secrets", "trufflehog"],
    "release_protection": ["require", "environment", "deployment", "release", "protection"],
}


ISO25010_MAP: Dict[str, List[str]] = {
    # Map gate categories to ISO/IEC 25010:2023 characteristics/subcharacteristics
    "tests": [
        "Functional suitability: correctness",
        "Reliability: faultlessness",
        "Maintainability: testability",
    ],
    "coverage": [
        "Maintainability: testability",
        "Maintainability: analysability",
    ],
    "lint": [
        "Maintainability: analysability",
        "Maintainability: modifiability",
    ],
    "sast": [
        "Security: resistance",
        "Security: integrity",
        "Security: accountability",
        "Maintainability: analysability",
    ],
    "dast": [
        "Security: resistance",
        "Security: authenticity",
        "Security: non-repudiation",
    ],
    "sca": [
        "Security: integrity",
        "Security: authenticity",
        "Reliability: fault tolerance",
    ],
    "iac": [
        "Security: confidentiality",
        "Security: integrity",
        "Safety: safe integration",
    ],
    "container": [
        "Security: resistance",
        "Reliability: recoverability",
        "Performance efficiency: resource use",
    ],
    "secrets": [
        "Security: confidentiality",
        "Security: accountability",
    ],
    "release_protection": [
        "Reliability: availability",
        "Security: accountability",
        "Safety: hazard warning",
    ],
}


@dataclass
class GateEvidence:
    workflow: str
    job: str
    step: str
    step_uses: Optional[str]
    step_run: Optional[str]


@dataclass
class DetectedGate:
    category: str
    name: str
    iso25010: List[str]
    evidence: GateEvidence
    evaluation: Dict[str, Any]


def read_yaml_file(path: Path) -> Optional[Dict[str, Any]]:
    try:
        with path.open("r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return None


def iter_workflow_files(repo_dir: Path) -> List[Path]:
    workflows_dir = repo_dir / ".github" / "workflows"
    if not workflows_dir.exists():
        return []
    return sorted([p for p in workflows_dir.glob("*.yml")] + [p for p in workflows_dir.glob("*.yaml")])


def text_in_step(step: Dict[str, Any]) -> str:
    parts: List[str] = []
    for key in ("name", "uses", "run"):
        v = step.get(key)
        if isinstance(v, str):
            parts.append(v)
    return " \n ".join(parts).lower()


def detect_gate_category(step_text: str) -> Optional[str]:
    for category, patterns in GATE_KEYWORDS.items():
        for pat in patterns:
            if pat in step_text:
                return category
    # Heuristics for common step names
    if "lint" in step_text:
        return "lint"
    if "test" in step_text:
        return "tests"
    if "coverage" in step_text or "codecov" in step_text:
        return "coverage"
    return None


def evaluate_gate(category: str, evidence_text: str) -> Dict[str, Any]:
    # Simple heuristic scoring [0..1]
    sufficiency = 0.6
    completeness = 0.5
    redundancy = 0.5
    resilience = 0.4

    # Heuristics
    if category in ("tests", "lint") and ("--max-warnings=0" in evidence_text or "-Werror" in evidence_text):
        sufficiency += 0.2
    if category == "coverage" and any(k in evidence_text for k in ["--coverage", "--cov", "nyc", "codecov"]):
        sufficiency += 0.2
        completeness += 0.2
    if category in ("sast", "sca", "iac", "container", "secrets") and any(k in evidence_text for k in ["--severity", "--exit-code", "--policy", "--baseline"]):
        sufficiency += 0.2
    if any(k in evidence_text for k in ["retry", "retries", "max-attempts", "timeout-minutes", "continue-on-error: false"]):
        resilience += 0.2

    # Bound to [0,1]
    def clamp(v: float) -> float:
        return max(0.0, min(1.0, round(v, 2)))

    return {
        "sufficiency": clamp(sufficiency),
        "completeness": clamp(completeness),
        "redundancy": clamp(redundancy),
        "resilience": clamp(resilience),
    }


def analyze_workflows(repo_dir: Path) -> Tuple[List[DetectedGate], List[str]]:
    gates: List[DetectedGate] = []
    notes: List[str] = []
    for wf_path in iter_workflow_files(repo_dir):
        data = read_yaml_file(wf_path)
        if not data:
            continue
        wf_name = str(data.get("name", wf_path.name))
        jobs = data.get("jobs", {}) or {}
        if not isinstance(jobs, dict):
            continue
        for job_id, job_data in jobs.items():
            steps = (job_data or {}).get("steps", []) or []
            if not isinstance(steps, list):
                continue
            for step in steps:
                if not isinstance(step, dict):
                    continue
                step_text = text_in_step(step)
                category = detect_gate_category(step_text)
                if not category:
                    continue
                iso_map = ISO25010_MAP.get(category, [])
                evaluation = evaluate_gate(category, step_text)
                gates.append(
                    DetectedGate(
                        category=category,
                        name=step.get("name") or step.get("uses") or (step.get("run", "").split("\n")[0][:80] or category),
                        iso25010=iso_map,
                        evidence=GateEvidence(
                            workflow=wf_name,
                            job=str(job_id),
                            step=str(step.get("name", "")),
                            step_uses=step.get("uses"),
                            step_run=step.get("run"),
                        ),
                        evaluation=evaluation,
                    )
                )
    if not gates:
        notes.append("No Quality Gates heuristically detected in GitHub Actions workflows.")
    return gates, notes


def overall_scores(gates: List[DetectedGate]) -> Dict[str, float]:
    if not gates:
        return {k: 0.0 for k in ["sufficiency", "completeness", "redundancy", "resilience"]}
    agg: Dict[str, float] = {"sufficiency": 0.0, "completeness": 0.0, "redundancy": 0.0, "resilience": 0.0}
    for g in gates:
        for k in agg.keys():
            agg[k] += float(g.evaluation.get(k, 0.0))
    n = float(len(gates))
    return {k: round(v / n, 2) for k, v in agg.items()}


def summarize_top_gaps(gates: List[DetectedGate]) -> List[str]:
    # Heuristic gaps: missing categories and low-scoring present categories
    categories_present = {g.category for g in gates}
    must_have = ["tests", "lint", "coverage", "sast", "sca", "secrets"]
    gaps: List[str] = []
    for cat in must_have:
        if cat not in categories_present:
            gaps.append(f"Missing gate: {cat}")
    low = sorted(gates, key=lambda g: g.evaluation.get("sufficiency", 0.0))[:3]
    for g in low:
        gaps.append(f"Low sufficiency: {g.category} in workflow '{g.evidence.workflow}' step '{g.evidence.step or g.name}'")
    return gaps[:3]


def write_json(output_dir: Path, data: Dict[str, Any]) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    out = output_dir / "qg_report.json"
    with out.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return out


def write_markdown(output_dir: Path, gates: List[DetectedGate], scores: Dict[str, float], notes: List[str]) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    out = output_dir / "qg_report.md"
    lines: List[str] = []
    lines.append("## Quality Gates Inventory (GitHub Actions)")
    lines.append("")
    lines.append(f"**Scores**: sufficiency {scores['sufficiency']}, completeness {scores['completeness']}, redundancy {scores['redundancy']}, resilience {scores['resilience']}")
    lines.append("")
    lines.append("### Detected Gates")
    lines.append("")
    lines.append("| Category | Workflow | Job | Step | ISO/IEC 25010 | Suff | Comp | Red | Res |")
    lines.append("|---|---|---|---|---|---:|---:|---:|---:|")
    for g in gates:
        lines.append(
            "| "
            + f"{g.category} | {g.evidence.workflow} | {g.evidence.job} | {g.evidence.step or g.name} | "
            + ", ".join(g.iso25010)
            + " | "
            + f"{g.evaluation['sufficiency']:.2f} | {g.evaluation['completeness']:.2f} | {g.evaluation['redundancy']:.2f} | {g.evaluation['resilience']:.2f} |"
        )
    if notes:
        lines.append("")
        lines.append("### Notes")
        for n in notes:
            lines.append(f"- {n}")
    lines.append("")
    lines.append("### Recommendations")
    lines.append("- Ensure gates exist for tests, lint, coverage, SAST, SCA, and secrets scanning.")
    lines.append("- Add explicit thresholds (e.g., coverage %, linter max warnings, SAST severity budget).")
    lines.append("- Add timeouts and retry policies to improve resilience.")
    lines.append("- Consider DAST, IaC, and container image scanning if relevant.")
    with out.open("w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return out


def fetch_branch_protection(owner_repo: str, token: Optional[str]) -> Optional[Dict[str, Any]]:
    if not token or not requests:
        return None
    try:
        headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github+json"}
        repo_resp = requests.get(f"https://api.github.com/repos/{owner_repo}", headers=headers, timeout=15)
        repo_resp.raise_for_status()
        default_branch = repo_resp.json().get("default_branch", "main")
        prot_resp = requests.get(
            f"https://api.github.com/repos/{owner_repo}/branches/{default_branch}/protection",
            headers=headers,
            timeout=15,
        )
        if prot_resp.status_code == 404:
            return {"enabled": False, "default_branch": default_branch}
        prot_resp.raise_for_status()
        data = prot_resp.json()
        return {"enabled": True, "default_branch": default_branch, "raw": data}
    except Exception:
        return None


def fetch_and_analyze_run_logs(owner_repo: str, run_id: Optional[str], token: Optional[str], output_dir: Path) -> Optional[Dict[str, Any]]:
    if not (requests and token and owner_repo and run_id):
        return None
    try:
        headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github+json"}
        url = f"https://api.github.com/repos/{owner_repo}/actions/runs/{run_id}/logs"
        resp = requests.get(url, headers=headers, timeout=60)
        if resp.status_code == 404:
            return {"downloaded": False, "reason": "logs_not_found"}
        resp.raise_for_status()
        output_dir.mkdir(parents=True, exist_ok=True)
        zip_path = output_dir / "gha_logs.zip"
        with open(zip_path, "wb") as f:
            f.write(resp.content)
        errors = 0
        warnings = 0
        files = 0
        with zipfile.ZipFile(zip_path, 'r') as zf:
            for name in zf.namelist():
                if name.endswith('/'):
                    continue
                files += 1
                try:
                    data = zf.read(name)
                    text = data.decode('utf-8', errors='ignore').lower()
                    errors += text.count('error')
                    warnings += text.count('warning')
                except Exception:
                    continue
        return {"downloaded": True, "zip_path": str(zip_path), "files": files, "errors": errors, "warnings": warnings}
    except Exception:
        return None


def build_json(gates: List[DetectedGate], scores: Dict[str, float], notes: List[str], branch_protection: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "version": 1,
        "scores": scores,
        "gates": [
            {
                "category": g.category,
                "name": g.name,
                "iso25010": g.iso25010,
                "evidence": asdict(g.evidence),
                "evaluation": g.evaluation,
            }
            for g in gates
        ],
        "branch_protection": branch_protection,
        "notes": notes,
        "top_gaps": summarize_top_gaps(gates),
    }


def ai_assess_quality_gates(payload: Dict[str, Any], api_key: str, model: str = "gpt-4o-mini") -> Optional[Dict[str, Any]]:
    if not requests:
        return None
    try:
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        system_msg = (
            "You are an expert DevSecOps and software quality auditor. "
            "Assess CI Quality Gates against ISO/IEC 25010:2023, SQuARE, OWASP, CWE, and SEI CERT. "
            "Respond in English. Output a single JSON object with keys: ai_json, ai_markdown. "
            "ai_json must contain: overall_score (0-100), scores {sufficiency, completeness, redundancy, resilience}, "
            "iso25010_scores per characteristic (0-100), critical_gaps[], recommendations[], and rationale. "
            "ai_markdown is a human-readable Markdown summary with tables and top 3 gaps."
        )
        user_msg = {
            "role": "user",
            "content": json.dumps({"measurements": payload}, ensure_ascii=False),
        }
        body = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_msg},
                user_msg,
            ],
            "temperature": 0.1,
        }
        resp = requests.post("https://api.openai.com/v1/chat/completions", headers=headers, json=body, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        content = data["choices"][0]["message"]["content"].strip()
        # Expect JSON
        parsed = json.loads(content)
        if not isinstance(parsed, dict):
            return None
        if "ai_json" in parsed and "ai_markdown" in parsed:
            return parsed
        # Fallback if model returned plain JSON for ai_json only
        return {"ai_json": parsed, "ai_markdown": ""}
    except Exception:
        return None


def main() -> int:
    parser = argparse.ArgumentParser(description="Inventory and analyze Quality Gates from GitHub Actions workflows")
    parser.add_argument("--repo-dir", default=str(Path.cwd()), help="Repository root directory")
    parser.add_argument("--output-dir", default="qg_artifacts", help="Directory to write qg_report.json and qg_report.md")
    parser.add_argument("--github-repo", default=os.environ.get("GITHUB_REPOSITORY", ""), help="owner/repo for GitHub API")
    parser.add_argument("--fail-on", default=os.environ.get("FAIL_ON", ""), help="Policy for failing the run (e.g., policy)")
    args = parser.parse_args()

    repo_dir = Path(args.repo_dir).resolve()
    out_dir = Path(args.output_dir).resolve()

    gates, notes = analyze_workflows(repo_dir)
    scores = overall_scores(gates)

    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    branch_protection = None
    if args.github_repo:
        branch_protection = fetch_branch_protection(args.github_repo, token)

    # Optionally include CODEOWNERS text
    def read_codeowners(r: Path) -> Optional[str]:
        for rel in [".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"]:
            p = r / rel
            if p.exists():
                try:
                    return p.read_text(encoding="utf-8")
                except Exception:
                    return None
        return None

    data = build_json(gates, scores, notes, branch_protection)
    # Collect current run logs if available
    run_id = os.environ.get("GITHUB_RUN_ID")
    logs_info = fetch_and_analyze_run_logs(args.github_repo, run_id, token, out_dir)
    if logs_info is not None:
        data["pipeline_logs"] = logs_info
    codeowners_text = read_codeowners(repo_dir)
    if codeowners_text is not None:
        data["codeowners"] = codeowners_text
    # AI assessment (optional)
    openai_key = os.environ.get("OPENAI_API_KEY")
    openai_model = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
    ai_result: Optional[Dict[str, Any]] = None
    if openai_key:
        ai_result = ai_assess_quality_gates(data, openai_key, model=openai_model)
        if ai_result:
            data["ai"] = ai_result.get("ai_json")

    json_path = write_json(out_dir, data)
    md_path = write_markdown(out_dir, gates, scores, notes)

    # Append AI markdown if available
    if ai_result and ai_result.get("ai_markdown"):
        try:
            with md_path.open("a", encoding="utf-8") as f:
                f.write("\n\n### AI Assessment\n")
                f.write(ai_result["ai_markdown"]) 
        except Exception:
            pass

    print(f"Wrote {json_path}")
    print(f"Wrote {md_path}")

    # Fail on critical gaps if policy is enabled
    if (args.fail_on or "").lower() == "policy":
        critical_missing = [g for g in ["tests", "lint", "coverage", "sast", "sca", "secrets"] if g not in {x.category for x in gates}]
        low_resilience = scores.get("resilience", 0.0) < 0.4
        if critical_missing or low_resilience:
            print("Policy failure due to critical gaps:")
            for c in critical_missing:
                print(f"- missing gate: {c}")
            if low_resilience:
                print("- low resilience score")
            return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())


