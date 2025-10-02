# .github/scripts/security_scan.py
# Create report.md and post_body_short.md from semgrep outputs.
# This script is intentionally simple and robust (no external AI calls by default).
import os, json

MAX_POST_CHARS = int(os.environ.get("MAX_POST_CHARS", "1800"))

def load_semgrep(fname):
    if not os.path.exists(fname):
        return []
    try:
        with open(fname, "r", encoding="utf8") as f:
            j = json.load(f)
        if isinstance(j, dict) and "results" in j:
            return j.get("results", [])
        # older/other shapes
        return j if isinstance(j, list) else []
    except Exception:
        return []

results = []
results += load_semgrep("semgrep-custom.json")
results += load_semgrep("semgrep-results.json")

lines = ["# 자동 보안 리포트 (Semgrep 초안)", ""]
if results:
    lines.append("## 발견 항목 (요약)")
    for r in results[:200]:
        path = r.get("path") or r.get("extra", {}).get("metadata", {}).get("file", "-")
        extra = r.get("extra") or {}
        msg = extra.get("message") or r.get("message") or ""
        start = "-"
        if isinstance(r.get("start"), dict):
            start = r.get("start").get("line", "-")
        else:
            start = r.get("start", "-")
        sev = extra.get("severity", "UNKNOWN")
        lines.append(f"- {path}:{start} [{sev}] {msg}")
else:
    lines.append("- Semgrep: 탐지 없음 (기본/커스텀 룰 기준).")

lines.append("")
lines.append("_전체 리포트는 artifact로 보관됩니다._")

# write full report
with open("report.md", "w", encoding="utf8") as fw:
    fw.write("\n".join(lines))

# prepare short post body: first ~60 lines, truncated to MAX_POST_CHARS bytes
head_text = "\n".join(lines[:60])
b = head_text.encode("utf8")[:MAX_POST_CHARS]
with open("post_body_short.md", "wb") as fo:
    fo.write(b)

print("report.md and post_body_short.md created; findings:", len(results))
