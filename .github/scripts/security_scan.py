# .github/scripts/security_scan.py
import json, os, sys

MAX_POST_BYTES = int(os.environ.get("MAX_POST_CHARS", "1800"))

def load(fname):
    if not os.path.exists(fname):
        return []
    try:
        with open(fname, "r", encoding="utf8") as f:
            j = json.load(f)
        if isinstance(j, dict) and "results" in j:
            return j.get("results", [])
    except Exception:
        pass
    return []

results = []
results += load("semgrep-results.json")
results += load("semgrep-custom.json")

lines = []
lines.append("# 자동 보안 리포트 (Semgrep 기반)")
lines.append("")

if results:
    lines.append("## 발견 항목 (요약)")
    for r in results[:300]:
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

with open("report.md", "w", encoding="utf8") as fw:
    fw.write("\n".join(lines))

# short file for posting to issue/comment
short_text = "\n".join(lines[:60])
b = short_text.encode("utf8")[:MAX_POST_BYTES]
with open("post_body_short.md", "wb") as fo:
    fo.write(b)

print("report.md and post_body_short.md created (entries: %d)" % len(results))
