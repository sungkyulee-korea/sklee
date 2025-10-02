#!/usr/bin/env python3
# .github/scripts/security_scan.py
# Always creates report.md. Optionally calls OpenAI if OPENAI key present.
# Save as: .github/scripts/security_scan.py

import os
import json
import traceback

WORKDIR = os.getcwd()
SEMGREP_FILE = os.path.join(WORKDIR, "semgrep-results.json")
OUT_MD = os.path.join(WORKDIR, "report.md")
OUT_STRUCT = os.path.join(WORKDIR, "ai_summary_structured.json")

OPENAI_KEY = os.environ.get("OPENAI_API_KEY", "").strip()
OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")

def load_semgrep_results():
    if not os.path.exists(SEMGREP_FILE):
        return []
    try:
        with open(SEMGREP_FILE, "r", encoding="utf8") as f:
            data = json.load(f)
        return data.get("results", []) if isinstance(data, dict) else []
    except Exception as e:
        print("ERROR: failed to parse semgrep-results.json:", e)
        return []

def build_fallback_report(findings):
    lines = []
    lines.append("# AI Security Scan (자동 리포트)")
    lines.append("")
    if not findings:
        lines.append("## 전체 판단: 취약점 없음 (자동 분석)")
        lines.append("")
        lines.append("- Semgrep 기준으로 탐지된 항목이 없습니다.")
    else:
        lines.append("## 전체 판단: 취약점 발견 (자동 분석)")
        lines.append("")
        lines.append("### Semgrep 발견 항목:")
        for r in findings:
            try:
                path = r.get("path") or r.get("extra", {}).get("metadata", {}).get("file", "-")
                s = r.get("start")
                if isinstance(s, dict):
                    line_no = s.get("line", "-")
                else:
                    line_no = s or "-"
                msg = (r.get("extra", {}) or {}).get("message") or r.get("message") or ""
                sev = (r.get("extra", {}) or {}).get("severity", "")
                lines.append(f"- {path}:{line_no} ({sev}) - {msg}")
            except Exception:
                lines.append("- (failed to read item)")
    lines.append("")
    lines.append("## 권고 요약")
    lines.append("- 자동분석 결과를 기반으로 합니다. 중요 로직은 수동검토 권장.")
    lines.append("")
    lines.append("_자동 생성 리포트 — 담당자 검토 필요_")
    return "\n".join(lines)

def call_openai_for_summary(semgrep_text, files_list):
    try:
        import requests
    except Exception as e:
        return {"error": f"requests not available: {e}"}

    system = "You are a concise security-focused code reviewer. Provide JSON with overall/items/summary_kr and then a short Korean markdown summary."
    user = "SEMgrep summary (short):\n" + (semgrep_text[:12000] if semgrep_text else "(empty)") + "\n\nFILES (list):\n" + "\n".join(files_list[:200]) + "\n\nPlease return JSON first then a short Korean markdown summary."

    body = {
        "model": OPENAI_MODEL,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user}
        ],
        "max_tokens": 1000,
        "temperature": 0
    }

    headers = {"Authorization": f"Bearer {OPENAI_KEY}", "Content-Type": "application/json"}
    try:
        resp = requests.post("https://api.openai.com/v1/chat/completions", headers=headers, json=body, timeout=30)
        text = resp.text
        if resp.status_code != 200:
            return {"error": f"OpenAI status {resp.status_code}", "detail": text}
        j = resp.json()
        content = (j.get("choices", [{}])[0].get("message", {}) or {}).get("content", "")
        return {"ok": True, "content": content, "raw": j}
    except Exception as e:
        return {"error": str(e), "detail": traceback.format_exc()[:2000]}

def main():
    try:
        findings = load_semgrep_results()
        fallback = build_fallback_report(findings)

        # small file list for context (names)
        files_list = []
        for root, dirs, files in os.walk("."):
            for fn in files:
                if fn.endswith((".java", ".py", ".js", ".yml", ".yaml")):
                    files_list.append(os.path.join(root, fn))
            if len(files_list) > 200:
                break

        sem_text = ""
        if os.path.exists(SEMGREP_FILE):
            try:
                sem_text = open(SEMGREP_FILE, "r", encoding="utf8").read()
            except Exception:
                sem_text = ""

        ai_note = "\n\n---\n\n(OpenAI 요약 없음)"
        ai_raw = None
        if OPENAI_KEY:
            print("OpenAI key present, attempting call...")
            resp = call_openai_for_summary(sem_text, files_list)
            if resp.get("ok"):
                content = resp.get("content","")
                ai_note = "\n\n---\n\n### AI 요약 (OpenAI)\n\n" + content
                ai_raw = resp.get("raw")
            else:
                ai_note = "\n\n---\n\nAI 호출 실패: " + str(resp.get("error", "unknown"))
                if "detail" in resp:
                    ai_note += "\n\n" + str(resp.get("detail",""))[:2000]
        else:
            ai_note = "\n\n---\n\n(OpenAI 키가 설정되지 않아 AI 요약은 생략됨.)"

        # always write report.md
        try:
            with open(OUT_MD, "w", encoding="utf8") as fw:
                fw.write(fallback)
                fw.write(ai_note)
            print("WROTE:", OUT_MD)
        except Exception as e:
            print("ERROR writing report.md:", e)

        # write structured AI raw if available
        if ai_raw:
            try:
                with open(OUT_STRUCT, "w", encoding="utf8") as fw:
                    json.dump(ai_raw, fw, ensure_ascii=False, indent=2)
                print("WROTE:", OUT_STRUCT)
            except Exception as e:
                print("ERROR writing ai structured:", e)

    except Exception as e:
        print("Unhandled exception in script:", e)
        traceback.print_exc()
        # ensure at least a minimal report exists
        try:
            if not os.path.exists(OUT_MD):
                with open(OUT_MD, "w", encoding="utf8") as fw:
                    fw.write("# AI Security Scan (fallback)\n\n스크립트 실행 중 오류가 발생했습니다. 수동 확인 필요.\n")
        except:
            pass

if __name__ == "__main__":
    main()
