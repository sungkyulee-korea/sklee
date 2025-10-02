#!/usr/bin/env python3
# .github/scripts/security_scan.py
# 설치: pip install requests
import os, sys, json, requests, textwrap, traceback

OUT_MD = "report.md"
OUT_STRUCT = "ai_summary_structured.json"
SEMGREP = "semgrep-results.json"
OPENAI_KEY = os.environ.get("OPENAI_API_KEY", "").strip()

def load_semgrep():
    if not os.path.exists(SEMGREP):
        return []
    try:
        with open(SEMGREP, "r", encoding="utf8") as f:
            data = json.load(f)
        return data.get("results", []) if isinstance(data, dict) else []
    except Exception as e:
        print("Failed to load semgrep results:", e)
        return []

def build_fallback_report(results):
    lines = []
    lines.append("# AI Security Scan (자동 리포트)")
    lines.append("")
    if not results:
        lines.append("### 전체 판단: 취약점 없음 (자동 분석)")
        lines.append("")
        lines.append("- Semgrep 기준으로 탐지된 항목이 없습니다.")
    else:
        lines.append("### 전체 판단: 취약점 발견 (자동 분석)")
        lines.append("")
        lines.append("#### Semgrep 발견 항목:")
        for r in results:
            path = r.get("path") or r.get("extra",{}).get("metadata",{}).get("file","-")
            msg = r.get("extra",{}).get("message") or r.get("message") or ""
            start = "-"
            s = r.get("start")
            if isinstance(s, dict):
                start = s.get("line", "-")
            elif s:
                start = s
            sev = r.get("extra",{}).get("severity", "")
            lines.append(f"- {path}:{start} ({sev}) - {msg}")
    lines.append("")
    lines.append("## 권고 요약")
    lines.append("- 자동분석 결과를 기반으로 합니다. 중요한 코드는 수동 검토 권장.")
    lines.append("")
    lines.append("_자동 생성 리포트 — 담당자 검토 필요_")
    return "\n".join(lines)

def call_openai_prompt(diff_text, files_list):
    system = "You are a concise code-security reviewer. Provide short Korean summary and recommended fixes. Response in JSON with keys: overall (Block|Manual review|Low), items (list of {file,line,severity,short_desc,fix}), summary_kor."
    user = (
        "아래 semgrep 결과(또는 변경파일 리스트)를 바탕으로 취약점 요약과 간단 권고를 한국어로 JSON 형식으로 출력하세요.\n\n"
        "FILES:\n" + ("\n".join(files_list[:200])) + "\n\n"
        "DIFF/SEMgrep:\n" + (diff_text[:12000])
    )
    body = {
        "model": "gpt-4o-mini",
        "messages": [
            {"role":"system","content":system},
            {"role":"user","content":user}
        ],
        "max_tokens": 800,
        "temperature": 0
    }
    headers = {"Authorization": f"Bearer {OPENAI_KEY}", "Content-Type": "application/json"}
    try:
        resp = requests.post("https://api.openai.com/v1/chat/completions", headers=headers, json=body, timeout=30)
        if resp.status_code == 200:
            j = resp.json()
            text = j.get("choices",[{}])[0].get("message",{}).get("content","")
            return text, j
        else:
            return f"[OpenAI error {resp.status_code}] {resp.text[:1000]}", None
    except Exception as e:
        return f"[OpenAI exception] {str(e)}", None

def main():
    results = load_semgrep()
    # build fallback report
    fallback = build_fallback_report(results)

    # attempt to call OpenAI if key is present
    ai_note = ""
    ai_struct = {}
    files_list = []
    # collect some sample files (names)
    try:
        for root, dirs, files in os.walk(".", topdown=True):
            # limit to tracked files quickly - but just collect
            for f in files:
                if f.endswith((".java",".py",".js",".yml",".yaml")):
                    files_list.append(os.path.join(root, f))
            if len(files_list) > 200:
                break
    except Exception:
        pass

    diff_text = ""
    if os.path.exists(SEMGREP):
        try:
            diff_text = open(SEMGREP, "r", encoding="utf8").read()
        except:
            diff_text = ""

    if OPENAI_KEY:
        try:
            ai_text, ai_json = call_openai_prompt(diff_text, files_list)
            ai_note = "\n\n---\n\n" + "### AI 요약 (OpenAI 결과)\n\n" + ai_text
            if ai_json:
                ai_struct = ai_json
        except Exception as e:
            ai_note = "\n\n---\n\nAI 호출 중 오류가 발생했습니다: " + str(e)
    else:
        ai_note = "\n\n---\n\n(OpenAI 키가 설정되지 않아 AI 요약은 수행되지 않았습니다.)"

    # write report.md (always)
    try:
        with open(OUT_MD, "w", encoding="utf8") as fw:
            fw.write(fallback)
            fw.write(ai_note)
        print(f"{OUT_MD} created; entries: {len(results)}")
    except Exception as e:
        print("Failed to write report.md:", e)
        traceback.print_exc()

    # write structured summary if AI returned json
    if ai_struct:
        try:
            with open(OUT_STRUCT, "w", encoding="utf8") as fw:
                json.dump(ai_struct, fw, indent=2)
            print(f"{OUT_STRUCT} created")
        except Exception:
            pass

if __name__ == "__main__":
    main()
