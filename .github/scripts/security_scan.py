#!/usr/bin/env python3
# .github/scripts/security_scan.py
# Create ai_report.md and ai_summary.json and post to PR (comment) or create an Issue.
# Requires: requests (installed by workflow)

import os
import sys
import json
import time
from pathlib import Path

try:
    import requests
except Exception as e:
    print("requests not installed:", e)
    sys.exit(1)

WORKDIR = Path.cwd()
REPO = os.environ.get('GITHUB_REPOSITORY')  # owner/repo
GITHUB_TOKEN = os.environ.get('GITHUB_TOKEN')
OPENAI_API_KEY = os.environ.get('OPENAI_API_KEY')
OPENAI_MODEL = os.environ.get('OPENAI_MODEL') or "gpt-4o-mini"

MAX_FILE_BYTES = int(os.environ.get('MAX_FILE_BYTES', '200000'))
MAX_FILES = int(os.environ.get('MAX_FILES', '8'))

SEMgrep_PATH = WORKDIR / "semgrep-results.json"
AI_REPORT = WORKDIR / "ai_report.md"
AI_SUMMARY = WORKDIR / "ai_summary.json"

def find_candidate_files(max_files=MAX_FILES):
    # 우선순위: 파일명에 'bad' 포함 또는 CWE 접두사, 그 다음 모든 .java
    candidates = []
    for p in sorted(WORKDIR.rglob("*.java")):
        name = p.name.lower()
        if 'bad' in name or name.startswith('cwe'):
            candidates.append(p)
    if len(candidates) < max_files:
        # 추가로 다른 java 파일 보충
        for p in sorted(WORKDIR.rglob("*.java")):
            if p not in candidates:
                candidates.append(p)
            if len(candidates) >= max_files:
                break
    return candidates[:max_files]

def read_file_excerpt(path, max_bytes=MAX_FILE_BYTES):
    try:
        if not path.exists():
            return None
        size = path.stat().st_size
        if size > max_bytes:
            return None
        text = path.read_text(encoding='utf8', errors='ignore')
        # limit length for OpenAI prompt
        if len(text) > 40000:
            return text[:40000] + "\n\n[...truncated]"
        return text
    except Exception as e:
        print(f"Error reading {path}: {e}")
        return None

def semgrep_summary_text():
    if not SEMgrep_PATH.exists():
        return "Semgrep: no results file found."
    try:
        j = json.loads(SEMgrep_PATH.read_text(encoding='utf8'))
        results = j.get("results", []) if isinstance(j, dict) else []
        lines = [f"Semgrep findings: {len(results)}"]
        for r in results[:40]:
            path = r.get("path") or (r.get("extra") or {}).get("metadata", {}).get("file", "-")
            start = (r.get("start") or {}).get("line") if isinstance(r.get("start"), dict) else r.get("start", "-")
            msg = (r.get("extra") or {}).get("message") or r.get("message") or ""
            sev = (r.get("extra") or {}).get("severity") or ""
            lines.append(f"- {path}:{start} [{sev}] {msg}")
        return "\n".join(lines)
    except Exception as e:
        return f"Semgrep parse error: {e}"

def build_prompt(file_excerpts, semgrep_text):
    files_desc = []
    for filename, excerpt in file_excerpts:
        safe_excerpt = excerpt if excerpt else "[no excerpt]"
        files_desc.append(f"--- FILE: {filename} ---\n{safe_excerpt}\n")
    files_joined = "\n\n".join(files_desc) if files_desc else "(no files attached)"

    instruction = (
        "You are a concise security-focused code reviewer. "
        "Given the semgrep summary and file excerpts, return first a JSON object, then a short Korean markdown summary.\n\n"
        "JSON format (exact keys):\n"
        "{\n"
        "  \"overall\": \"Block\" | \"Manual review\" | \"Low\",\n"
        "  \"items\": [ {\"file\":\"...\",\"line\":123, \"severity\":\"High|Medium|Low\", \"title\":\"short title\", \"cwe\":\"CWE-xxx or ''\",\"owasp\":\"OWASP-xxx or ''\",\"description\":\"short description\",\"one_line_fix\":\"code or fix\"} ],\n"
        "  \"summary_kr\":\"short Korean summary\"\n"
        "}\n\n"
        "Now analyze. Use semgrep output and code excerpts. Focus on SQL injection, XSS, LDAP, XPath, command injection first. "
        "If nothing found, set overall=\"Low\" and items = [].\n\n"
        "SEMgrep SUMMARY:\n" + semgrep_text + "\n\n"
        "FILES:\n" + files_joined
    )
    return instruction

def call_openai(prompt_text):
    if not OPENAI_API_KEY:
        return {"error": "OPENAI_API_KEY not set"}
    url = "https://api.openai.com/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type": "application/json"
    }
    messages = [
        {"role":"system","content":"You are a concise security-focused code reviewer."},
        {"role":"user","content": prompt_text}
    ]
    body = {
        "model": OPENAI_MODEL,
        "messages": messages,
        "max_tokens": 1200,
        "temperature": 0
    }
    try:
        r = requests.post(url, headers=headers, json=body, timeout=60)
    except Exception as e:
        return {"error": f"Request failed: {e}"}
    if r.status_code != 200:
        # return status and text for debug
        text = r.text
        return {"error": f"OpenAI status {r.status_code}", "detail": text}
    try:
        j = r.json()
        content = j.get("choices", [{}])[0].get("message", {}).get("content", "")
        return {"ok": True, "content": content, "raw": j}
    except Exception as e:
        return {"error": f"OpenAI parse error: {e}", "text": r.text}

def post_issue(title, body):
    if not GITHUB_TOKEN or not REPO:
        return {"error":"No GITHUB_TOKEN or REPO"}
    url = f"https://api.github.com/repos/{REPO}/issues"
    headers = {"Authorization": f"Bearer {GITHUB_TOKEN}", "Accept": "application/vnd.github+json"}
    payload = {"title": title, "body": body}
    try:
        r = requests.post(url, headers=headers, json=payload, timeout=30)
        try:
            return {"status": r.status_code, "json": r.json()}
        except:
            return {"status": r.status_code, "text": r.text}
    except Exception as e:
        return {"error": str(e)}

def post_pr_comment(pr_number, body):
    if not GITHUB_TOKEN or not REPO:
        return {"error":"No GITHUB_TOKEN or REPO"}
    url = f"https://api.github.com/repos/{REPO}/issues/{pr_number}/comments"
    headers = {"Authorization": f"Bearer {GITHUB_TOKEN}", "Accept": "application/vnd.github+json"}
    payload = {"body": body}
    try:
        r = requests.post(url, headers=headers, json=payload, timeout=30)
        try:
            return {"status": r.status_code, "json": r.json()}
        except:
            return {"status": r.status_code, "text": r.text}
    except Exception as e:
        return {"error": str(e)}

def detect_pr_from_event():
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if not event_path or not os.path.exists(event_path):
        return None
    try:
        ev = json.loads(open(event_path,'r',encoding='utf8').read())
        pr = ev.get("pull_request")
        if pr:
            return pr.get("number")
    except Exception as e:
        print("Error parsing event file:", e)
    return None

def main():
    print("=== security_scan.py start ===")
    files = find_candidate_files()
    print("Found candidate files (count):", len(files))
    excerpts = []
    for p in files:
        txt = read_file_excerpt(p)
        if txt:
            excerpts.append((str(p.relative_to(WORKDIR)), txt))
            print(f"Included excerpt: {p} (len {len(txt)})")
        else:
            print(f"Skipped (too large or unreadable): {p}")

    sem_text = semgrep_summary_text()
    print("Semgrep summary (head):")
    for l in sem_text.splitlines()[:20]:
        print("  ", l)

    prompt = build_prompt(excerpts, sem_text)
    # Call OpenAI
    print("Calling OpenAI...")
    resp = call_openai(prompt)
    if "error" in resp:
        print("OpenAI call error:", resp.get("error"))
        if "detail" in resp:
            print("Detail (head):", str(resp.get("detail"))[:1000])
        # fallback: create minimal report from semgrep
        fallback = "# AI Security Report (fallback)\n\n"
        fallback += "OpenAI call failed or not configured.\n\n"
        fallback += sem_text + "\n\n"
        fallback += "_자동 생성 리포트 (fallback)_\n"
        AI_REPORT.write_text(fallback, encoding='utf8')
        AI_SUMMARY.write_text(json.dumps(resp, ensure_ascii=False), encoding='utf8')
        print("Wrote fallback ai_report.md and ai_summary.json")
        return

    content = resp.get("content","")
    print("OpenAI returned content length:", len(content))
    # Save outputs
    AI_REPORT.write_text(content, encoding='utf8')
    try:
        AI_SUMMARY.write_text(json.dumps(resp.get("raw",{}), ensure_ascii=False), encoding='utf8')
    except Exception as e:
        print("Failed write ai_summary.json:", e)

    # Post to PR or Issue
    pr_number = detect_pr_from_event()
    if pr_number:
        print("Detected PR number:", pr_number, "-> posting comment")
        res = post_pr_comment(pr_number, content + "\n\n_자동 생성 리포트_")
        print("PR post result:", res)
    else:
        print("No PR detected -> creating issue")
        title = "[AI Security Scan] 자동 리포트 - " + time.strftime("%Y-%m-%d")
        res = post_issue(title, content + "\n\n_자동 생성 리포트_")
        print("Issue create result:", res)

    print("=== security_scan.py done ===")

if __name__ == "__main__":
    main()
