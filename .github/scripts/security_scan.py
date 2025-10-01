#!/usr/bin/env python3
# .github/scripts/security_scan.py
# 필요한 패키지: requests (설치는 워크플로우에서 수행됨)

import os, json, re, subprocess, requests, textwrap, sys

def load_json(p):
    try:
        with open(p,'r',encoding='utf8') as f:
            return json.load(f)
    except Exception:
        return None

def write_json(p,obj):
    with open(p,'w',encoding='utf8') as f:
        json.dump(obj,f,ensure_ascii=False,indent=2)

def short(s,n=120000):
    if s is None:
        return ''
    return s if len(s) <= n else s[:n] + "\n\n[...truncated]"

# 1) changed files (PR 우선, 없으면 git diff 또는 모든 파일)
def get_changed_files(limit=200):
    files=[]
    evt = os.environ.get('GITHUB_EVENT_PATH')
    repo = os.environ.get('GITHUB_REPOSITORY','')
    token = os.environ.get('GITHUB_TOKEN')
    if evt and os.path.exists(evt) and token and repo:
        try:
            ev = json.load(open(evt,'r',encoding='utf8'))
            pr = ev.get('pull_request')
            if pr and pr.get('number'):
                owner,repo_name = repo.split('/')
                page=1
                headers={'Authorization':f'Bearer {token}','Accept':'application/vnd.github+json'}
                while True:
                    url = f'https://api.github.com/repos/{owner}/{repo_name}/pulls/{pr["number"]}/files?per_page=100&page={page}'
                    r = requests.get(url, headers=headers, timeout=30)
                    if r.status_code != 200:
                        break
                    arr = r.json()
                    if not arr:
                        break
                    for it in arr:
                        files.append(it.get('filename'))
                    if len(arr) < 100:
                        break
                    page += 1
        except Exception:
            pass
    if not files and evt and os.path.exists(evt):
        try:
            ev = json.load(open(evt,'r',encoding='utf8'))
            before = ev.get('before','')
            after = ev.get('after', os.environ.get('GITHUB_SHA',''))
            if before and after and before != after:
                out = subprocess.check_output(['git','diff','--name-only', before, after]).decode().splitlines()
                files = out
        except Exception:
            pass
    if not files:
        try:
            out = subprocess.check_output(['git','ls-files']).decode().splitlines()
            files = out
        except Exception:
            files = []
    seen=[]
    for f in files:
        if f and f not in seen:
            seen.append(f)
    return seen[:limit]

# 2) read contents truncated
def read_contents(files, max_bytes=120000):
    out={}
    for f in files:
        try:
            if os.path.exists(f) and os.path.isfile(f):
                s = open(f,'r',encoding='utf8',errors='ignore').read()
                out[f] = short(s, max_bytes)
            else:
                out[f] = '[not available]'
        except Exception as e:
            out[f] = f'[error reading: {e}]'
    return out

# 3) simple heuristics
PATTERNS = {
    "XSS_output_like": re.compile(r"response\.getWriter|getWriter\(|println\(", re.I),
    "XSS_replaceAll": re.compile(r"\.replaceAll\(", re.I),
    "SQL_concat_in_exec": re.compile(r"execute(Query|Update)?\(|execute\).*\+", re.I),
    "SQL_stmt": re.compile(r"\bnew\s+Statement\b|\bStatement\b", re.I),
    "LDAP_usage": re.compile(r"\b(InitialDirContext|DirContext|ldap|LDAP)\b", re.I),
}

def heuristic_scan(contents):
    out={}
    for f,text in contents.items():
        hits=[]
        try:
            for i,line in enumerate(text.splitlines(), start=1):
                for name,pat in PATTERNS.items():
                    try:
                        if pat.search(line):
                            hits.append({"line":i,"pattern":name,"snippet":line.strip()[:300]})
                    except Exception:
                        pass
        except Exception as e:
            hits.append({"error":str(e)})
        out[f]=hits
    return out

# 4) semgrep summary
def semgrep_summary(semgrep_json):
    items = semgrep_json.get('results',[]) if semgrep_json else []
    lines=[]
    for r in items:
        path = r.get('path') or r.get('check_id') or '-'
        start='-'
        try:
            st = r.get('start') or r.get('extra',{}).get('start') or {}
            if isinstance(st, dict):
                start = st.get('line','-')
        except Exception:
            start='-'
        msg = r.get('extra',{}).get('message') or r.get('message') or ''
        sev = r.get('extra',{}).get('severity') or ''
        lines.append(f"{path}:{start} [{sev}] {msg}")
    return lines

# 5) optional OpenAI enrichment (JSON). Requires SKLEE_OPENAI_API_KEY secret (or OPENAI_API_KEY env)
def call_openai(sem_lines, heur_dict, files_block):
    key = os.environ.get('SKLEE_OPENAI_API_KEY') or os.environ.get('OPENAI_API_KEY')
    if not key:
        return {"note":"OpenAI key not provided; skipped"}
    prompt = textwrap.dedent(f"""
    You are a concise security code reviewer. Return JSON only with structure:
    {{ "overall":"Block"|"Manual review"|"Low"|"None",
       "items":[{{"file":"<path>","line":<num or '-'>,"severity":"Low|Medium|High|Critical","cwe":"CWE-xxx or -","owasp":"Axx or -","present":true|false,"details_ko":"...","recommendation_ko":"..."}}] }}
    Semgrep lines sample:
    {json.dumps(sem_lines[:100], ensure_ascii=False)}
    Heuristics sample:
    {json.dumps(list(heur_dict.items())[:50], ensure_ascii=False)}
    File contents (truncated):
    {files_block[:100000]}
    Respond ONLY with valid JSON.
    """)
    headers = {"Authorization": f"Bearer {key}", "Content-Type":"application/json"}
    body = {"model":"gpt-4o-mini", "messages":[{"role":"system","content":"You are a concise, security-focused code reviewer. Produce JSON only."},{"role":"user","content":prompt}], "temperature":0, "max_tokens":1400}
    try:
        r = requests.post("https://api.openai.com/v1/chat/completions", headers=headers, json=body, timeout=120)
        if r.status_code != 200:
            return {"error":f"OpenAI {r.status_code}", "raw": r.text[:2000]}
        text = r.json().get('choices',[{}])[0].get('message',{}).get('content','')
        m = re.search(r'(\{[\s\S]*\})\s*$', text.strip())
        if m:
            try:
                return json.loads(m.group(1))
            except Exception:
                return {"error":"parse_error","raw": text[:2000]}
        else:
            return {"error":"no_json","raw": text[:2000]}
    except Exception as e:
        return {"error": str(e)}

def main():
    semgrep_json = load_json('semgrep-results.json') or {}
    files = get_changed_files(limit=int(os.environ.get('MAX_FILES_TO_ANALYZE',200)))
    write_json('files_to_analyze.json', files)
    contents = read_contents(files, max_bytes=int(os.environ.get('MAX_FILE_BYTES',120000)))
    write_json('files_content.json', contents)
    heur = heuristic_scan(contents)
    write_json('heuristics.json', heur)
    sem_lines = semgrep_summary(semgrep_json)

    files_block = ""
    for f in files:
        files_block += f"--- {f} ---\n" + contents.get(f,'') + "\n\n"

    ai_summary = call_openai(sem_lines, heur, files_block)
    write_json('ai_summary_structured.json', ai_summary)

    # build report.md
    lines=[]
    lines.append("### 🤖 자동 보안 리포트")
    lines.append("")
    lines.append("#### 1) 분석 대상 파일")
    for f in files:
        pr = "HIGH" if 'bad' in f.lower() else "normal"
        lines.append(f"- {f} ({pr})")
    lines.append("")
    lines.append("#### 2) Semgrep (요약)")
    if sem_lines:
        for l in sem_lines[:200]:
            lines.append(f"- {l}")
    else:
        lines.append("- Semgrep: 문제 없음 (기본 룰)")
    lines.append("")
    lines.append("#### 3) 휴리스틱 샘플")
    for f,hits in list(heur.items())[:200]:
        if hits:
            lines.append(f"- {f}:")
            for h in hits[:5]:
                if 'error' in h:
                    lines.append(f"  - ERROR: {h['error']}")
                else:
                    lines.append(f"  - L{h['line']} {h['pattern']} -> {h['snippet']}")
    lines.append("")
    lines.append("#### 4) OpenAI 자동 분석 (JSON)")
    lines.append("```json")
    lines.append(json.dumps(ai_summary, ensure_ascii=False, indent=2))
    lines.append("```")
    lines.append("")
    lines.append("_자동 리포트 — 담당자 검토 필요_")
    with open('report.md','w',encoding='utf8') as f:
        f.write('\n'.join(lines))
    print('report.md created; files_count:', len(files))

if __name__=='__main__':
    main()
