#!/usr/bin/env python3
# .github/scripts/security_scan.py
# 개선판: 파일 크기 검증, 예외 로깅, 간단한 메시지 sanitize, 안전한 post_body_short 생성

import os
import json
import logging
from typing import List, Any

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

MAX_POST_CHARS = int(os.environ.get("MAX_POST_CHARS", "1800"))
MAX_FILE_BYTES = int(os.environ.get("MAX_FILE_BYTES", "150000"))  # 워크플로우와 일치시킬 것
INPUT_FILES = ["semgrep-custom.json", "semgrep-results.json"]

def safe_load_json(fname: str) -> Any:
    if not os.path.exists(fname):
        logging.info("file not found: %s", fname)
        return []
    try:
        size = os.path.getsize(fname)
    except OSError as e:
        logging.warning("Could not stat %s: %s", fname, e)
        return []
    if size > MAX_FILE_BYTES:
        logging.warning("Skipping %s: file too large (%d bytes)", fname, size)
        return []
    try:
        with open(fname, "r", encoding="utf8") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        logging.exception("JSON decode error for %s: %s", fname, e)
        return []
    except Exception as e:
        logging.exception("Error loading %s: %s", fname, e)
        return []

def normalize_results(j: Any) -> List[dict]:
    if isinstance(j, dict) and "results" in j:
        return j.get("results") or []
    if isinstance(j, list):
        return j
    return []

def sanitize_message(msg: str, max_len: int = 200) -> str:
    if not msg:
        return ""
    # 한 줄로 만들고 과도한 공백 제거, 길이 제한
    single = " ".join(msg.splitlines()).strip()
    if len(single) <= max_len:
        return single
    return single[:max_len-3] + "..."

def summarize_results(results: List[dict]) -> List[str]:
    lines = ["# 자동 보안 리포트 (Semgrep 요약)", ""]
    if not results:
        lines.append("- 탐지된 항목이 없습니다 (기본/커스텀 룰 기준).")
        return lines
    lines.append("## 발견 항목 (상위 요약)")
    for r in results[:200]:
        # 여러 포맷 대비 안전하게 추출
        path = r.get("path") or (r.get("extra") or {}).get("metadata", {}).get("file") or "<unknown>"
        # start line이 dict인지 숫자인지 여러 케이스 처리
        start = "-"
        if isinstance(r.get("start"), dict):
            start = r["start"].get("line", "-")
        else:
            start = r.get("start", "-")
        extra = r.get("extra") or {}
        severity = extra.get("severity") or extra.get("precision") or "UNKNOWN"
        message = sanitize_message(extra.get("message") or r.get("message") or "")
        lines.append(f"- `{path}`:{start} [{severity}] — {message}")
    lines.append("")
    lines.append("_전체 Semgrep JSON은 워크플로우 artifact로 업로드되어 확인하세요._")
    return lines

def write_outputs(lines: List[str]):
    report_md = "\n".join(lines)
    with open("report.md", "w", encoding="utf8") as f:
        f.write(report_md)
    short = report_md.encode("utf8")[:MAX_POST_CHARS]
    with open("post_body_short.md", "wb") as f:
        f.write(short)
    logging.info("report.md and post_body_short.md written; summary length: %d chars", len(report_md))

def main():
    all_results = []
    for fname in INPUT_FILES:
        j = safe_load_json(fname)
        normalized = normalize_results(j)
        if normalized:
            all_results.extend(normalized)
    # 중복 제거 (path+start+message 간단 키)
    seen = set()
    unique = []
    for r in all_results:
        key = (r.get("path"), str(r.get("start")), (r.get("extra") or {}).get("message") or r.get("message"))
        if key in seen:
            continue
        seen.add(key)
        unique.append(r)
    lines = summarize_results(unique)
    write_outputs(lines)
    logging.info("Found %d unique issues", len(unique))

if __name__ == "__main__":
    main()
