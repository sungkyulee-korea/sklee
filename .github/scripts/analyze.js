/*
 Improved analyze.js for GitHub Action
 - Robustly extracts JSON from OpenAI responses (removes markdown fences, finds first JSON array/object)
 - Keeps fallback behavior if parsing fails but avoids writing "Analysis parse error" when JSON is present inside fences
 - Splits large diffs into chunks and aggregates findings
 - Creates a concise GitHub Issue with structured findings

 Note: This file expects environment variables:
 - OPENAI_API_KEY (from secrets)
 - GITHUB_TOKEN (from secrets.GITHUB_TOKEN)
 - GITHUB_REPOSITORY (owner/repo)
 - PR_NUMBER (optional)

 Requires: @octokit/rest installed in .github/scripts/package.json
 Node 18+ (fetch available)
*/

import fs from 'fs';
import path from 'path';
import process from 'process';
import { Octokit } from '@octokit/rest';

const OPENAI_KEY = process.env.OPENAI_API_KEY;
const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
const REPO = process.env.GITHUB_REPOSITORY; // owner/repo
const PR_NUMBER = process.env.PR_NUMBER || null;

if (!OPENAI_KEY) {
  console.error('OPENAI_API_KEY missing');
  process.exit(1);
}
if (!GITHUB_TOKEN) {
  console.error('GITHUB_TOKEN missing');
  process.exit(1);
}
if (!REPO) {
  console.error('GITHUB_REPOSITORY missing');
  process.exit(1);
}

const diffPath = path.resolve('.github/scripts/pr.diff');
const raw = fs.existsSync(diffPath) ? fs.readFileSync(diffPath, 'utf8') : '';

if (!raw || raw.trim().length === 0) {
  console.log('No diff found — exiting.');
  process.exit(0);
}

function chunkText(text, maxChars = 15000) {
  const chunks = [];
  for (let i = 0; i < text.length; i += maxChars) {
    chunks.push(text.slice(i, i + maxChars));
  }
  return chunks;
}

function buildPrompt(diffChunk) {
  return [
    { role: 'system', content: 'You are a professional security analyst. Produce structured JSON only (no surrounding explanation). Return a JSON array of findings; each finding object MUST include: file, line_range, issue, severity (LOW/MEDIUM/HIGH/CRITICAL), confidence (0-1 number), remediation.' },
    { role: 'user', content: `Analyze the following git diff for security vulnerabilities, insecure patterns, secrets, or risky dependencies. Return ONLY JSON (an array). DIFF:\n${diffChunk}` }
  ];
}

async function callOpenAI(messages) {
  const res = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${OPENAI_KEY}`
    },
    body: JSON.stringify({
      model: 'gpt-4o-mini',
      messages,
      max_tokens: 800,
      temperature: 0.0
    })
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`OpenAI API error ${res.status}: ${text}`);
  }
  const data = await res.json();
  const reply = data.choices?.[0]?.message?.content || '';
  return reply;
}

// Robust JSON extraction: remove markdown fences and find first JSON array/object
function extractJsonFromText(text) {
  if (!text || typeof text !== 'string') return null;

  // Remove common markdown fences ```json ... ``` or ``` ... ```
  let cleaned = text.replace(/```(?:json)?\s*/gi, '');
  cleaned = cleaned.replace(/```\s*$/gi, '');

  // Sometimes model includes triple backticks with language, we removed them above
  // Try to find the first JSON array or object using a heuristic regex (dotall)
  const re = /([\[{][\s\S]*[\]}])/m;
  const m = cleaned.match(re);
  if (!m) return null;

  const candidate = m[1];

  // Try safe JSON parse with fallback attempts
  try {
    return JSON.parse(candidate);
  } catch (e) {
    // Heuristic: sometimes trailing commas or single quotes exist. Attempt small fixes.
    let attempt = candidate
      .replace(/,\s*\}/g, '}')
      .replace(/,\s*\]/g, ']')
      .replace(/\n\s*'/g, '\n"')
      .replace(/':/g, '":')
      .replace(/\t'/g, '\t"')
      .replace(/([:\[,\{\s])'([^']*)'/g, '$1"$2"');

    try {
      return JSON.parse(attempt);
    } catch (e2) {
      return null;
    }
  }
}

(async () => {
  try {
    const chunks = chunkText(raw, 15000);
    const allFindings = [];
    const rawReplies = [];

    for (let i = 0; i < chunks.length; i++) {
      const messages = buildPrompt(chunks[i]);
      const reply = await callOpenAI(messages);
      rawReplies.push(reply);

      const parsed = extractJsonFromText(reply);
      if (parsed && Array.isArray(parsed)) {
        // Ensure each item has required fields, normalize a bit
        for (const item of parsed) {
          const normalized = {
            file: item.file || item.filename || 'unknown',
            line_range: item.line_range || item.line || 'n/a',
            issue: item.issue || item.title || 'unspecified issue',
            severity: (item.severity || 'LOW').toUpperCase(),
            confidence: typeof item.confidence === 'number' ? item.confidence : (parseFloat(item.confidence) || 0.5),
            remediation: item.remediation || item.fix || 'No remediation provided.'
          };
          allFindings.push(normalized);
        }
      } else {
        // If parsing failed, include fallback finding with raw reply for visibility
        allFindings.push({
          file: 'multiple',
          line_range: 'n/a',
          issue: 'Analysis parse error — raw output included',
          severity: 'LOW',
          confidence: 0.5,
          remediation: `OpenAI reply could not be parsed as JSON. Raw reply:\n\n${reply}`
        });
      }
    }

    // Build issue body
    const bodyLines = [];
    bodyLines.push('Automated vulnerability analysis results (OpenAI).');
    bodyLines.push('');
    bodyLines.push('### Findings');

    allFindings.forEach((f, idx) => {
      bodyLines.push(`#### ${idx + 1}. ${f.issue}`);
      bodyLines.push(`- **File / Range:** ${f.file} / ${f.line_range}`);
      bodyLines.push(`- **Severity:** ${f.severity}`);
      bodyLines.push(`- **Confidence:** ${f.confidence}`);
      bodyLines.push(`- **Remediation:**\n\n\`\`\`\n${f.remediation}\n\`\`\``);
      bodyLines.push('');
    });

    // If there were any raw replies that contained extra info, append as folded details for debugging
    const problematicReplies = rawReplies.filter(r => !extractJsonFromText(r));
    if (problematicReplies.length > 0) {
      bodyLines.push('---');
      bodyLines.push('### Raw responses that could not be parsed as strict JSON (for debugging)');
      problematicReplies.forEach((r, i) => {
        // Fold long blocks
        bodyLines.push(`<details><summary>Raw reply ${i + 1}</summary>\n\n\n\`\`\`\n${r}\n\`\`\`\n</details>`);
      });
    }

    const issueTitle = `[AutoSecurity] ${allFindings.length} findings for ${PR_NUMBER ? 'PR #' + PR_NUMBER : 'recent push'}`;
    const issueBody = bodyLines.join('\n');

    // Create GitHub issue
    const octokit = new Octokit({ auth: GITHUB_TOKEN });
    const [owner, repo] = REPO.split('/');

    const issue = await octokit.rest.issues.create({
      owner,
      repo,
      title: issueTitle,
      body: issueBody,
      labels: ['security', 'auto-scan']
    });

    console.log('Created issue:', issue.data.html_url);
  } catch (err) {
    console.error('ERROR:', err);
    process.exit(1);
  }
})();
