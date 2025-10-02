// requires: node 18+, packages: node-fetch (or built-in fetch in node18+), @octokit/rest
import fs from "fs";
import path from "path";
import process from "process";
import { Octokit } from "@octokit/rest";

const OPENAI_KEY = process.env.OPENAI_API_KEY;
const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
const REPO = process.env.GITHUB_REPOSITORY; // owner/repo
const PR_NUMBER = process.env.PR_NUMBER || null;

if (!OPENAI_KEY) {
  console.error("OPENAI_API_KEY missing");
  process.exit(1);
}
if (!GITHUB_TOKEN) {
  console.error("GITHUB_TOKEN missing");
  process.exit(1);
}

const diffPath = path.resolve(".github/scripts/pr.diff");
const raw = fs.existsSync(diffPath) ? fs.readFileSync(diffPath, "utf8") : "";

if (!raw || raw.trim().length === 0) {
  console.log("No diff found — exiting.");
  process.exit(0);
}

// Helper: chunk long diffs into pieces under N chars
function chunkText(text, maxChars = 20000) {
  const chunks = [];
  for (let i = 0; i < text.length; i += maxChars) {
    chunks.push(text.slice(i, i + maxChars));
  }
  return chunks;
}

// Prompt template (you can tune it)
function buildPrompt(diffChunk) {
  return [
    { role: "system", content: "You are a security analyst that finds code vulnerabilities. Return a JSON array of findings with fields: file, line_range, issue, severity (LOW/MEDIUM/HIGH/CRITICAL), confidence(0-1), remediation." },
    { role: "user", content: `Analyze the following git diff for security vulnerabilities, insecure patterns, potential misconfigurations, secrets, or risky dependencies. Return ONLY JSON.\n\nDIFF:\n${diffChunk}` }
  ];
}

async function callOpenAI(messages) {
  const res = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${OPENAI_KEY}`
    },
    body: JSON.stringify({
      model: "gpt-4o-mini", // 원하는 모델로 교체하세요
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
  const reply = data.choices?.[0]?.message?.content || "";
  return reply;
}

// Main:
(async () => {
  try {
    const chunks = chunkText(raw, 15000);
    const allFindings = [];

    for (let i = 0; i < chunks.length; i++) {
      const messages = buildPrompt(chunks[i]);
      const reply = await callOpenAI(messages);

      // Try to extract JSON from the reply
      let json;
      try {
        const firstBrace = reply.indexOf("{");
        const firstBracket = reply.indexOf("[");
        const start = (firstBracket >= 0) ? firstBracket : firstBrace;
        json = JSON.parse(reply.slice(start));
      } catch (e) {
        // Fallback: put whole reply as an info finding
        json = [{
          file: "multiple",
          line_range: "n/a",
          issue: "Analysis parse error — raw output included",
          severity: "LOW",
          confidence: 0.5,
          remediation: `OpenAI reply could not be parsed as JSON. Raw reply:\n\n${reply}`
        }];
      }
      allFindings.push(...json);
    }

    // Summarize into issue body
    const bodyLines = [];
    bodyLines.push("Automated vulnerability analysis results (OpenAI).");
    bodyLines.push("");
    bodyLines.push("### Findings");
    allFindings.forEach((f, idx) => {
      bodyLines.push(`#### ${idx+1}. ${f.issue}`);
      bodyLines.push(`- **File / Range:** ${f.file} / ${f.line_range}`);
      bodyLines.push(`- **Severity:** ${f.severity}`);
      bodyLines.push(`- **Confidence:** ${f.confidence}`);
      bodyLines.push(`- **Remediation:**\n\n\`\`\`\n${f.remediation}\n\`\`\``);
      bodyLines.push("");
    });

    const issueTitle = `[AutoSecurity] ${allFindings.length} findings for ${PR_NUMBER ? "PR #"+PR_NUMBER : "recent push"}`;
    const issueBody = bodyLines.join("\n");

    // Create GitHub issue
    const octokit = new Octokit({ auth: GITHUB_TOKEN });
    const [owner, repo] = REPO.split("/");

    const issue = await octokit.rest.issues.create({
      owner,
      repo,
      title: issueTitle,
      body: issueBody,
      labels: ["security", "auto-scan"]
    });

    console.log("Created issue:", issue.data.html_url);
  } catch (err) {
    console.error("ERROR:", err);
    process.exit(1);
  }
})();
