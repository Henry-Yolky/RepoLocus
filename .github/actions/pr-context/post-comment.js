"use strict";

const fs = require("fs");

const marker = "<!-- repolocus-pr-context -->";
const maxBodyLength = 60_000;

function fail(message) {
  throw new Error(`RepoLocus PR comment refused: ${message}`);
}

function required(name) {
  const value = process.env[name] || "";
  if (!value) fail(`${name} is required`);
  return value;
}

async function request(url, token, options = {}) {
  const response = await fetch(url, {
    ...options,
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${token}`,
      "X-GitHub-Api-Version": "2022-11-28",
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
  });
  if (!response.ok) {
    const detail = (await response.text()).slice(0, 500);
    fail(`GitHub API returned ${response.status}: ${detail}`);
  }
  return response.status === 204 ? null : response.json();
}

async function main() {
  if (required("GITHUB_EVENT_NAME") !== "pull_request") {
    fail("only pull_request events may publish comments");
  }
  const event = JSON.parse(fs.readFileSync(required("GITHUB_EVENT_PATH"), "utf8"));
  const pullRequest = event.pull_request;
  if (!pullRequest || !Number.isSafeInteger(pullRequest.number) || pullRequest.number < 1) {
    fail("pull-request metadata is missing");
  }
  const baseRepository = pullRequest.base?.repo?.full_name;
  const headRepository = pullRequest.head?.repo?.full_name;
  if (!baseRepository || baseRepository !== headRepository || baseRepository !== required("GITHUB_REPOSITORY")) {
    fail("fork or repository-mismatched pull requests cannot publish comments");
  }
  if (pullRequest.base.sha !== required("BASE_REF") || pullRequest.head.sha !== required("HEAD_REF")) {
    fail("artifact revisions do not match the event revisions");
  }

  const token = required("COMMENT_TOKEN");
  let body = fs.readFileSync(required("MARKDOWN_PATH"), "utf8");
  if (body.length > maxBodyLength) {
    body = `${body.slice(0, maxBodyLength)}\n\n_Context truncated; download the JSON artifact for the complete diff._\n`;
  }
  body = `${marker}\n${body}`;

  const api = required("GITHUB_API_URL").replace(/\/$/, "");
  const [owner, repository] = baseRepository.split("/");
  const commentsUrl = `${api}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repository)}` +
    `/issues/${pullRequest.number}/comments`;
  const comments = await request(`${commentsUrl}?per_page=100`, token);
  const existing = comments.find(
    (comment) => comment.user?.login === "github-actions[bot]" &&
      typeof comment.body === "string" && comment.body.startsWith(marker),
  );
  if (existing) {
    await request(`${api}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repository)}` +
      `/issues/comments/${existing.id}`, token, { method: "PATCH", body: JSON.stringify({ body }) });
  } else {
    await request(commentsUrl, token, { method: "POST", body: JSON.stringify({ body }) });
  }
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
