#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { appendFile, readFile } from 'node:fs/promises';
import { parseArgs } from 'node:util';
import { pathToFileURL } from 'node:url';

const API_ROOT = 'https://api.github.com';
const API_VERSION = '2022-11-28';
export const DASHBOARD_MARKER = '<!-- discrete-release-gap-dashboard -->';
const FINGERPRINT_PREFIX = '<!-- release-gap-fingerprint:';

export class GitHubIssueApi {
  constructor({ token, fetchImpl = globalThis.fetch } = {}) {
    if (!token) throw new Error('GITHUB_TOKEN is required to publish the operator dashboard');
    this.token = token;
    this.fetchImpl = fetchImpl;
  }

  async request(method, path, body) {
    const response = await this.fetchImpl(new URL(path, API_ROOT), {
      method,
      headers: {
        Accept: 'application/vnd.github+json',
        Authorization: `Bearer ${this.token}`,
        'Content-Type': 'application/json',
        'User-Agent': 'discrete-release-gap-dashboard',
        'X-GitHub-Api-Version': API_VERSION,
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (!response.ok) {
      const responseBody = (await response.text()).slice(0, 500);
      throw new Error(`GitHub API ${response.status} for ${method} ${path}: ${responseBody}`);
    }
    return response.json();
  }

  async paginate(path, maxPages = 10) {
    const items = [];
    for (let page = 1; page <= maxPages; page += 1) {
      const separator = path.includes('?') ? '&' : '?';
      const batch = await this.request('GET', `${path}${separator}per_page=100&page=${page}`);
      if (!Array.isArray(batch)) throw new Error(`Expected an array from GitHub API path ${path}`);
      items.push(...batch);
      if (batch.length < 100) break;
    }
    return items;
  }
}

export function dashboardTitle(report) {
  const count = report.summary.actionable;
  if (count === 0) return 'Release/deployment dashboard: current';
  return `[ACTION REQUIRED] Release/deployment gaps (${count})`;
}

export function dashboardState(report) {
  return report.summary.actionable > 0 ? 'open' : 'closed';
}

export function findDashboardIssue(issues) {
  return issues.find((issue) => !issue.pull_request && String(issue.body ?? '').includes(DASHBOARD_MARKER)) ?? null;
}

export function dashboardFingerprint(report) {
  const actionable = report.results
    .filter((result) => result.actionable)
    .map((result) => ({
      repository: result.repository,
      status: result.status,
      headSha: result.headSha ?? '',
      releaseTag: result.release?.tag ?? '',
      runId: result.run?.id ?? '',
      deploymentId: result.deployment?.id ?? '',
      summary: result.summary,
    }))
    .sort((left, right) => left.repository.localeCompare(right.repository));
  return createHash('sha256').update(JSON.stringify(actionable)).digest('hex').slice(0, 16);
}

function issueFingerprint(issue) {
  const match = String(issue?.body ?? '').match(/<!-- release-gap-fingerprint:([a-f0-9]+) -->/);
  return match?.[1] ?? '';
}

function tableEscape(value) {
  return String(value ?? '').replaceAll('|', '\\|').replaceAll('\n', ' ');
}

function htmlText(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;');
}

function resultEvidence(result) {
  if (result.status === 'UNRELEASED_COMMITS') {
    return `${result.release.tag}; ${result.comparison.aheadBy} unreleased commit(s)`;
  }
  if (result.run) return `workflow run ${result.run.id}; ${result.run.conclusion ?? result.run.status}`;
  if (result.deployment) return `deployment ${result.deployment.id}; ${result.deployment.state}`;
  return result.summary;
}

export function renderDashboardBody(report, { runUrl = '' } = {}) {
  const fingerprint = dashboardFingerprint(report);
  const lines = [
    DASHBOARD_MARKER,
    `${FINGERPRINT_PREFIX}${fingerprint} -->`,
    '# Release/deployment dashboard',
    '',
    '> **How to read this:** open issue = operator action required; closed issue = all configured repositories current. A red workflow means the monitor itself could not complete verification.',
    '',
    `- Last checked: ${report.generatedAt}`,
    `- Action required: **${report.summary.actionable}**`,
    `- Current: **${report.summary.current}**`,
  ];
  if (runUrl) lines.push(`- Evidence run: [GitHub Actions](${runUrl})`);
  lines.push('', '| Repository | Result | Evidence |', '|---|---|---|');
  for (const result of report.results) {
    const repositoryUrl = `https://github.com/${report.owner}/${result.repository}`;
    lines.push(
      `| [${tableEscape(result.label)}](${repositoryUrl}) | ${tableEscape(result.status)} | ${tableEscape(resultEvidence(result))} |`,
    );
  }

  const actionable = report.results.filter((result) => result.actionable);
  if (actionable.length) {
    lines.push('', '## Required actions', '');
    for (const result of actionable) {
      lines.push(`### ${result.label}`, '', `- ${result.summary}`);
      if (result.headSha) lines.push(`- Source head: \`${result.headSha}\``);
      if (result.release) lines.push(`- Latest stable release: [${result.release.tag}](${result.release.url})`);
      if (result.commits?.length) {
        lines.push('- Relevant commits:');
        for (const commit of result.commits) {
          const pullLinks = commit.pullRequests
            .map((pull) => ` [#${pull.number}](${pull.url})`)
            .join('');
          lines.push(
            `  - [\`${commit.sha.slice(0, 12)}\`](${commit.url}) <code>${htmlText(commit.title)}</code>${pullLinks}`,
          );
        }
      }
      if (result.boundary) lines.push(`- Evidence boundary: ${result.boundary}`);
      lines.push('');
    }
  }

  lines.push(
    '## Evidence boundary',
    '',
    'A merge is not a release, and a release is not proof that a production process or VPS runs that version. Core and desktop-wallet deployment state remains unknown until the actual deployment path emits an authenticated receipt.',
    '',
    '_This issue is maintained automatically. Do not edit its body manually._',
    '',
  );
  return lines.join('\n');
}

export async function synchronizeDashboard({ api, repository, report, runUrl = '', assignee = '' }) {
  const [owner, name, ...rest] = String(repository).split('/');
  if (!owner || !name || rest.length) throw new Error(`Invalid GITHUB_REPOSITORY: ${repository}`);

  const issues = await api.paginate(`/repos/${owner}/${name}/issues?state=all`);
  const existing = findDashboardIssue(issues);
  const title = dashboardTitle(report);
  const body = renderDashboardBody(report, { runUrl });
  const state = dashboardState(report);
  const fingerprint = dashboardFingerprint(report);

  if (!existing) {
    const created = await api.request('POST', `/repos/${owner}/${name}/issues`, {
      title,
      body,
      ...(assignee ? { assignees: [assignee] } : {}),
    });
    if (state === 'closed') {
      const closed = await api.request('PATCH', `/repos/${owner}/${name}/issues/${created.number}`, {
        state: 'closed',
      });
      return { action: 'created-and-closed', issue: closed };
    }
    return { action: 'created', issue: created };
  }

  const currentState = existing.state === 'closed' ? 'closed' : 'open';
  if (existing.title === title && existing.body === body && currentState === state) {
    return { action: 'unchanged', issue: existing };
  }

  const updated = await api.request('PATCH', `/repos/${owner}/${name}/issues/${existing.number}`, {
    title,
    body,
    state,
    ...(state === 'open' && assignee ? { assignees: [assignee] } : {}),
  });
  const statusChanged = issueFingerprint(existing) !== fingerprint;
  if (state === 'open' && statusChanged) {
    const mention = assignee ? `@${assignee} — ` : '';
    const evidence = runUrl ? `\n- Evidence: [GitHub Actions](${runUrl})` : '';
    await api.request('POST', `/repos/${owner}/${name}/issues/${existing.number}/comments`, {
      body: `${mention}release/deployment status changed.\n\n- Action required: **${report.summary.actionable}**\n- Current: **${report.summary.current}**${evidence}\n\nThe dashboard body now contains the current SHAs and required actions.`,
    });
  }
  return {
    action: state === 'open' && currentState === 'closed' ? 'reopened' : 'updated',
    issue: updated,
    changeNotified: state === 'open' && statusChanged,
  };
}

async function main() {
  const { values } = parseArgs({
    options: {
      report: { type: 'string', default: 'release-gap-report.json' },
    },
  });
  const report = JSON.parse(await readFile(values.report, 'utf8'));
  const api = new GitHubIssueApi({ token: process.env.GITHUB_TOKEN });
  const result = await synchronizeDashboard({
    api,
    repository: process.env.GITHUB_REPOSITORY,
    report,
    runUrl: process.env.GITHUB_RUN_URL ?? '',
    assignee: process.env.DASHBOARD_ASSIGNEE ?? '',
  });
  const issueUrl = result.issue.html_url;
  process.stdout.write(`Operator dashboard ${result.action}: ${issueUrl}\n`);
  if (process.env.GITHUB_OUTPUT) {
    await appendFile(process.env.GITHUB_OUTPUT, `issue_url=${issueUrl}\nissue_number=${result.issue.number}\n`);
  }
  if (process.env.GITHUB_STEP_SUMMARY) {
    await appendFile(
      process.env.GITHUB_STEP_SUMMARY,
      `## Operator dashboard\n\n[Issue #${result.issue.number}](${issueUrl}) is **${dashboardState(report)}**.\n`,
    );
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}
