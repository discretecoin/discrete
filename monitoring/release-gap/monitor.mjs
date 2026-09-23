#!/usr/bin/env node

import { appendFile, readFile, writeFile } from 'node:fs/promises';
import { parseArgs } from 'node:util';
import { pathToFileURL } from 'node:url';

const API_ROOT = 'https://api.github.com';
const API_VERSION = '2022-11-28';
const MAX_DETAIL_COMMITS = 25;

export class GitHubApi {
  constructor({ token = '', fetchImpl = globalThis.fetch } = {}) {
    this.token = token;
    this.fetchImpl = fetchImpl;
  }

  async get(path, query = {}) {
    const url = new URL(path, API_ROOT);
    for (const [key, value] of Object.entries(query)) {
      if (value !== undefined && value !== null && value !== '') {
        url.searchParams.set(key, String(value));
      }
    }

    let response = await this.#request(url, Boolean(this.token));
    if (this.token && (response.status === 403 || response.status === 404)) {
      response = await this.#request(url, false);
    }

    if (!response.ok) {
      const body = (await response.text()).slice(0, 500);
      throw new Error(`GitHub API ${response.status} for ${url.pathname}: ${body}`);
    }

    return response.json();
  }

  async paginate(path, query = {}, maxPages = 10) {
    const items = [];
    const perPage = 100;
    for (let page = 1; page <= maxPages; page += 1) {
      const batch = await this.get(path, { ...query, per_page: perPage, page });
      if (!Array.isArray(batch)) {
        throw new Error(`Expected an array from GitHub API path ${path}`);
      }
      items.push(...batch);
      if (batch.length < perPage) break;
    }
    return items;
  }

  #request(url, authenticated) {
    const headers = {
      Accept: 'application/vnd.github+json',
      'User-Agent': 'discrete-release-gap-monitor',
      'X-GitHub-Api-Version': API_VERSION,
    };
    if (authenticated) headers.Authorization = `Bearer ${this.token}`;
    return this.fetchImpl(url, { headers });
  }
}

function repositoryUrl(owner, name) {
  return `https://github.com/${owner}/${name}`;
}

function shortSha(sha) {
  return sha ? sha.slice(0, 12) : 'unknown';
}

function firstLine(value) {
  return String(value ?? '').split(/\r?\n/, 1)[0];
}

function escapeTable(value) {
  return String(value ?? '').replaceAll('|', '\\|').replaceAll('\n', ' ');
}

function htmlText(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;');
}

export function extractPullRequestNumbers(message) {
  const numbers = new Set();
  const patterns = [
    /\bPR\s*#(\d+)\b/gi,
    /\bmerge pull request\s*#(\d+)\b/gi,
    /\bmerge\s+#(\d+)\b/gi,
    /\(#(\d+)\)/g,
  ];
  for (const pattern of patterns) {
    for (const match of String(message ?? '').matchAll(pattern)) numbers.add(Number(match[1]));
  }
  return [...numbers].sort((left, right) => left - right);
}

export function classifyRelease({ policy, release, comparison }) {
  if (!release) {
    return {
      status: 'NO_RELEASE',
      actionable: true,
      summary: 'No stable GitHub release exists',
    };
  }

  if (comparison.behind_by > 0) {
    return {
      status: 'RELEASE_DIVERGED',
      actionable: true,
      summary: `${release.tag_name} is not an ancestor of ${policy.branch}`,
    };
  }

  if (comparison.ahead_by > 0) {
    return {
      status: 'UNRELEASED_COMMITS',
      actionable: true,
      summary: `${comparison.ahead_by} commit(s) on ${policy.branch} are not in ${release.tag_name}`,
    };
  }

  return {
    status: 'CURRENT',
    actionable: false,
    summary: `${policy.branch} is included in ${release.tag_name}`,
  };
}

export function classifyDirectDeployment({ headSha, deployments }) {
  const current = deployments.find((deployment) => deployment.sha === headSha);
  if (current?.state === 'success') {
    return {
      status: 'CURRENT',
      actionable: false,
      summary: `Source ${shortSha(headSha)} has a successful deployment`,
      deployment: current,
    };
  }
  if (current) {
    return {
      status: 'DEPLOYMENT_NOT_SUCCESSFUL',
      actionable: true,
      summary: `Deployment for source ${shortSha(headSha)} is ${current.state}`,
      deployment: current,
    };
  }

  const latestSuccessful = deployments.find((deployment) => deployment.state === 'success');
  return {
    status: 'SOURCE_NOT_DEPLOYED',
    actionable: true,
    summary: latestSuccessful
      ? `Latest successful deployment is ${shortSha(latestSuccessful.sha)}, source is ${shortSha(headSha)}`
      : `No successful deployment exists for source ${shortSha(headSha)}`,
    deployment: latestSuccessful ?? deployments[0] ?? null,
  };
}

export function classifyWorkflowDeployment({ headSha, runs }) {
  const run = runs.find((candidate) => candidate.head_sha === headSha);
  if (run?.status === 'completed' && run.conclusion === 'success') {
    return {
      status: 'CURRENT',
      actionable: false,
      summary: `Deploy workflow succeeded for source ${shortSha(headSha)}`,
      run,
    };
  }
  if (run) {
    return {
      status: 'DEPLOY_WORKFLOW_NOT_SUCCESSFUL',
      actionable: true,
      summary: `Deploy workflow for ${shortSha(headSha)} is ${run.conclusion ?? run.status}`,
      run,
    };
  }
  return {
    status: 'SOURCE_NOT_DEPLOYED',
    actionable: true,
    summary: `No deploy workflow run exists for source ${shortSha(headSha)}`,
    run: null,
  };
}

export function findMissingPolicies(discoveredRepositories, policies) {
  const configured = new Set(policies.map((policy) => policy.name));
  return discoveredRepositories
    .filter((repository) => !repository.archived && !repository.disabled)
    .filter((repository) => !configured.has(repository.name))
    .map((repository) => repository.name)
    .sort();
}

function comparisonCommits(owner, repository, commits) {
  return commits.slice(-MAX_DETAIL_COMMITS).map((entry) => {
    const title = firstLine(entry.commit?.message);
    return {
      sha: entry.sha,
      title,
      url: entry.html_url,
      pullRequests: extractPullRequestNumbers(title).map((number) => ({
        number,
        url: `${repositoryUrl(owner, repository)}/pull/${number}`,
      })),
    };
  });
}

async function inspectRelease(api, owner, policy, headSha) {
  const releases = await api.paginate(`/repos/${owner}/${policy.name}/releases`, {}, 2);
  const release = releases
    .filter((candidate) => !candidate.draft && !candidate.prerelease)
    .sort((left, right) => Date.parse(right.published_at) - Date.parse(left.published_at))[0] ?? null;
  if (!release) {
    return {
      repository: policy.name,
      label: policy.label,
      kind: policy.kind,
      branch: policy.branch,
      headSha,
      ...classifyRelease({ policy, release: null, comparison: null }),
      boundary: 'GitHub release state only; production runtime deployment is not observed.',
    };
  }

  const base = encodeURIComponent(release.tag_name);
  const head = encodeURIComponent(policy.branch);
  const comparison = await api.get(`/repos/${owner}/${policy.name}/compare/${base}...${head}`);
  return {
    repository: policy.name,
    label: policy.label,
    kind: policy.kind,
    branch: policy.branch,
    headSha,
    release: {
      tag: release.tag_name,
      url: release.html_url,
      publishedAt: release.published_at,
    },
    comparison: {
      status: comparison.status,
      aheadBy: comparison.ahead_by,
      behindBy: comparison.behind_by,
      totalCommits: comparison.total_commits,
    },
    commits: comparisonCommits(owner, policy.name, comparison.commits ?? []),
    ...classifyRelease({ policy, release, comparison }),
    boundary: 'GitHub release state only; production runtime deployment is not observed.',
  };
}

async function deploymentStates(api, owner, policy) {
  const deployments = await api.paginate(
    `/repos/${owner}/${policy.name}/deployments`,
    { environment: policy.environment },
    2,
  );
  const inspected = [];
  for (const deployment of deployments.slice(0, 30)) {
    const statuses = await api.paginate(
      `/repos/${owner}/${policy.name}/deployments/${deployment.id}/statuses`,
      {},
      1,
    );
    inspected.push({
      id: deployment.id,
      sha: deployment.sha,
      ref: deployment.ref,
      environment: deployment.environment,
      createdAt: deployment.created_at,
      state: statuses[0]?.state ?? 'unknown',
      url: `${repositoryUrl(owner, policy.name)}/deployments/${policy.environment}`,
    });
    if (inspected.at(-1).state === 'success') break;
  }
  return inspected;
}

async function inspectDirectDeployment(api, owner, policy, headSha) {
  const deployments = await deploymentStates(api, owner, policy);
  return {
    repository: policy.name,
    label: policy.label,
    kind: policy.kind,
    branch: policy.branch,
    headSha,
    ...classifyDirectDeployment({ headSha, deployments }),
    deployments,
    boundary: `GitHub deployment environment ${policy.environment}; external runtime content is not probed.`,
  };
}

async function inspectWorkflowDeployment(api, owner, policy, headSha) {
  const workflow = encodeURIComponent(policy.workflow);
  const response = await api.get(
    `/repos/${owner}/${policy.name}/actions/workflows/${workflow}/runs`,
    { branch: policy.branch, event: 'push', per_page: 100 },
  );
  const runs = response.workflow_runs ?? [];
  return {
    repository: policy.name,
    label: policy.label,
    kind: policy.kind,
    branch: policy.branch,
    headSha,
    workflow: policy.workflow,
    ...classifyWorkflowDeployment({ headSha, runs }),
    boundary: 'A successful deploy workflow for the exact source SHA counts even when publishing was a no-op.',
  };
}

async function inspectPolicy(api, owner, policy) {
  const repository = await api.get(`/repos/${owner}/${policy.name}`);
  if (repository.default_branch !== policy.branch) {
    return {
      repository: policy.name,
      label: policy.label,
      kind: policy.kind,
      branch: policy.branch,
      status: 'POLICY_BRANCH_MISMATCH',
      actionable: true,
      summary: `Configured branch ${policy.branch}, GitHub default is ${repository.default_branch}`,
    };
  }

  const head = await api.get(`/repos/${owner}/${policy.name}/commits/${encodeURIComponent(policy.branch)}`);
  if (policy.kind === 'release') return inspectRelease(api, owner, policy, head.sha);
  if (policy.kind === 'pages-direct') return inspectDirectDeployment(api, owner, policy, head.sha);
  if (policy.kind === 'pages-workflow') return inspectWorkflowDeployment(api, owner, policy, head.sha);
  return {
    repository: policy.name,
    label: policy.label,
    kind: policy.kind,
    branch: policy.branch,
    headSha: head.sha,
    status: 'UNKNOWN_POLICY_KIND',
    actionable: true,
    summary: `Unsupported policy kind: ${policy.kind}`,
  };
}

export async function runMonitor({ api, config, now = new Date() }) {
  const results = [];
  let discovered = [];
  if (config.discoverPublicRepositories) {
    try {
      discovered = await api.paginate(`/orgs/${config.owner}/repos`, { type: 'public' });
      for (const name of findMissingPolicies(discovered, config.repositories)) {
        results.push({
          repository: name,
          label: name,
          kind: 'unconfigured',
          status: 'POLICY_MISSING',
          actionable: true,
          summary: 'Active public canonical repository has no monitoring policy',
        });
      }
    } catch (error) {
      results.push({
        repository: config.owner,
        label: `${config.owner} repository discovery`,
        kind: 'discovery',
        status: 'API_ERROR',
        actionable: true,
        summary: error.message,
      });
    }
  }

  for (const policy of config.repositories) {
    try {
      results.push(await inspectPolicy(api, config.owner, policy));
    } catch (error) {
      results.push({
        repository: policy.name,
        label: policy.label,
        kind: policy.kind,
        branch: policy.branch,
        status: 'API_ERROR',
        actionable: true,
        summary: error.message,
      });
    }
  }

  const actionable = results.filter((result) => result.actionable).length;
  const monitorErrors = results.filter((result) =>
    ['API_ERROR', 'UNKNOWN_POLICY_KIND'].includes(result.status),
  ).length;
  return {
    schemaVersion: 1,
    generatedAt: now.toISOString(),
    owner: config.owner,
    summary: {
      repositories: results.length,
      current: results.length - actionable,
      actionable,
      monitorErrors,
    },
    results,
  };
}

function statusMark(result) {
  return result.actionable ? 'ACTION REQUIRED' : 'CURRENT';
}

function resultEvidence(result) {
  if (result.status === 'UNRELEASED_COMMITS') {
    return `${result.release.tag}; ${result.comparison.aheadBy} unreleased commit(s)`;
  }
  if (result.kind === 'release' && result.release) return result.release.tag;
  if (result.run) return `run ${result.run.id}; ${result.run.conclusion ?? result.run.status}`;
  if (result.deployment) return `deployment ${result.deployment.id}; ${shortSha(result.deployment.sha)}`;
  return result.summary;
}

export function renderMarkdown(report) {
  const lines = [
    '# Discrete canonical repository release/deployment gaps',
    '',
    `Generated: ${report.generatedAt}`,
    '',
    `Action required: **${report.summary.actionable}**; current: **${report.summary.current}**.`,
    '',
    report.summary.monitorErrors > 0
      ? '> **Monitor incomplete.** Verification errors require operator attention; the workflow is red.'
      : report.summary.actionable > 0
        ? '> **Monitor healthy.** The workflow stays green; the open operator dashboard issue tracks required release or deployment work.'
        : '> **Monitor healthy.** All configured release and deployment evidence is current; the operator dashboard issue is closed.',
    '',
    '| Repository | Policy | Result | Evidence |',
    '|---|---|---|---|',
  ];

  for (const result of report.results) {
    const url = repositoryUrl(report.owner, result.repository);
    lines.push(
      `| [${escapeTable(result.label)}](${url}) | ${escapeTable(result.kind)} | ${statusMark(result)}: ${escapeTable(result.status)} | ${escapeTable(resultEvidence(result))} |`,
    );
  }

  const findings = report.results.filter((result) => result.actionable);
  if (findings.length) {
    lines.push('', '## Actionable findings', '');
    for (const result of findings) {
      lines.push(`### ${result.label}`, '', `- ${result.summary}`);
      if (result.headSha) lines.push(`- Source head: \`${result.headSha}\``);
      if (result.release) lines.push(`- Latest stable release: [${result.release.tag}](${result.release.url})`);
      if (result.commits?.length) {
        lines.push('- Unreleased commits:');
        for (const commit of result.commits) {
          const pulls = commit.pullRequests
            .map((pull) => ` [#${pull.number}](${pull.url})`)
            .join('');
          lines.push(
            `  - [\`${shortSha(commit.sha)}\`](${commit.url}) <code>${htmlText(commit.title)}</code>${pulls}`,
          );
        }
        if (result.comparison.aheadBy > result.commits.length) {
          lines.push(`  - ...plus ${result.comparison.aheadBy - result.commits.length} earlier commit(s)`);
        }
      }
      if (result.run?.html_url) lines.push(`- Workflow run: ${result.run.html_url}`);
      if (result.boundary) lines.push(`- Evidence boundary: ${result.boundary}`);
      lines.push('');
    }
  }

  lines.push(
    '## Evidence boundaries',
    '',
    '- Release policies compare the latest stable GitHub release tag with the canonical branch.',
    '- Direct Pages policies require a successful GitHub deployment for the exact source SHA.',
    '- Workflow Pages policies require a successful deploy workflow run for the exact source SHA; a successful no-op publish is current.',
    '- Core and desktop-wallet production runtime state is not inferred from a merge or a release. Add an authenticated deployment receipt before making that claim.',
    '',
  );
  return lines.join('\n');
}

async function main() {
  const { values } = parseArgs({
    options: {
      config: { type: 'string', default: 'monitoring/release-gap/config.json' },
      json: { type: 'string', default: 'release-gap-report.json' },
      markdown: { type: 'string', default: 'release-gap-report.md' },
      'fail-on-gap': { type: 'string', default: 'true' },
    },
  });
  const config = JSON.parse(await readFile(values.config, 'utf8'));
  const api = new GitHubApi({ token: process.env.GH_TOKEN || process.env.GITHUB_TOKEN || '' });
  const report = await runMonitor({ api, config });
  const markdown = renderMarkdown(report);
  await writeFile(values.json, `${JSON.stringify(report, null, 2)}\n`);
  await writeFile(values.markdown, markdown);
  if (process.env.GITHUB_STEP_SUMMARY) {
    await appendFile(process.env.GITHUB_STEP_SUMMARY, markdown);
  }
  if (process.env.GITHUB_OUTPUT) {
    await appendFile(process.env.GITHUB_OUTPUT, `actionable_count=${report.summary.actionable}\n`);
    await appendFile(process.env.GITHUB_OUTPUT, `monitor_error_count=${report.summary.monitorErrors}\n`);
  }
  process.stdout.write(markdown);
  if (values['fail-on-gap'] !== 'false' && report.summary.actionable > 0) process.exitCode = 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}
