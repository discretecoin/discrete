import assert from 'node:assert/strict';
import test from 'node:test';

import {
  classifyDirectDeployment,
  classifyRelease,
  classifyWorkflowDeployment,
  extractPullRequestNumbers,
  findMissingPolicies,
  renderMarkdown,
} from './monitor.mjs';

const policy = { branch: 'main' };

test('release policy is current when canonical branch has no commits after the release', () => {
  const result = classifyRelease({
    policy,
    release: { tag_name: 'v1.2.3' },
    comparison: { ahead_by: 0, behind_by: 0 },
  });
  assert.equal(result.status, 'CURRENT');
  assert.equal(result.actionable, false);
});

test('release policy flags commits after the latest release', () => {
  const result = classifyRelease({
    policy,
    release: { tag_name: 'v1.2.3' },
    comparison: { ahead_by: 4, behind_by: 0 },
  });
  assert.equal(result.status, 'UNRELEASED_COMMITS');
  assert.equal(result.actionable, true);
});

test('release policy treats a diverged release as actionable', () => {
  const result = classifyRelease({
    policy,
    release: { tag_name: 'v1.2.3' },
    comparison: { ahead_by: 2, behind_by: 1 },
  });
  assert.equal(result.status, 'RELEASE_DIVERGED');
  assert.equal(result.actionable, true);
});

test('direct deployment requires success for the exact source SHA', () => {
  const stale = classifyDirectDeployment({
    headSha: 'bbbbbbbbbbbbbbbb',
    deployments: [{ id: 1, sha: 'aaaaaaaaaaaaaaaa', state: 'success' }],
  });
  assert.equal(stale.status, 'SOURCE_NOT_DEPLOYED');

  const current = classifyDirectDeployment({
    headSha: 'bbbbbbbbbbbbbbbb',
    deployments: [{ id: 2, sha: 'bbbbbbbbbbbbbbbb', state: 'success' }],
  });
  assert.equal(current.status, 'CURRENT');
});

test('failed deployment for the exact source SHA is actionable', () => {
  const result = classifyDirectDeployment({
    headSha: 'bbbbbbbbbbbbbbbb',
    deployments: [{ id: 2, sha: 'bbbbbbbbbbbbbbbb', state: 'failure' }],
  });
  assert.equal(result.status, 'DEPLOYMENT_NOT_SUCCESSFUL');
  assert.equal(result.actionable, true);
});

test('successful no-op publish workflow counts as current for the exact source SHA', () => {
  const result = classifyWorkflowDeployment({
    headSha: 'cccccccccccccccc',
    runs: [{ id: 3, head_sha: 'cccccccccccccccc', status: 'completed', conclusion: 'success' }],
  });
  assert.equal(result.status, 'CURRENT');
  assert.equal(result.actionable, false);
});

test('active public repositories without policy are reported', () => {
  const missing = findMissingPolicies(
    [
      { name: 'configured', archived: false, disabled: false },
      { name: 'new-repository', archived: false, disabled: false },
      { name: 'old-repository', archived: true, disabled: false },
    ],
    [{ name: 'configured' }],
  );
  assert.deepEqual(missing, ['new-repository']);
});

test('pull request numbers are extracted without duplicates', () => {
  assert.deepEqual(extractPullRequestNumbers('Merge pull request #44: work (PR #44) Merge #45'), [44, 45]);
});

test('Markdown report includes evidence boundary and actionable commits', () => {
  const markdown = renderMarkdown({
    generatedAt: '2026-09-23T00:00:00.000Z',
    owner: 'discretecoin',
    summary: { actionable: 1, current: 0, monitorErrors: 0 },
    results: [
      {
        repository: 'discrete',
        label: 'Discrete Core',
        kind: 'release',
        status: 'UNRELEASED_COMMITS',
        actionable: true,
        summary: '1 commit is not released',
        headSha: 'abcdef1234567890',
        release: { tag: 'v1', url: 'https://example.test/release' },
        comparison: { aheadBy: 1 },
        commits: [
          {
            sha: 'abcdef1234567890',
            title: 'Change (#44)',
            url: 'https://example.test/commit',
            pullRequests: [{ number: 44, url: 'https://example.test/pull/44' }],
          },
        ],
        boundary: 'GitHub release only.',
      },
    ],
  });
  assert.match(markdown, /#44/);
  assert.match(markdown, /<code>Change \(#44\)<\/code>/);
  assert.match(markdown, /GitHub release only/);
  assert.match(markdown, /Monitor healthy/);
  assert.match(markdown, /operator dashboard issue/);
  assert.match(markdown, /production runtime state is not inferred/);
});
