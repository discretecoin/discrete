import assert from 'node:assert/strict';
import test from 'node:test';

import {
  DASHBOARD_MARKER,
  dashboardFingerprint,
  dashboardState,
  dashboardTitle,
  findDashboardIssue,
  renderDashboardBody,
  synchronizeDashboard,
} from './publish-issue.mjs';

function report(actionable = 2) {
  return {
    generatedAt: '2026-09-23T00:00:00.000Z',
    owner: 'discretecoin',
    summary: { actionable, current: actionable ? 4 : 6, monitorErrors: 0 },
    results: actionable
      ? [
          {
            repository: 'discrete',
            label: 'Discrete Core',
            status: 'UNRELEASED_COMMITS',
            actionable: true,
            summary: '30 commits are not released',
            headSha: 'abcdef1234567890',
            release: { tag: 'v1', url: 'https://example.test/release' },
            comparison: { aheadBy: 30 },
            commits: [],
            boundary: 'Release state only.',
          },
        ]
      : [],
  };
}

class FakeApi {
  constructor(issues = []) {
    this.issues = issues;
    this.requests = [];
  }

  async paginate() {
    return this.issues;
  }

  async request(method, path, body) {
    this.requests.push({ method, path, body });
    return {
      number: 7,
      title: body.title ?? this.issues[0]?.title,
      body: body.body ?? this.issues[0]?.body,
      state: body.state ?? 'open',
      html_url: 'https://example.test/issues/7',
    };
  }
}

test('dashboard title and state communicate action rather than monitor health', () => {
  assert.equal(dashboardTitle(report(2)), '[ACTION REQUIRED] Release/deployment gaps (2)');
  assert.equal(dashboardState(report(2)), 'open');
  assert.equal(dashboardTitle(report(0)), 'Release/deployment dashboard: current');
  assert.equal(dashboardState(report(0)), 'closed');
});

test('dashboard body explains the open/closed contract', () => {
  const body = renderDashboardBody(report(2), { runUrl: 'https://example.test/run' });
  assert.match(body, new RegExp(DASHBOARD_MARKER));
  assert.match(body, /open issue = operator action required/);
  assert.match(body, /30 commits are not released/);
  assert.match(body, /GitHub Actions/);
  assert.match(body, new RegExp(`release-gap-fingerprint:${dashboardFingerprint(report(2))}`));
});

test('dashboard body prevents cross-repository issue autolinks in commit titles', () => {
  const unsafeReport = report(2);
  unsafeReport.results[0].commits = [
    {
      sha: 'abcdef1234567890',
      url: 'https://example.test/commit',
      title: 'Merge #44: [wallet] fix',
      pullRequests: [{ number: 44, url: 'https://example.test/pull/44' }],
    },
  ];
  const body = renderDashboardBody(unsafeReport);
  assert.ok(body.includes('<code>Merge #44: [wallet] fix</code>'));
  assert.match(body, /\[#44\]\(https:\/\/example\.test\/pull\/44\)/);
});

test('dashboard issue lookup ignores pull requests', () => {
  const issue = { number: 2, body: DASHBOARD_MARKER };
  assert.equal(
    findDashboardIssue([
      { number: 1, body: DASHBOARD_MARKER, pull_request: {} },
      issue,
    ]),
    issue,
  );
});

test('synchronization creates an assigned open dashboard for gaps', async () => {
  const api = new FakeApi();
  const result = await synchronizeDashboard({
    api,
    repository: 'MatthewFreeman/discrete-infrastructure',
    report: report(2),
    runUrl: 'https://example.test/run',
    assignee: 'MatthewFreeman',
  });
  assert.equal(result.action, 'created');
  assert.deepEqual(api.requests[0].body.assignees, ['MatthewFreeman']);
  assert.match(api.requests[0].body.title, /\[ACTION REQUIRED\].*\(2\)/);
});

test('synchronization closes the dashboard when all repositories are current', async () => {
  const existing = {
    number: 7,
    title: '[ACTION REQUIRED] Release/deployment gaps (2)',
    body: DASHBOARD_MARKER,
    state: 'open',
  };
  const api = new FakeApi([existing]);
  const result = await synchronizeDashboard({
    api,
    repository: 'MatthewFreeman/discrete-infrastructure',
    report: report(0),
  });
  assert.equal(result.action, 'updated');
  assert.equal(api.requests[0].body.state, 'closed');
  assert.equal(api.requests[0].body.title, 'Release/deployment dashboard: current');
});

test('synchronization comments only when the actionable snapshot changes', async () => {
  const oldReport = report(2);
  oldReport.results[0].headSha = 'old-head';
  const existing = {
    number: 7,
    title: dashboardTitle(oldReport),
    body: renderDashboardBody(oldReport),
    state: 'open',
  };
  const api = new FakeApi([existing]);
  const result = await synchronizeDashboard({
    api,
    repository: 'MatthewFreeman/discrete-infrastructure',
    report: report(2),
    runUrl: 'https://example.test/run',
    assignee: 'MatthewFreeman',
  });
  assert.equal(result.changeNotified, true);
  assert.equal(api.requests[1].path, '/repos/MatthewFreeman/discrete-infrastructure/issues/7/comments');
  assert.match(api.requests[1].body.body, /@MatthewFreeman — release\/deployment status changed/);

  const unchangedReport = report(2);
  const unchangedApi = new FakeApi([
    {
      number: 7,
      title: dashboardTitle(unchangedReport),
      body: renderDashboardBody(unchangedReport),
      state: 'open',
    },
  ]);
  const unchanged = await synchronizeDashboard({
    api: unchangedApi,
    repository: 'MatthewFreeman/discrete-infrastructure',
    report: unchangedReport,
  });
  assert.equal(unchanged.action, 'unchanged');
  assert.equal(unchangedApi.requests.length, 0);
});
