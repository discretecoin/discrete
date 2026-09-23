# Canonical release and deployment gap monitor

The scheduled GitHub Action in this canonical repository checks every active public repository in
the `discretecoin` organization every six hours and can also be run manually. It never merges, tags,
publishes, deploys, or modifies another repository. Its only write is the operator dashboard issue
in this repository.

The current inventory is public, so the workflow works without a secret. GitHub's built-in
`GITHUB_TOKEN` is deliberately not used for cross-repository reads because it is scoped to this
repository. If private repositories are added or unauthenticated API limits become a problem, add a
read-only GitHub App token or fine-grained token as the `DISCRETE_MONITOR_TOKEN` repository secret.

## What the monitor flags

- A canonical branch contains commits after its latest stable GitHub release.
- A release tag is not an ancestor of the configured canonical branch.
- The exact current source SHA of a direct GitHub Pages repository has no successful deployment.
- The exact current source SHA of a workflow-published Pages repository has no successful deploy
  workflow run.
- A new active public repository appears without an explicit monitoring policy.
- Required GitHub evidence cannot be read or a configured default branch no longer matches GitHub.

The first five states are repository action signals. They keep the dashboard issue open but do not
make a healthy workflow red. GitHub/API/configuration failures make the workflow red because the
verification is incomplete.

The workflow health and repository status are deliberately separate:

- A green workflow means the monitor completed its checks and published its evidence.
- One automatically maintained operator issue stays open while release/deployment action is needed.
- The issue title contains the current action count; its body contains the repository table, exact
  SHAs, relevant commits/PRs, evidence link, and evidence boundaries.
- The issue is updated in place and closes automatically when every configured repository is current.
- A changed actionable SHA or status adds one issue comment and explicitly mentions the configured
  dashboard assignee; unchanged scheduled checks do not add comments.
- A red workflow is reserved for an incomplete verification, API failure, or invalid monitor policy.

The run summary names the repository, exact source SHA, release or deployment evidence,
and the latest 25 unreleased commits. Pull request links are included when the commit subject contains
a PR number.

## Policy file

`monitoring/release-gap/config.json` is the canonical inventory. Supported policy kinds are:

- `release`: compare the latest stable release tag with the canonical branch.
- `pages-direct`: require a successful deployment for the exact canonical-branch SHA.
- `pages-workflow`: require a successful named deployment workflow run for the exact source SHA.

Repository discovery deliberately fails closed. When a new active public repository is added to
the organization, the monitor stays red until its release/deployment policy is added.

## Evidence boundary

A merge is not a release, and a release is not proof that a production process or VPS runs that
version. The Core and desktop-wallet policies detect unreleased source only. Production deployment
claims require a separate authenticated receipt emitted by the actual deployment path, such as a
GitHub deployment tied to the deployed commit or release asset digest.

For GitHub Pages repositories, GitHub's deployment/workflow records are the observed delivery
evidence. The monitor does not probe user-visible page content.

## Operator use

Open **Issues** for the operator-facing dashboard. An open dashboard issue means action is required;
a closed dashboard issue means every configured repository is current. Use **Actions → Monitor
canonical release and deployment gaps** for monitor health, exact run evidence, and the retained
`release-gap-report` artifact.

Keep GitHub mention notifications enabled to receive actionable-state changes.
GitHub Actions failure notifications now mean the monitor itself could not complete verification.
The README badge is a second visible health indicator.

GitHub can disable scheduled workflows in a public repository after 60 days without repository
activity. If this repository becomes dormant, re-enable the workflow in the Actions tab or change
the schedule in a normal reviewed commit.

Local validation:

```bash
node --test monitoring/release-gap/monitor.test.mjs
node --test monitoring/release-gap/publish-issue.test.mjs
node --check monitoring/release-gap/monitor.mjs
node --check monitoring/release-gap/publish-issue.mjs
node monitoring/release-gap/monitor.mjs --fail-on-gap=false
```

The last command queries live public GitHub state and writes `release-gap-report.json` and
`release-gap-report.md` in the current directory.
