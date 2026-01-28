#!/usr/bin/env bash
set -euo pipefail

# Configurable via env (easy to adjust in CI)
FORK_REPO="${FORK_REPO:-kaukabrizvi/boring}"          # owner/repo
FORK_BRANCH="${FORK_BRANCH:-symbol-prefixing}"        # branch to check
THRESHOLD_DAYS="${THRESHOLD_DAYS:-180}"               # ~6 months

# Requires: curl, jq
if ! command -v jq >/dev/null 2>&1; then
  echo "ERROR: jq is required for the BoringSSL fork freshness check."
  exit 2
fi

commit_api="https://api.github.com/repos/${FORK_REPO}/commits/${FORK_BRANCH}"
json="$(curl -fsSL "${commit_api}")"

last_commit_date="$(echo "${json}" | jq -r '.commit.committer.date')"
last_commit_sha="$(echo "${json}" | jq -r '.sha')"

if [[ -z "${last_commit_date}" || "${last_commit_date}" == "null" ]]; then
  echo "ERROR: Could not determine last commit date for ${FORK_REPO}@${FORK_BRANCH} from GitHub API."
  exit 2
fi

now_epoch="$(date -u +%s)"
commit_epoch="$(date -u -d "${last_commit_date}" +%s)"
age_days="$(( (now_epoch - commit_epoch) / 86400 ))"

if (( age_days > THRESHOLD_DAYS )); then
  cat <<EOF
ERROR: BoringSSL fork branch appears stale.

  Fork:            ${FORK_REPO}
  Branch:          ${FORK_BRANCH}
  Last commit:     ${last_commit_sha}
  Last commit date:${last_commit_date}  (~${age_days} days ago)
  Threshold:       ${THRESHOLD_DAYS} days

Why this is failing:
  s2n-tls currently depends on a forked BoringSSL branch (for symbol prefixing) to avoid
  OpenSSL symbol collisions in integration tests. A stale fork is a maintenance risk.

How to refresh the fork (typical workflow):
  1) Sync fork branch with upstream BoringSSL:
       git clone git@github.com:${FORK_REPO}.git
       cd boring
       git remote add upstream https://github.com/google/boringssl.git
       git fetch upstream
       git checkout ${FORK_BRANCH}
       git merge --ff-only upstream/master   # adjust if upstream uses main
       git push origin ${FORK_BRANCH}

  2) Update s2n-tls to point at the refreshed fork commit (wherever this is pinned),
     then open a PR.

If the fork is intentionally frozen, raise THRESHOLD_DAYS or disable this check with a comment
explaining why.
EOF
  exit 1
fi

echo "OK: ${FORK_REPO}@${FORK_BRANCH} last commit ${last_commit_sha} at ${last_commit_date} (~${age_days} days ago) within threshold ${THRESHOLD_DAYS}."
