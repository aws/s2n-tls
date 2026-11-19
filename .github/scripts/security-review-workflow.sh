#!/bin/bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# GitHub-side orchestration around the CodeBuild reviewer runner.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
readonly REPO_ROOT
readonly REVIEW_RUNNER="$REPO_ROOT/codebuild/bin/run_security_review.sh"
readonly FINDINGS_ROOT="https://d1nbcgsscvf4yf.cloudfront.net"

RUNNER_RESULT=""
RUNNER_EXIT=0
CURRENT_PR_STATE=""
CURRENT_HEAD_SHA=""

usage() {
    cat <<'EOF'
security-review-workflow.sh run-review <source-version> <pr-number>
security-review-workflow.sh preflight <source-version> <pr-number> <repository>
security-review-workflow.sh reconcile <pr-number> <repository>
security-review-workflow.sh publish-status <result-json> <repository> <pr-number>
security-review-workflow.sh track-closure <source-version> <pr-number>
EOF
}

capture_runner() {
    RUNNER_RESULT=""
    RUNNER_EXIT=0
    RUNNER_RESULT="$("$REVIEW_RUNNER" "$@")" || RUNNER_EXIT=$?
}

run_review() {
    local source_version="$1"
    local pr_number="$2"
    local result=""

    capture_runner "$source_version" "$pr_number"

    # Accept one result object whose exit code and finding count agree with its outcome.
    if result="$(jq -cse --argjson runner_exit "$RUNNER_EXIT" '
        if length == 1 then .[0] else empty end |
        (.findings_count |
          type == "number" and floor == . and . >= 0) as $valid_count |
        select(
          ([.outcome, .resolved_sha, .error] | all(type == "string")) and
          (
            ($runner_exit == 0 and .outcome == "pass" and $valid_count) or
            ($runner_exit == 2 and .outcome == "blocking" and
              $valid_count and .findings_count > 0) or
            ($runner_exit == 1 and .outcome == "error" and
              (.error | length > 0))
          )
        )
      ' <<< "$RUNNER_RESULT")"; then
        printf '%s\n' "$result"
        return
    fi

    echo "Reviewer runner did not return a consistent result." >&2
    return 1
}

track_closure() {
    local source_version="$1"
    local pr_number="$2"
    local error=""

    capture_runner "$source_version" "$pr_number"
    if [[ "$RUNNER_EXIT" -ne 0 ]]; then
        error="$(jq -r '.error // "unknown closure tracking error"' <<< "$RUNNER_RESULT" 2>/dev/null || echo "invalid closure tracking result")"
        echo "Closure tracking failed: $error" >&2
        return 1
    fi
}

load_pull_request() {
    local repository="$1"
    local pr_number="$2"
    local pr_json=""

    if [[ ! "$pr_number" =~ ^[1-9][0-9]*$ ]]; then
        echo "Invalid pull request number." >&2
        return 1
    fi

    pr_json="$(gh api "repos/$repository/pulls/$pr_number")"
    CURRENT_PR_STATE="$(jq -r 'if .merged_at != null then "merged" else .state end' <<< "$pr_json")"
    CURRENT_HEAD_SHA="$(jq -er '.head.sha | select(test("^[0-9a-f]{40}$"))' <<< "$pr_json")"

    case "$CURRENT_PR_STATE" in
        open|closed|merged) ;;
        *) echo "Unexpected pull request state: $CURRENT_PR_STATE" >&2; return 1 ;;
    esac
}

preflight() {
    local source_version="$1"
    local pr_number="$2"
    local repository="$3"
    local source_pr_number=""
    local pinned_sha=""

    load_pull_request "$repository" "$pr_number"
    if [[ "$CURRENT_PR_STATE" != "open" ]]; then
        echo "false"
        return
    fi

    if [[ "$source_version" =~ ^refs/pull/([1-9][0-9]*)/head\^\{([0-9a-f]{40})\}$ ]]; then
        source_pr_number="${BASH_REMATCH[1]}"
        pinned_sha="${BASH_REMATCH[2]}"
    else
        echo "Invalid review source version." >&2
        return 1
    fi

    if [[ "$source_pr_number" != "$pr_number" ]]; then
        echo "Source version and pull request number do not match." >&2
        return 1
    fi

    if [[ "$pinned_sha" != "$CURRENT_HEAD_SHA" ]]; then
        echo "false"
        return
    fi

    echo "true"
}

reconcile() {
    local pr_number="$1"
    local repository="$2"
    local source_version=""

    load_pull_request "$repository" "$pr_number"
    if [[ "$CURRENT_PR_STATE" == "open" ]]; then
        echo "true"
        return
    fi

    source_version="refs/pull/$pr_number/head^{$CURRENT_HEAD_SHA}"
    export PR_STATE="$CURRENT_PR_STATE"
    track_closure "$source_version" "$pr_number"
    echo "false"
}

publish_status() {
    local result_json="$1"
    local repository="$2"
    local pr_number="$3"
    local outcome=""
    local resolved_sha=""
    local github_state=""
    local description=""
    local report_url=""

    outcome="$(jq -er '.outcome | select(. == "pass" or . == "blocking" or . == "error")' <<< "$result_json")"
    if [[ "$outcome" == "error" ]]; then
        echo "Infrastructure failure; no report status will be published."
        return
    fi

    resolved_sha="$(jq -er '.resolved_sha | select(test("^[0-9a-f]{40}$"))' <<< "$result_json")"
    report_url="$FINDINGS_ROOT/s2n-tls/findings.html?pr=$pr_number&commit=$resolved_sha"

    case "$outcome" in
        pass)
            github_state="success"
            description="Security review passed"
            ;;
        blocking)
            github_state="failure"
            description="Security review found blocking findings"
            ;;
    esac

    gh api --method POST \
        --header "X-GitHub-Api-Version: 2022-11-28" \
        "repos/$repository/statuses/$resolved_sha" \
        -f state="$github_state" \
        -f target_url="$report_url" \
        -f description="$description" \
        -f context="security-review / report" > /dev/null
}

command="${1:-}"
case "$command" in
    run-review)
        [[ "$#" -eq 3 ]] || { usage; exit 1; }
        run_review "$2" "$3"
        ;;
    preflight)
        [[ "$#" -eq 4 ]] || { usage; exit 1; }
        preflight "$2" "$3" "$4"
        ;;
    reconcile)
        [[ "$#" -eq 3 ]] || { usage; exit 1; }
        reconcile "$2" "$3"
        ;;
    publish-status)
        [[ "$#" -eq 4 ]] || { usage; exit 1; }
        publish_status "$2" "$3" "$4"
        ;;
    track-closure)
        [[ "$#" -eq 3 ]] || { usage; exit 1; }
        track_closure "$2" "$3"
        ;;
    *)
        usage
        exit 1
        ;;
esac
