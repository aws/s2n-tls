#!/bin/bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Starts one reviewer build, waits for its terminal result, and emits one JSON object.
set -euo pipefail
export AWS_PAGER=""

readonly REGION="us-west-2"
readonly PROJECT="SecurityReview-s2n-tls"
readonly MAX_POLLS=60 # 30 minutes at the production interval

RESULT_RESOLVED_SHA=""
RESULT_FINDINGS_COUNT="null"

usage() {
    cat <<'EOF'
run_security_review.sh 'refs/pull/<pr>/head^{<full-sha>}' <pr>

Requires PR_TITLE, PR_AUTHOR, and PR_STATE=open|closed|merged.
Set SECURITY_REVIEW_POLL_INTERVAL_SECONDS=0 only for local tests.
EOF
}

finish_result() {
    local exit_code="$1"
    local outcome="$2"
    local error_message="$3"

    jq -cn \
        --arg outcome "$outcome" \
        --arg resolved_sha "$RESULT_RESOLVED_SHA" \
        --arg error "$error_message" \
        --argjson findings_count "$RESULT_FINDINGS_COUNT" \
        '{outcome: $outcome, resolved_sha: $resolved_sha, error: $error, findings_count: $findings_count}'
    exit "$exit_code"
}

finish_error() {
    RESULT_FINDINGS_COUNT="null"
    finish_result 1 error "$1"
}

finish_pass() {
    finish_result 0 pass ""
}

finish_blocking() {
    finish_result 2 blocking "blocking findings reported"
}

finish_tracked() {
    finish_result 0 tracked ""
}

run_security_review() {
    local source_version="$1"
    local pr_number="$2"
    local source_pr_number=""
    local pinned_sha=""
    local environment_overrides=""
    local start_response=""
    local poll_response=""
    local build_json=""
    local build_id=""
    local candidate_sha=""
    local build_status=""
    local review_outputs=""
    local review_status=""
    local poll=""
    local poll_interval="${SECURITY_REVIEW_POLL_INTERVAL_SECONDS:-30}"

    if [[ ! "$pr_number" =~ ^[1-9][0-9]*$ ]]; then
        finish_error "invalid PR number"
    fi

    if [[ "$source_version" =~ ^refs/pull/([1-9][0-9]*)/head\^\{([0-9a-f]{40})\}$ ]]; then
        source_pr_number="${BASH_REMATCH[1]}"
        pinned_sha="${BASH_REMATCH[2]}"
        RESULT_RESOLVED_SHA="$pinned_sha"
    else
        finish_error "reviewer source version must be pinned to a full SHA"
    fi

    if [[ "$source_pr_number" != "$pr_number" ]]; then
        finish_error "source version and PR number do not match"
    fi

    if [[ "${PR_TITLE+x}" != "x" || "${PR_AUTHOR+x}" != "x" || "${PR_STATE+x}" != "x" ]]; then
        finish_error "required PR metadata is not set"
    fi

    case "$PR_STATE" in
        open) ;;
        closed|merged) ;;
        *) finish_error "unsupported PR state" ;;
    esac

    if [[ ! "$poll_interval" =~ ^[0-9]+$ || ${#poll_interval} -gt 3 ]]; then
        finish_error "invalid polling interval"
    fi
    poll_interval=$((10#$poll_interval))
    if ((poll_interval > 300)); then
        finish_error "polling interval exceeds limit"
    fi

    environment_overrides="$(jq -cn \
        --arg title "$PR_TITLE" \
        --arg author "$PR_AUTHOR" \
        --arg state "$PR_STATE" \
        '[
            {name: "PR_TITLE", value: $title, type: "PLAINTEXT"},
            {name: "PR_AUTHOR", value: $author, type: "PLAINTEXT"},
            {name: "PR_STATE", value: $state, type: "PLAINTEXT"}
        ]')"

    local -a start_command=(
        aws --region "$REGION" codebuild start-build
        --project-name "$PROJECT"
        --source-version "$source_version"
        --environment-variables-override "$environment_overrides"
        --output json
    )

    if ! start_response="$("${start_command[@]}")"; then
        finish_error "failed to start reviewer build"
    fi

    if ! build_id="$(jq -er '.build.id | strings | select(length > 0)' <<< "$start_response")"; then
        finish_error "reviewer start response did not contain a build ID"
    fi
    echo "Started CodeBuild build $build_id" >&2

    for ((poll = 1; poll <= MAX_POLLS; poll++)); do
        if ! poll_response="$(aws --region "$REGION" codebuild batch-get-builds \
            --ids "$build_id" --output json)"; then
            finish_error "failed to poll reviewer build"
        fi

        if ! build_json="$(jq -ce --arg id "$build_id" '
            .builds
            | select(type == "array" and length == 1)
            | .[0]
            | select(.id == $id)
        ' <<< "$poll_response")"; then
            finish_error "invalid reviewer polling response"
        fi

        candidate_sha="$(jq -r '.resolvedSourceVersion // empty | strings' <<< "$build_json" 2>/dev/null || true)"
        RESULT_RESOLVED_SHA=""

        if [[ -n "$candidate_sha" && ! "$candidate_sha" =~ ^[0-9a-f]{40}$ ]]; then
            finish_error "reviewer response contained an invalid resolved SHA"
        fi
        if [[ -n "$candidate_sha" && "$candidate_sha" != "$pinned_sha" ]]; then
            finish_error "reviewer resolved SHA did not match the pinned SHA"
        fi
        RESULT_RESOLVED_SHA="$candidate_sha"

        if ! build_status="$(jq -er '.buildStatus | strings | select(length > 0)' <<< "$build_json")"; then
            finish_error "reviewer response did not contain a build status"
        fi

        case "$build_status" in
            IN_PROGRESS)
                if ((poll == MAX_POLLS)); then
                    finish_error "reviewer polling timed out"
                fi
                sleep "$poll_interval"
                ;;
            SUCCEEDED)
                if [[ -z "$RESULT_RESOLVED_SHA" ]]; then
                    finish_error "reviewer response did not contain a valid resolved SHA"
                fi
                if [[ "$PR_STATE" != "open" ]]; then
                    finish_tracked
                fi

                if ! review_outputs="$(jq -ce '
                    .exportedEnvironmentVariables
                    | select(type == "array")
                    | (map(select(type == "object" and .name == "REVIEW_STATUS"))) as $statuses
                    | (map(select(type == "object" and .name == "REVIEW_FINDINGS_COUNT"))) as $counts
                    | select(
                        ($statuses | length) == 1 and
                        ($statuses[0].value | type) == "string" and
                        ($counts | length) == 1 and
                        ($counts[0].value | type) == "string" and
                        ($counts[0].value | test("^(0|[1-9][0-9]*)$"))
                      )
                    | {
                        status: $statuses[0].value,
                        findings_count: ($counts[0].value | tonumber)
                      }
                ' <<< "$build_json")"; then
                    finish_error "missing or invalid review outputs"
                fi

                review_status="$(jq -r '.status' <<< "$review_outputs")"
                RESULT_FINDINGS_COUNT="$(jq -r '.findings_count' <<< "$review_outputs")"
                case "$review_status" in
                    PASS) finish_pass ;;
                    BLOCKING)
                        if ((RESULT_FINDINGS_COUNT == 0)); then
                            finish_error "blocking verdict reported without findings"
                        fi
                        finish_blocking
                        ;;
                    *) finish_error "unknown review verdict" ;;
                esac
                ;;
            FAILED|FAULT|STOPPED|TIMED_OUT)
                finish_error "reviewer build did not succeed: $build_status"
                ;;
            *)
                finish_error "unknown reviewer build status: $build_status"
                ;;
        esac
    done

    finish_error "reviewer polling ended without a terminal result"
}

if [[ "$#" -ne 2 ]]; then
    usage
    exit 1
fi
run_security_review "$1" "$2"
