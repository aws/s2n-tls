#!/bin/bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Maintains one bot-owned PR comment with commit-specific review history.
set -euo pipefail

readonly FINDINGS_ROOT="https://d1nbcgsscvf4yf.cloudfront.net"
readonly COMMENT_MARKER="<!-- security-review-history -->"
readonly COMMENT_FOOTER=$'\n\n_Report access is restricted to maintainers._'

result_json="${1:?result JSON is required}"
repository="${2:?repository is required}"
pr_number="${3:?pull request number is required}"
server_url="${4:?server URL is required}"

review_result="$(jq -cer '
    select(
      (.outcome == "pass" and
        (.findings_count | type == "number" and floor == . and . >= 0)) or
      (.outcome == "blocking" and
        (.findings_count | type == "number" and floor == . and . > 0))
    )
    | {outcome, findings_count}
  ' <<< "$result_json" 2>/dev/null || true)"
if [[ -z "$review_result" ]]; then
    echo "No completed security review verdict to add to the report history."
    exit 0
fi

outcome="$(jq -r '.outcome' <<< "$review_result")"
findings_count="$(jq -r '.findings_count' <<< "$review_result")"
resolved_sha="$(jq -er '.resolved_sha | select(test("^[0-9a-f]{40}$"))' <<< "$result_json")"
report_url="$FINDINGS_ROOT/s2n-tls/findings.html?pr=$pr_number&commit=$resolved_sha"

short_sha="${resolved_sha:0:12}"
commit_url="$server_url/$repository/commit/$resolved_sha"
case "$outcome" in
    pass)
        if ((findings_count > 0)); then
            result_label="⚠️ Findings to review"
        else
            result_label="✅ No findings"
        fi
        ;;
    blocking) result_label="❌ Blocking findings" ;;
esac

# Ignore marker text in contributor comments; only Actions owns this comment.
comments_json="$(gh api --paginate "repos/$repository/issues/$pr_number/comments?per_page=100")"
comment_json="$(jq -cs --arg marker "$COMMENT_MARKER" '
    ([.[][]
      | select(.user.login == "github-actions[bot]")
      | select((.body // "") | startswith($marker))]
    | first) // empty
  ' <<< "$comments_json")"

if [[ -z "$comment_json" ]]; then
    # A clean PR stays quiet until its first finding-producing review.
    if ((findings_count == 0)); then
        echo "No review history exists; not creating a comment for a review without findings."
        exit 0
    fi

    body="$(cat <<EOF
$COMMENT_MARKER

## 🔒 Security review

| Commit | Result | Report |
|---|---|---|
| [\`$short_sha\`]($commit_url) | $result_label | [View report]($report_url) |

_Report access is restricted to maintainers._
EOF
)"
    gh api --method POST "repos/$repository/issues/$pr_number/comments" -f body="$body" > /dev/null
    echo "Created security review report history."
    exit 0
fi

comment_id="$(jq -er '.id' <<< "$comment_json")"
body="$(jq -er '.body' <<< "$comment_json")"
row="| [\`$short_sha\`]($commit_url) | $result_label | [View report]($report_url) |"
updated_body=""
separator=""
row_found=false

# Replace an existing SHA row, or append a new one before the footer.
while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ "$line" == *"($report_url)"* ]]; then
        line="$row"
        row_found=true
    fi

    updated_body+="$separator$line"
    separator=$'\n'
done <<< "$body"

if [[ "$updated_body" != *"$COMMENT_FOOTER" ]]; then
    echo "The existing security review history has an unexpected format." >&2
    exit 1
fi

if [[ "$row_found" != "true" ]]; then
    body_without_footer="${updated_body%"$COMMENT_FOOTER"}"
    updated_body="$body_without_footer"$'\n'"$row$COMMENT_FOOTER"
fi
gh api --method PATCH "repos/$repository/issues/comments/$comment_id" -f body="$updated_body" > /dev/null
echo "Updated security review report history."
