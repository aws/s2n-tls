import argparse
import subprocess
from github import Github
import os

REPO_NAME = "aws/s2n-tls"


def get_release_summaries(pr) -> None | str:
    """Extract release summaries from PRs that have them."""
    body = pr.body or ""
    if "### Release Summary:" in body:
        # get everything between "### Release Summary:" and the next heading
        summary = body.split("### Release Summary:")[1].split("###")[0].strip()
        # make sure it's not the default HTML comment
        if summary and "<!--" not in summary:
            return summary


def format_pr_entry(pr) -> str:
    """Format a PR into the desired changelog entry format."""
    return f"{pr.title} by @{pr.user.login} in {pr.html_url}"


def get_last_release_commit(repo):
    """Get the commit SHA of the last release."""
    latest_release = repo.get_latest_release()
    tag = repo.get_git_ref(f"tags/{latest_release.tag_name}")
    return tag.object.sha


def get_commits_in_release(previous_commit: str, new_commit: str) -> list[str]:
    """Get all of the commits between the previous release commit and the new release commit"""
    # make sure we are currently on the main branch
    current_branch = subprocess.check_output(
        ["git", "branch", "--show-current"], text=True
    )
    assert "main" in current_branch

    log_output = subprocess.check_output(
        ["git", "log", f"{previous_commit}..{new_commit}", "--pretty=format:%s"],
        text=True,
    )
    return [commit for commit in log_output.splitlines()]


def get_pr_from_commit_description(description: str) -> int:
    """Given 'chore: Bump nixpkgs version to 24.11 (#5294)' return '5294'"""
    assert "(#" in description

    number_start = description.find("(#") + len("#(")
    number_end = description.find(")", number_start)
    number = description[number_start:number_end]

    return int(number)


def main():
    parser = argparse.ArgumentParser(prog="s2n-tls release note generator")
    parser.add_argument("--release-commit", required=True)
    args = parser.parse_args()

    token = os.getenv("GITHUB_TOKEN")
    if not token:
        print("Please set the GITHUB_TOKEN environment variable")
        return

    g = Github(token)
    repo = g.get_repo(REPO_NAME)
    last_release_commit = get_last_release_commit(repo)

    print(
        f"generating release notes from ({last_release_commit}, {args.release_commit}]"
    )
    commits = get_commits_in_release(last_release_commit, args.release_commit)
    prs = [get_pr_from_commit_description(description) for description in commits]

    changelog = []
    release_summaries = []

    for pr_number in prs:
        pr = repo.get_pull(pr_number)
        changelog.append(format_pr_entry(pr))
        maybe_release_note = get_release_summaries(pr)
        if maybe_release_note is not None:
            release_summaries.append(maybe_release_note)

    # generate markdown release notes
    print("\n\n")
    print("## Release Summary:")
    for summary in release_summaries:
        print(f"* {summary}")
    print("")

    print("## What's Changed:")
    for change in changelog:
        print(f"* {change}")
    print("")


if __name__ == "__main__":
    main()
