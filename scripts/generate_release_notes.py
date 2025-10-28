#!/usr/bin/env -S uv run --script
import os
import subprocess
from datetime import datetime,timedelta
import click
from github import Github, Auth


def get_release_summaries(pr) -> str | None:
    """Extract release summaries from PRs that have them."""
    body = pr.body or ""
    if "### Release Summary:" in body:
        # get everything between "### Release Summary:" and the next heading
        summary = body.split("### Release Summary:")[1].split("###")[0].strip()
        # make sure it's not the default HTML comment
        if summary and "<!--" not in summary:
            return summary
    else:
        return None


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
    assert "main" in current_branch, "You must be on the main branch todo a release."

    log_output = subprocess.check_output(
        ["git", "log", f"{previous_commit}..{new_commit}", "--pretty=format:%s"],
        text=True,
    )
    return [commit for commit in log_output.splitlines()]


def get_pr_from_commit_description(description: str) -> int:
    """Given 'chore: Bump nixpkgs version to 24.11 (#5294)' return '5294'"""
    assert "(#" in description, "PR number not found in commit message."

    number_start = description.find("(#") + len("#(")
    number_end = description.find(")", number_start)
    number = description[number_start:number_end]

    return int(number)


@click.command()
@click.option('--release-commit', required=True, help="The git SHA on the main branch you'd like to generate relase notes for.")
@click.option('--repo-name',default="aws/s2n-tls", help="Defaults to aws/s2n-tls")
@click.option('--output', default="release_notes.md", help="Release notes output file")
def main(release_commit:str, repo_name:str, output:str):
    """ Main """
    token = os.getenv("GITHUB_TOKEN")
    if not token:
        print("Please set the GITHUB_TOKEN environment variable")
        return

    auth = Auth.Token(token)
    g = Github(auth=auth)
    repo = g.get_repo(repo_name)
    last_release_commit = get_last_release_commit(repo)

    print(
        f"Generating release notes from ({last_release_commit}, {release_commit}]"
    )
    commits = get_commits_in_release(last_release_commit, release_commit)
    prs = [get_pr_from_commit_description(description) for description in commits]

    monday_of_current_week = (datetime.now() - timedelta(days=datetime.now().weekday())).replace(hour=0, minute=0, second=0, microsecond=0)
    changelog = []
    release_summaries = []

    for pr_number in prs:
        pr = repo.get_pull(pr_number)
        changelog.append(format_pr_entry(pr))
        maybe_release_note = get_release_summaries(pr)
        if maybe_release_note is not None:
            release_summaries.append(maybe_release_note)

    # generate markdown release notes
    with open(output, 'w', encoding="utf-8") as fh:
        fh.write(f"\n\nWeekly release for {monday_of_current_week.strftime('%b %d, %Y')}\n")
        fh.write("\n## Release Summary:\n")
        for summary in release_summaries:
            fh.write(f"- {summary}\n")
        fh.write("\n\n## What's Changed:\n")
        for change in changelog:
            fh.write(f"- {change}\n")
        fh.write(f"\n\n**Full Changelog**: https://github.com/{repo_name}/compare/{last_release_commit}..{release_commit}\n\n")
    print(f"\nSuccessfully wrote release notes to {output}.\nYou could use the gh cli to do a release with:")
    print("\n\tgh release create v91.92.93 -F release_notes.md\n")


if __name__ == "__main__":
    main()
