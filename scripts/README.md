`uv` will automatically configure dependencies. To run `script.py` use `uv run script.py`.

### Release Script
To run the release note script you need to pass in a github token through an environment variable. This is because unauthenticated users are limited to 60 API calls per _hour_.

```
GITHUB_TOKEN=<token> uv run generate_release_notes.py --release-commit <release commit>
```
if you use the [GitHub CLI](https://cli.github.com/) utility, you could use: `GITHUB_TOKEN=$(gh auth token)`.

You can generate personal access tokens here: https://github.com/settings/personal-access-tokens, which should result in something that looks like
```
gho_11A098uas3kuArAnDomLoOkInGHasH
```