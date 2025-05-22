`uv` will automatically configure dependencies. Some run some `script.py` you can use `uv run script.py`.

### Release Script
To run the release script you need to pass in a github token through an environment variable. This is because unauthenticated users are limited to 60 API calls per _hour_.

```
GITHUB_TOKEN=<token> uv run generate_release_notes.py --release-commit <release commit>
```

You can generate personal access tokens here: https://github.com/settings/personal-access-tokens, which should result in something that looks like
```
github_pat_11A098uas3kuA78daawj_hkaj987987QWERTYUIOPkjhkjha8and8A8Andjw
```

Example script run
```
GITHUB_TOKEN=github_pat_11A098uas3kuA78daawj_hkaj987987QWERTYUIOPkjhkjha8and8A8Andjw uv run generate_release_notes.py --release-commit 92f7827c8487eb2a99b443aec6ee7d1df031b1bf
```