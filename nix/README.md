### Nix support

### Quickstart

- `sudo bash -c “mkdir /nix && chmod 755 /nix && chown -R $USERNAME /nix”`
- Run the multi-user command from `https://nixos.org/download.html#nix-install-linux`
- Enable flakes: `mkdir ~/.config/nix; echo "experimental-features = nix-command flakes" > ~/.config/nix.conf`
- `cd s2n-tls`
### Devshell

To enter a development shell with everything needed to build and test, run `nix develop` at the root of the project.

There are some helper scripts in the environment to make building easier, but if you're familiar with Nix, note that these are 
separate from the buildPhase, configurePhase and checkPhase.
### Configure and build

From inside the devShell: `configure; build`.

### Unit tests

From inside the devShell after configuring and building run `unit`.  Individual tests can be run by passing regex snippets to the unit function, e.g. `unit stuffer`

The CI does this in one shot with: `nix develop --max-jobs auto --ignore-environnment --command bash -c "source ./nix/shell.sh; configure;build;unit" `

### Integration tests

From inside a devShell after running configure and build, use `integ` to run all the tests.  Note that some of the tests are still broken under nix, so some failures are expected.

The CI does this in one shot with `nix develop --max-jobs auto --ignore-environnment --command bash -c "source ./nix/shell.sh; configure;build;integ" `

Like with the unit tests, an individual test can be run with a regex: `nix develop --max-jobs auto --ignore-environnment --command bash -c "source ./nix/shell.sh; configure;build;integ happy_path"`


### S3 Binary Cache

Nix can store build artifacts in an external store, to reduce build times, and to allow CI to only do the build task once.
While there are [services to handle this](https://www.cachix.org/), for s2n-tls' CI, we're relying on S3 buckets.

In its simplest form, the `nix copy` command can be used to stash a specific package, but in the case of CI, where we'd like to stash an entire build environment,
 more sophistication is required.

By using inputDerivation, we can create a meta-package that contains all the packages in our devShell.

As an exmample, this copy will stash the s2n-tls devShell:

```
nix copy --to 's3://my-nix-chache-bucket?region=us-west-2' .#devShell
```

To retrieve these:

```
nix copy --from  's3://my-nix-cache-bucket?region=us-west-2' --all --no-check-sigs
```

(--no-check-sigs because this bucket is private and authenticated)

#### Links

- nix copy [documentation](https://nixos.org/manual/nix/stable/command-ref/new-cli/nix3-copy.html)
