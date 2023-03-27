### Nix support

### Devshell

To enter a development shell with everything needed to build and test, run `nix develop` at the root of the project.

There are some helper scripts in the environment to make building easier, but if you're familiar with Nix, note that these are 
separate from the buildPhase, configurePhase and checkPhase.

### Unit tests

- Oneshot: `nix develop --max-jobs auto --ignore-environnment --command bash -c "source ./nix/shell.sh; configure;build;unit" `

### Integration tests

- Oneshot: `nix develop --max-jobs auto --ignore-environnment --command bash -c "source ./nix/shell.sh; configure;build;integ" `
- Specific test: `nix develop --max-jobs auto --ignore-environnment --command bash -c "source ./nix/shell.sh; configure;build;integ happy_path"`

- interactively: 

```
nix develop
configure
build
integ
```

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
