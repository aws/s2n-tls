### Nix support

From the [wiki](https://nixos.wiki/wiki/Nix_package_manager), Nix is a package manager and build system that parses reproducible build instructions specified in the Nix Expression Language.

In the context of s2n-tls, we're using it to ease the setup of development environments that
 closely match our CI. While this could be done with custom Docker containers, there are still missing toolchain issues to sort our per distribution and platform. Nix
 does not replace or negate Docker, cmake and compilers, but should allow for frictionless installs of a wider number of versions of build and test dependencies.

### Quickstart

- `sudo bash -c “mkdir /nix && chmod 755 /nix && chown -R $USERNAME /nix”`
- Run the single-user command from `https://nixos.org/download.html#nix-install-linux`
- Enable flakes: `mkdir ~/.config/nix; echo "experimental-features = nix-command flakes" > ~/.config/nix/nix.conf`
- `cd s2n-tls`

#### What is this doing?

1. Creates a /nix store directory where artifacts (_derivations_) will be stored.  It's not advised to change this, even for small roots - if you have disk space constraints, consider using a [bindmount](https://docs.rackspace.com/support/how-to/bind-mounts-in-linux/)
2. Installs nix
3. Enables the experimental _flakes_ feature.  A flake is simply a source tree (such as a Git repository) containing a file named flake.nix that provides a standardized interface to Nix artifacts such as packages or NixOS modules. See the [blog post](https://www.tweag.io/blog/2020-05-25-flakes/) for more.
4. cd into the s2n-tls project root, where flake.nix lives.

### Devshell

A devShell is an environment with all of the build dependencies installed (on PATH) and ready for use. It is intended to easily get a usable development environment setup.

To enter the development shell, run `nix develop` at the root of the project.

There are some helper scripts in the environment to make building easier, but if you're familiar with Nix, note that these are 
separate from the buildPhase, configurePhase and checkPhase.
### Configure and build

From inside the devShell: `configure; build`.

The first time this is run, it might take a while to build everything.

### Unit tests

From inside the devShell after configuring and build finish, run `unit <test name>`, or with no test name for all of the tests.
For example, to run the stuffer_test use: `unit stuffer_test`, or `unit stuffer` to run all of tests with stuffer in the name.

The CI does this in one shot with: `nix develop --max-jobs auto --ignore-environment --command bash -c "source ./nix/shell.sh; configure;build;unit" `.

What is this doing?

1. max-jobs tells nix to use all the cores available to build
2. ignore-environment strips out environment variables to get a clean environment
3. source the shell functions needed to configure, build and run tests
### Integration tests

From inside a devShell after running configure and build, use `integ <test name>` to run the integ tests matching the regex `<test name>`, or with no arguments to run all the integ tests.  Note that some of the tests are still broken under nix, so some failures are expected.
For example: `integ happy_path`.

The CI does this in one shot with `nix develop --max-jobs auto --ignore-environnment --command bash -c "source ./nix/shell.sh; configure;build;integ" `

Like with the unit tests, an individual test, like [happy_path](https://github.com/aws/s2n-tls/blob/main/tests/integrationv2/test_happy_path.py) in this example, can be run with: `nix develop --max-jobs auto --ignore-environnment --command bash -c "source ./nix/shell.sh; configure;build;integ happy_path"`


### S3 Binary Cache

Nix can store build artifacts in an external store, to reduce build times, and to allow CI to only do the build task once.
While there are [services to handle this](https://www.cachix.org/), for s2n-tls' CI, we're relying on S3 buckets.

In its simplest form, the `nix copy` command can be used to stash a specific package, but in the case of CI, where we'd like to stash an entire build environment,
 more sophistication is required.

By using inputDerivation, we can create a meta-package that contains all the packages in our devShell.

As an example, this copy will stash the s2n-tls devShell:

```
nix copy --to 's3://my-nix-cache-bucket?region=us-west-2' .#devShell
```

To retrieve these:

```
nix copy --from  's3://my-nix-cache-bucket?region=us-west-2' --all --no-check-sigs
```

(--no-check-sigs because this bucket is private and authenticated)

#### Links

- nix copy [documentation](https://nixos.org/manual/nix/stable/command-ref/new-cli/nix3-copy.html)
