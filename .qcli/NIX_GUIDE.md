# s2n-tls Nix Guide

This guide provides information on using the Nix package manager with the s2n-tls project, based on the project's flake.nix and nix/* files.

## Introduction to Nix in s2n-tls

s2n-tls uses Nix to create reproducible development environments that closely match the CI environment. This approach allows developers to work with consistent toolchains across different platforms and distributions.

## Setup

### Prerequisites

1. Create a directory for the Nix store:
   ```bash
   sudo bash -c "mkdir /nix && chmod 755 /nix && chown -R $USER /nix"
   ```

2. Install Nix using the single-user installation:
   ```bash
   sh <(curl -L https://nixos.org/nix/install) --no-daemon
   ```

3. Enable flakes (required for s2n-tls):
   ```bash
   mkdir -p ~/.config/nix
   echo "experimental-features = nix-command flakes" > ~/.config/nix/nix.conf
   ```

## Using Nix with s2n-tls

### Development Shells

s2n-tls provides several development shells with different libcrypto implementations:

- **Default (OpenSSL 3.0)**: `nix develop`
- **AWS-LC**: `nix develop .#awslc`
- **AWS-LC FIPS 2022**: `nix develop .#awslcfips2022`
- **AWS-LC FIPS 2024**: `nix develop .#awslcfips2024`
- **OpenSSL 1.1.1**: `nix develop .#openssl111`
- **OpenSSL 1.0.2**: `nix develop .#openssl102`
- **LibreSSL**: `nix develop .#libressl`

Each shell sets up the appropriate environment variables and dependencies for building and testing s2n-tls with the specified libcrypto.

### Common Development Workflow

Once inside a development shell, you can use the following helper bash functions:

1. **Configure the build**:
   ```bash
   configure
   ```

2. **Build s2n-tls**:
   ```bash
   build
   ```

3. **Run unit tests**:
   ```bash
   unit [test_name]
   ```

4. **Run integration tests**:
   ```bash
   integ [test_name]
   ```

### One-line Commands

For CI or quick testing, you can combine commands:

```bash
nix develop --max-jobs auto --ignore-environment --command bash -c "source ./nix/shell.sh; configure; build; unit"
```

## Creating Custom Nix Derivations

### Package Structure

s2n-tls uses a standard structure for its Nix packages:

```nix
{ pkgs }:
pkgs.stdenv.mkDerivation rec {
  pname = "package-name";
  version = "1.0.0";

  src = pkgs.fetchzip {
    url = "https://example.com/package-source.zip";
    sha256 = "sha256-hash";
  };

  buildInputs = [ /* dependencies */ ];

  configurePhase = ''
    # Configuration commands
  '';

  buildPhase = ''
    # Build commands
  '';

  installPhase = ''
    # Install commands
  '';
}
```

### Example: Adding a New libcrypto Version

To add a new libcrypto that we want to build from source:

1. Create a new file in the `nix/` directory (e.g., `nix/new_libcrypto.nix`)
2. Define the derivation following the pattern of existing libcrypto implementations
3. Add a new devShell in `flake.nix` that uses your new libcrypto as the primary

Example:

```nix
# nix/new_libcrypto.nix
{ pkgs }:
pkgs.stdenv.mkDerivation rec {
  pname = "new-libcrypto";
  version = "1.0.0";

  src = pkgs.fetchzip {
    url = "https://example.com/new-libcrypto-1.0.0.zip";
    sha256 = "sha256-hash";
  };

  buildInputs = [ pkgs.gnumake pkgs.perl534 pkgs.coreutils ];

  configurePhase = ''
    ./configure --prefix=$out
  '';

  buildPhase = ''
    make -j $(nproc)
  '';

  installPhase = ''
    make install
  '';
}
```

Then in `nix/devshells.nix`, add:

```nix
devShells.newlibcrypto = devShells.default.overrideAttrs
  (finalAttrs: previousAttrs: {
    buildInputs = [ pkgs.cmake new_libcrypto ];
    S2N_LIBCRYPTO = "new-libcrypto";
    shellHook = ''
      echo Setting up $S2N_LIBCRYPTO environment from flake.nix...
      export PATH=${openssl_1_1_1}/bin:$PATH
      export PS1="[nix $S2N_LIBCRYPTO] $PS1"
      source ${writeScript ./nix/shell.sh}
    '';
  });
```

## Best Practices for Nix in s2n-tls

### 1. Use Pinned Dependencies

When building from source with upstream source archives, Always pin dependencies with specific versions and SHA256 hashes to ensure reproducibility:

```nix
src = pkgs.fetchzip {
  url = "https://github.com/example/repo/archive/refs/tags/v1.0.0.zip";
  sha256 = "sha256-hash";
};
```

### 2. Override Attributes Carefully

When overriding attributes in a derivation, make sure to preserve necessary attributes from the original:

```nix
packages.custom-s2n-tls = packages.s2n-tls.overrideAttrs
  (finalAttrs: previousAttrs: {
    doCheck = true;
    buildInputs = previousAttrs.buildInputs ++ [ pkgs.additional-dependency ];
  });
```

### 3. Document Environment Variables

When creating new development shells, document any environment variables that are set:

```nix
# Sets:
# - S2N_LIBCRYPTO: The libcrypto implementation being used
# - OPENSSL_1_1_1_INSTALL_DIR: Path to OpenSSL 1.1.1 installation
```

## Binary Cache

s2n-tls uses a private S3 bucket for binary caching in CI to speed up builds.

## Common Issues and Solutions

### Missing Dependencies

If you encounter errors about missing dependencies, ensure you're using the correct development shell for your needs:

```bash
nix develop .#awslc  # For AWS-LC dependencies
```

## Additional Resources

- [Nix Manual](https://nixos.org/manual/nix/stable/)
- [Nix Flakes](https://nixos.wiki/wiki/Flakes)
- [Nixpkgs Manual](https://nixos.org/manual/nixpkgs/stable/)
