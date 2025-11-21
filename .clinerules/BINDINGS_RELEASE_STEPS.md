# s2n-tls Rust Bindings Release Guide

## Version Bump Process for Bindings Releases

This guide provides context for bumping the version of the s2n-tls Rust bindings.

### Prerequisites

- Ensure you're in the `bindings/rust/extended` directory
- A new release MUST be committed and tagged as a release on github.com.
- An s2n-tls release version MUST be provided, in the format "v<MAJOR>.<MINOR>.<PATCH>".
- The user SHOULD tell you if this release needs a MAJOR or MINOR version bump, otherwise it's expected that this is just a PATCH release, but always double check.
- Sub-package version numbers MAY not match the overall release version, but SHOULD match the versioning bump with the release, e.g. if the overall project has bumped the MINOR version, the sub-packages should also increment their MINOR version (ahd implicitly, PATCH version resets to 0).

### Step-by-Step Instructions

#### Checkout the s2n-tls release version provided

`git checkout v<MAJOR>.<MINOR>.<PATCH>`

#### Update s2n-tls-sys Template

**File**: `bindings/rust/extended/s2n-tls-sys/templates/Cargo.template`

**Change**:
```toml
version = "0.3.29"

# To:
version = "0.3.30"
```

**Why**: This template is used by `generate.sh` to create the actual `s2n-tls-sys/Cargo.toml` file.

---

#### Step 2: Run generate.sh

**Command**:
```bash
cd bindings/rust/extended
./generate.sh --skip-tests
```

**What this does**:
- Copies the latest C sources from the main s2n-tls codebase into `s2n-tls-sys/lib/`
- Generates Rust FFI bindings from the C headers
- Creates `s2n-tls-sys/Cargo.toml` from the template (with the new version)
- The `--skip-tests` flag skips running the test suite to speed things up

**Expected output**: The script should complete successfully and regenerate `s2n-tls-sys/Cargo.toml`.

---

#### Step 3: Update s2n-tls Crate

**File**: `bindings/rust/extended/s2n-tls/Cargo.toml`

**Changes** (2 locations):

1. **Package version**
```toml
# Change from:
version = "0.3.29"

# To:
version = "0.3.30"
```

2. **Dependency version**
```toml
# Change from:
s2n-tls-sys = { version = "=0.3.29", path = "../s2n-tls-sys", features = ["internal"] }

# To:
s2n-tls-sys = { version = "=0.3.30", path = "../s2n-tls-sys", features = ["internal"] }
```

**Important**: Note the `=` prefix which means "exact version". Both the package version and the dependency version must match exactly.

---

#### Step 4: Update s2n-tls-tokio Crate

**File**: `bindings/rust/extended/s2n-tls-tokio/Cargo.toml`

**Changes**

1. **Package version**
```toml
# Change from:
version = "0.3.29"

# To:
version = "0.3.30"
```

2. **Dependency version**
```toml
# Change from:
s2n-tls = { version = "=0.3.29", path = "../s2n-tls" }

# To:
s2n-tls = { version = "=0.3.30", path = "../s2n-tls" }
```

---

#### Update other dependencies

These paths might also contain Cargo.toml files with dependencies on specific versions of the bindings; inspect them and increment as needed:

- tests/regression/Cargo.toml
- tests/pcap/Cargo.toml
- bindings/rust/standard/s2n-tls-hyper
- bindings/rust/aws-kms-tls-auth
  - **Special Note**: This crate is tested in CI and should be updated to N-1 version (e.g., if releasing 0.3.30, update aws-kms-tls-auth to 0.3.29) to ensure CI tests pass against the previous published version.


### Verification Checklist

After making all changes, verify:

1. `cargo build` in s2n-tls should succeed.
2. Run tests: `cargo test` and `cargo test --all-features`
3. Verify the changes with `git diff`
4. Commit the changes with a conventional commit message in the format: "chore: Rust bindings release <MAJOR>.<MINOR>.<PATCH>" NOTE: this version is of the bindings, not the main release version number.

---

## Notes

- All three crates must be released together due to exact version dependencies
- The `generate.sh` script must be run after updating the template to regenerate the actual Cargo.toml
- The `--skip-tests` flag is used to speed up the generation process; tests should be run separately before publishing, but will also be run in CI as part of the pull request process.
