# s2n-tls Pull Request Checklist

Use this checklist to ensure your pull request meets the s2n-tls project standards.

## Before Creating a PR

- [ ] Read the [DEVELOPMENT-GUIDE.md](docs/DEVELOPMENT-GUIDE.md) to understand s2n-tls development principles
- [ ] For significant changes, create an issue first to discuss the proposed changes
- [ ] Ensure your code follows the [code style guidelines](#code-style-verification)
- [ ] Run all tests locally to verify your changes work as expected
- [ ] Add appropriate tests for your changes

## PR Content

- [ ] Follow the PR template structure
- [ ] Keep the PR focused on a single task or feature
- [ ] Include a clear description of what your code changes
- [ ] Link to any issues this PR resolves
- [ ] Call out any potentially confusing code or implementation details
- [ ] Describe how your change is tested

## Code Style Verification

Before submitting your PR, ensure your code is properly formatted.

Since we're using C, Rust, Python, Nix and Bash, you'll need to find the approriate linter to validate  the formatting

```bash
# Format all changed files
./codebuild/bin/clang_format_changed_files.sh
```

## Testing Requirements

- [ ] Any change to library source code includes unit tests
- [ ] Changes to core stuffer or blob methods include CBMC proofs
- [ ] CI or test changes prove success for good input and failure for bad input

## Security Considerations

- [ ] No security-sensitive information is included in the PR
- [ ] Memory is handled safely using s2n_blob and s2n_stuffer structures
- [ ] Error handling follows s2n-tls conventions (GUARD, BAIL macros)
- [ ] Return values are always checked

## Final Checks

- [ ] Rebasing your branch isn't required, since we're using GitHub Merge Queues, which will rebase automatically as part of the workflow.
- [ ] Verify all CI checks pass
- [ ] Be responsive to code review feedback

Remember that all submissions are made under the terms of the Apache Software License 2.0.
