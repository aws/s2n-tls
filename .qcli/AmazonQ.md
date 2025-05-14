# s2n-tls Contribution Guidelines

This document provides guidance for contributing to the s2n-tls project, with a focus on creating effective pull requests and following the project's coding standards.

## Pull Request Guidelines

### Creating a Pull Request

1. **Fork the Repository**: Create a fork of the s2n-tls repository and prepare your changes locally.

2. **Ensure Tests Pass**: Make sure all tests are passing before submitting your PR.

3. **Follow the PR Template**: When creating a PR, follow the template structure:
   - **Release Summary**: Include a brief description (1-2 sentences) if the change impacts customers significantly
   - **Resolved Issues**: Link to any issues your PR resolves
   - **Description of Changes**: Explain current behavior and how your code changes it
   - **Call-outs**: Address any potentially confusing code or implementation details
   - **Testing**: Describe how your change is tested (unit tests, fuzz tests, etc.)

4. **Testing Requirements**:
   - Any change to library source code should include unit tests
   - Changes to core stuffer or blob methods should include CBMC proofs
   - CI or test changes should prove success for good input and failure for bad input

5. **Code Review Process**: All changes undergo code review, by at least 2 reviewers on the team.
   - All submissions are made under the terms of the Apache Software License 2.0

### PR Best Practices

- For significant contributions, create an issue first to discuss the change, and outline the smaller PR tasks.
- Keep PRs focused on a single task or feature
- Respond promptly to review feedback
- Rebasing your branch before submitting is not required; we use GitHub merge queues, which does the rebasing as part of the workflow.

## Code Style Guidelines

s2n-tls follows specific coding conventions to maintain readability and consistency:

### Formatting

- The project uses clang-format for code formatting
- Run `./codebuild/bin/clang_format_changed_files.sh` to format changed files
- CI checks will fail if code is not properly formatted

### General Style Rules

- **Language**: s2n-tls is written in C99
- **Indentation**: 4 spaces, no tabs
- **Line Width**: 120 characters is acceptable
- **Braces**: Always include curly braces for control structures (even for single-line blocks)
- **Function Design**:
  - Functions should be small (no more than a page or two)
  - Functions should have clear input and output
  - Follow the "pure function" approach where possible

### Naming and Organization

- Use explicitly sized primitives where possible (e.g., uint8_t, uint32_t)
- Use unsigned ints for sizes (following TLS/SSL conventions)
- Structures exposed to application authors must be opaque
- Declare variables closest to their first point of use
- Avoid duplication of logic

### Error Handling

- Always check return values
- Use the GUARD macro for error handling to maintain linear control flow
- Use BAIL macro to surface errors to applications
- Minimize the use of else clauses; favor linear control flow

### Comments

- Use C-style comments (`/* */`) and avoid C++ comments (`//`)
- Comments should explain *why* code exists, not *what* it does
- Variable and function names should be self-explanatory
- Include references to RFCs or context when necessary
- Every source file must include the Apache Software License 2.0 and copyright notice

## Memory Handling

- Use s2n_blob structures to track memory regions
- Use s2n_stuffer structures for buffer manipulation
- Avoid C string functions and standard buffer manipulation patterns
- Follow the stuffer lifecycle guidelines when using raw pointers

## Security Considerations

- Report security-critical bugs via http://aws.amazon.com/security/vulnerability-reporting/
- Do NOT create public issues for security vulnerabilities
- s2n-tls undergoes periodic security analyses, including code audits and penetration tests

## Development Workflow

1. Read all documentation in the "docs/" directory
2. For significant contributions, discuss the change by creating an issue first
3. Create a git fork and prepare changes locally
4. Ensure all tests pass
5. Create a pull request to the main repository
6. Address feedback from code review
7. Once approved, your changes will be merged

Remember that s2n-tls prioritizes security, readability, ease of use, and performance, in that order.
