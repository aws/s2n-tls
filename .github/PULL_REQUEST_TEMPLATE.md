### Release Summary:
<!-- If this is a feature or bug that impacts customers and is significant enough to include in the "Summary" section of the next version release, please include a brief (1-2 sentences) description of the change. The audience of this summary is future customers, not maintainers or reviewers. See https://github.com/aws/s2n-tls/releases/tag/v1.5.7 for an example. Otherwise, leave this section blank -->

### Resolved issues:

resolves #ISSUE-NUMBER1, resolves #ISSUE-NUMBER2, etc.

### Description of changes: 

Describe s2n’s current behavior and how your code changes that behavior. If there are no issues this PR is resolving, explain why this change is necessary.

### Call-outs:

Address any potentially confusing code. Is there code added that needs to be cleaned up later? Is there code that is missing because it’s still in development? If a callout is specific to a section of code, it might make more sense to leave a comment on your own PR file diff.

### Testing:

How is this change tested (unit tests, fuzz tests, etc.)? What manual testing was performed? Are there any testing steps to be verified by the reviewer?
How can you convince your reviewers that this PR is safe and effective?
Is this a refactor change? If so, how have you proved that the intended behavior hasn't changed?

Remember:
* Any change to the library source code should at least include unit tests.
* Any change to the core stuffer or blob methods should include [CBMC proofs](https://github.com/aws/s2n-tls/tree/main/tests/cbmc).
* Any change to the CI or tests should:
   1. prove that the test succeeds for good input
   2. prove that the test fails for bad input (eg, a test for memory leaks fails when a memory leak is committed)


By submitting this pull request, I confirm that my contribution is made under the terms of the Apache 2.0 license.
