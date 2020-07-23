---
name: S2N Issue
about: Template
title: ''
labels: ''
assignees: ''

---

### Security issue notifications

If you discover a potential security issue in s2n we ask that you notify
AWS Security via our [vulnerability reporting page](http://aws.amazon.com/security/vulnerability-reporting/). Please do **not** create a public github issue.

### Problem:

A short description of what the problem is and why we need to fix it. Add reproduction steps if necessary.

### Solution:

A description of the possible solution in terms of S2N architecture. Highlight and explain any potentially controversial design decisions taken.

* **Does this change what S2N sends over the wire?** If yes, explain.
* **Does this change any public APIs?** If yes, explain.
* **Which versions of TLS will this impact?**

### Requirements / Acceptance Criteria:

What must a solution address in order to solve the problem? How do we know the solution is complete?

* **RFC links:** Links to relevant RFC(s)
* **Related Issues:** Link any relevant issues
* **Will the Usage Guide or other documentation need to be updated?**
* **Testing:** How will this change be tested? Call out new integration tests, functional tests, or particularly interesting/important unit tests.
  * **Will this change trigger SAW changes?** Changes to the state machine, the s2n_handshake_io code that controls state transitions, the DRBG, or the corking/uncorking logic could trigger SAW failures.
  * **Should this change be fuzz tested?** Will it handle untrusted input? Create a separate issue to track the fuzzing work.

### Out of scope:

Is there anything the solution will intentionally NOT address?

[//]: #  (NOTE: If you believe this might be a security issue, please email aws-security@amazon.com instead of creating a GitHub issue. For more details, see the AWS Vulnerability Reporting Guide: https://aws.amazon.com/security/vulnerability-reporting/ )
