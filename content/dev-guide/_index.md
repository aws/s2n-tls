+++
title = "Developer Guide"
date = 2023-10-27T13:44:04-07:00
weight = 2
+++

If you are curious about the internals of s2n-tls, or interested in contributing to
s2n-tls, this document is for you. If instead you are interested in using s2n-tls in an application
that you are developing, please see the accompanying [User Guide](/content/user-guide/).

## Contributing to s2n-tls

We are happy to accept contributions to s2n-tls . We suggest the following general procedure:

* Please read all of the documentation available in the s2n-tls "docs/" directory. This development guide along with the usage guide should give a good flavor for what the goals of s2n-tls are and whether they line up with your idea for a contribution
* If you have an idea for a significant contribution, it is worth first cutting an issue and discussing the change. Get feedback on the API design, or what the feature might require, before writing code.
* If you discover a security critical bug, please report it via [`http://aws.amazon.com/security/vulnerability-reporting/`](http://aws.amazon.com/security/vulnerability-reporting/) and **do not** create a public issue.
* Create a git fork of the s2n-tls repository and prepare your changes locally within your fork.
* When you're ready, and when all tests are passing, create a pull request to the master awslabs s2n-tls repository.
* All changes to s2n-tls go through code review and legal review. All submissions and contributions are made under the terms of the Apache Software License 2.0. For larger contributions, we may ask you to sign a contributor license agreement.
* s2n-tls undergoes periodic government and commercial security analyses, including code audits and penetration tests. To participate in these analyses, we may ask you to sign a Non-Disclosure Agreement.
