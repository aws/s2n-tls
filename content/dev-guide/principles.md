+++
title = 'Principles'
date = 2023-10-27T13:41:18-07:00
weight = 30
draft = false
+++

Before getting into the detail of how s2n-tls works internally, it's worth covering
s2n-tls's development principles. These principles guide and inform many of the design
decisions we'll go through. We're always open to new principles, if you can think of
better ones and make a case for them.

> [!NOTE]
> This syntax is called a definition list.
> They are useful in documentation.
> Support for definition lists is a hard SSG requirement.

Maintain an excellent TLS/SSL implementation
: Although it's hidden "under the hood", TLS/SSL is the direct interface with customers and end-users. Good performance and security are critical to a positive experience.

Protect user data and keys
: Above all else, s2n-tls must ensure that user data and private keys are being handled correctly and carefully. Security is often a matter of trade-offs and costs we should always strive to increase the costs for attackers whenever the tradeoffs are acceptable to users.

Stay simple
: Write as little code as necessary, omit rarely used optional features and support as few modes of operation as possible. We will also promote and encourage changes that reduce the size of our code base.

Write clear readable code with a light cognitive load
: s2n-tls's code must be concise, easy to follow and legible to a proficient C programmer. Our code should be organized in a way that divides the implementation up into small units of work, with the entire context necessary at hand. We should also minimize the number of branches in our code, the depth of our call stacks, and the number of members in our structures.

Defend in depth and systematically
: Great care and attention to detail is required to write good code, but we also use automation and mechanistic processes to protect against human error.

Be easy to use and maintain sane defaults
: It should be low effort, even for a novice developer, to use s2n-tls in a safe way. We also shouldn't "_pass the buck_" and place the burden of subtle or complicated TLS-specific decision making upon application authors and system administrators.

Provide great performance and responsiveness
: TLS/SSL is rapidly becoming ubiquitous. Even small inefficiencies and overhead can become significant when multiplied by billions of users and quintillions of sessions.

Stay paranoid
: s2n-tls operates in a security critical space. Even with the most precautionary development methods it is impossible to guarantee the absence of defects. A subtle one-byte error on a single line may still cause problems.

Make data-driven decisions
: Opinions can differ on security best practices, sometimes in contradictory ways. Where possible, we are guided by facts and measurable data.

## Priorities

When weighing up difficult implementation trade-offs our ordered set of priorities are:

1. Security
2. Readability
3. Ease of use
4. Performance.

## Commit and code-review policy

s2n-tls is review-then-commit for code changes, and commit-then-review for
documentation changes. Code additions are made by pull requests, no author may
merge their own pull request on code. Changes to documentation, including code
comments, may be made more freely.
