*****************
Versioning Policy
*****************

We use a three-part X.Y.Z (Major.Minor.Patch) versioning definition, as follows:

* **X (Major)** version changes are significant and expected to break backwards compatibility.
* **Y (Minor)** version changes are moderate changes. These include:

  * Significant non-breaking feature additions.
  * Possible backwards-incompatible changes. These changes will be noted and explained in detail in the release notes.

* **Z (Patch)** version changes are small changes. These changes will not break backwards compatibility.

  * Z releases will also include warning of upcoming breaking changes, whenever possible.

Beta releases
=============

Versions with a zero major version (0.Y.Z) are considered to be beta
releases. In beta releases, a Y-change may involve significant API changes.

Branch stability
================

Untagged branches (such as main) are not subject to any API or ABI
stability policy; APIs may change at any time.

What this means for you
=======================

We recommend running the most recent version. Here are our suggestions for managing updates:

* Beta releases should be considered to be under flux. While we will try to minimize churn, expect that
  you'll need to make some changes to move to the 1.0.0 release.
* X changes will require some effort to incorporate.
* Y changes will not require significant effort to incorporate.
  * If you have good unit and integration tests, these changes are generally safe to pick up automatically.
* Z changes will not require any changes to your code. Z changes are intended to be picked up automatically.
  * Good unit and integration tests are always recommended.
