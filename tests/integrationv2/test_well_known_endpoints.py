# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0


def test_well_known_endpoints():
    """
    This is a stub test, which allows the existing CI to continue passing while
    https://github.com/aws/s2n-tls/pull/4884 is merged in.

    Once the PR is merged, the Codebuild spec for NixIntegV2Batch will be updated
    to remove the "well_known_endpoints" argument (manual process) and then this test
    can be fully removed (PR).
    """
    assert 1 == 1
