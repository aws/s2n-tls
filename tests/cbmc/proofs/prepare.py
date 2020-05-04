#!/usr/bin/env python3
#
# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may not use
# this file except in compliance with the License. A copy of the License is
# located at
#
#     http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing permissions and
# limitations under the License.

# The CBMC CI system, at https://github.com/awslabs/aws-batch-cbmc, runs
# this program as part of preparing the source code. This program runs
# before any proof is built.


import logging
import os
import subprocess
import sys


def main():
    # Unconditionally rebuild the cbmc-batch.yaml file for every proof in
    # the source tree, so that the CI parameters for each proof are updated
    # before the proof is run.
    cmd = ["make", "-B", "cbmc-batch.yaml"]
    ok = True
    for root, _, fyles in os.walk("."):
        if "cbmc-batch.yaml" in fyles:
            proc = subprocess.run(cmd, cwd=root)
            if proc.returncode:
                ok = False
                logging.error(
                    "Failed to build cbmc-batch.yaml in %s (return code %d)",
                    root, proc.returncode)

    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
