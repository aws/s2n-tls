##
# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at
#
#  http://aws.amazon.com/apache2.0
#
# or in the "license" file accompanying this file. This file is distributed
# on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.
#

"""
Common functions used to report the results of tests.
"""

import sys
from enum import Enum


class Status(Enum):
    """
    Enum to represent success/failure. The values are the
    color codes used to print the status.
    """
    PASSED = 32
    FAILED = 31

    def __str__(self):
        return with_color(self.name, self.value)


class Result:

    """
    A class to standardize how test results are reported.

    """

    def __init__(self, error=None):
        self.error = error
        self.status = Status.PASSED if error == None else Status.FAILED

    def is_success(self):
        return self.status is not Status.FAILED

    def __str__(self):
        result = str(self.status)
        if self.error:
            result += "\n\t%s" % self.error
        return result


def with_color(msg, color):
    if sys.stdout.isatty():
        return "\033[%d;1m%s\033[0m" % (color, msg)
    else:
        return msg

