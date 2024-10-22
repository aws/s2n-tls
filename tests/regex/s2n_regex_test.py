# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from codebuild.bin.s2n_open_fds_test import analysis_file_pattern


def test_analysis_file_pattern():
    assert analysis_file_pattern.match(
        "LastDynamicAnalysis_20241017-1745.log").group() == "LastDynamicAnalysis_20241017-1745.log"


def test_analysis_file_pattern_incorrect_file_name():
    assert analysis_file_pattern.match("Lastdynamicanalysis_20241017-1745.log") is None
