import pytest

from codebuild.bin.s2n_open_fds_test import analysis_file_pattern, fd_pattern, error_message_start_pattern, error_message_end_pattern


def test_analysis_file_pattern():
    assert analysis_file_pattern.match(
        "LastDynamicAnalysis_20241017-1745.log").group() == "LastDynamicAnalysis_20241017-1745.log"


def test_analysis_file_pattern_incorrect_file_name():
    assert analysis_file_pattern.match("Lastdynamicanalysis_20241017-1745.log") == None


def test_fd_pattern_valgrind_3_13():
    assert fd_pattern.search("==6099== FILE DESCRIPTORS: 4 open at exit.").group(
    ) == "FILE DESCRIPTORS: 4 open at exit."


def test_fd_pattern_valgrind_3_18():
    assert fd_pattern.search("==6099== FILE DESCRIPTORS: 4 open (3 std) at exit.").group(
    ) == "FILE DESCRIPTORS: 4 open (3 std) at exit."


def test_fd_pattern_invalid():
    assert fd_pattern.match("==6129== Open AF_UNIX socket 19: <unknown>") == None


def test_error_message_start_pattern():
    assert error_message_start_pattern.match("Running /codebuild/output/src1744391194/src/tests/unit/s2n_blob_test.c ... PASSED         45 tests").group(
    ) == "Running /codebuild/output/src1744391194/src/tests/unit/s2n_blob_test.c ... PASSED         45 tests"


def test_error_message_start_pattern_invalid():
    assert error_message_start_pattern.match("==6099==    <inherited from parent>") == None


def test_error_message_end_pattern():
    assert error_message_end_pattern.match("<end of output>").group() == "<end of output>"


def test_error_message_end_pattern_invalid():
    assert error_message_end_pattern.match("==6099== FILE DESCRIPTORS: 4 open (3 std) at exit.") == None
