import os
import re
import sys

# Allow stdin, stdout, stderr, and the file descriptor for dynamic analysis log to remain open at exit
ACCEPTABLE_OPEN_FDS = 4
ERROR_EXIT_CODE = 123

analysis_file_location = "../../build/Testing/Temporary"
analysis_file_pattern = re.compile(r"^LastDynamicAnalysis*")
# This regular expression captures valgrind 3.13 and valgrind 3.18+ log
fd_pattern = re.compile(r"FILE DESCRIPTORS: \d+ open(?: \(\d+ std\))? at exit.$")
error_message_start_pattern = re.compile(r"^Running /codebuild/output/src\d+/src/.*")
error_message_end_pattern = re.compile(r"^<end of output>$")


def open_analysis_file(path):
    for file_name in os.listdir(path):
        if analysis_file_pattern.match(file_name):
            file = open(os.path.join(path, file_name), 'r')
    return file


def print_error_message(file_name, error_message):
    # Take the path to the failing test file
    print(f"{file_name.split(' ')[1]} leaks file descriptor(s):\n")
    print(''.join(error_message))
    return 0


def read_analysis_file(file):
    exit_code = 0
    error_message = []
    to_store = False
    to_print = False
    file_name = ""
    for line in file:
        start_match = error_message_start_pattern.search(line)
        if start_match:
            file_name = start_match.group()
        """
        The FILE DESCRIPTORS string sometimes come on the same line
        as the Running s2n_test.c. Hence, we need multiple check to handle
        that corner case.
        """
        open_fd_match = fd_pattern.search(line)
        if open_fd_match:
            # Take the number of open file descriptors and check against the acceptable amount
            if int(re.findall(r"\d+", open_fd_match.group())[0]) > ACCEPTABLE_OPEN_FDS:
                exit_code = ERROR_EXIT_CODE
                to_print = True
                # Only store information about leaking file descriptors
                to_store = True
            else:
                to_store = False

        if error_message_end_pattern.match(line):
            if to_print:
                print_error_message(file_name, error_message)
            to_store = False
            error_message.clear()
            file_name = ""
            to_print = False

        if to_store:
            if open_fd_match:
                error_message.append(open_fd_match.group() + '\n')
            else:
                error_message.append(line)

    file.close()
    return exit_code


def main():
    file = open_analysis_file(analysis_file_location)
    return read_analysis_file(file)


if __name__ == '__main__':
    sys.exit(main())
