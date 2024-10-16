import os, re, sys

# Allow stdin, stdout, stderr, and the file descriptor for dynamic analysis log to remain open at exit 
ACCEPTABLE_OPEN_FDS = 4
ERROR_EXIT_CODE = 123

analysis_file_location = "../../build/Testing/Temporary"
analysis_file_pattern = re.compile(r"^LastDynamicAnalysis*")
# This regular expression captures valgrind 3.13 and valgrind 3.18+ log
fd_pattern = re.compile(r"^==\d+== FILE DESCRIPTORS: \d+ open(?: \(3 std\))? at exit.$")
res_start_pattern = re.compile(r"^Running /codebuild/output/src\d+/src/.*")
res_end_pattern = re.compile(r"^<end of output>$")

def open_analysis_file(path):
    for file_name in os.listdir(path):
        if analysis_file_pattern.match(file_name):
            file = open(os.path.join(path, file_name), 'r')
    return file

def print_res(file_name, res):
    # Take the path to the failing test file
    print(f"{file_name.split(' ')[1]} leaks file descriptor(s):\n")
    print(''.join(res))
    return 0

def read_analysis_file(file):
    exit_code = 0
    res = []
    to_store = False
    to_print = False
    file_name = ""
    for line in file:
        if res_start_pattern.match(line):
            to_store = True
            file_name = line
            continue
        if res_end_pattern.match(line):
            if to_print:
                print_res(file_name, res)
            to_store = False
            res.clear()
            file_name = ""
            to_print = False
        if to_store:
            res.append(line)
            open_fd_match = fd_pattern.match(line)
            if open_fd_match:
                # Take the number of open file descriptors and check against the acceptable amount
                if int(re.findall(r"\d+", line)[1]) > ACCEPTABLE_OPEN_FDS:
                    exit_code = ERROR_EXIT_CODE
                    to_print = True
    file.close()
    return exit_code

def main():
    file = open_analysis_file(analysis_file_location)
    return read_analysis_file(file)

if __name__ == '__main__':
    sys.exit(main())
