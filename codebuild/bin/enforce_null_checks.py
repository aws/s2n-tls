from collections import defaultdict
import os
import re
import sys
from typing import Union

VARIABLE_TOKEN = "<VARIABLE>"

NULL_CHECKS = [
    "RESULT_ENSURE_REF(<VARIABLE>)",
    "POSIX_ENSURE_REF(<VARIABLE>)",
    "EXPECT_NOT_NULL(<VARIABLE>)",
    # we often use if statement to check nullability, e.g. if "not null" which
    # uses this construction
    "!<VARIABLE>",
    "<VARIABLE> == NULL",
]

AUTOFIX_ELGIBLE = {
    "RESULT_": "RESULT_ENSURE_REF(<VARIABLE>);\n",
    "POSIX_": "POSIX_ENSURE_REF(<VARIABLE>);\n",
    "EXPECT_": "EXPECT_NOT_NULL(<VARIABLE>);\n",
    "PTR_": "PTR_ENSURE_REF(<VARIABLE>);\n",
}

# We include the declaration in the regex to avoid alerting on the common case
# of EXPECT_NOT_NULL(config = s2n_config_new())
FUNCTIONS_TO_CHECK = {
    "s2n_config_new": re.compile(r"\bstruct s2n_config \*(.*) = s2n_config_new\s*\("),
    "s2n_connection_new": re.compile(
        r"\bstruct s2n_connection \*(.*) = s2n_connection_new\s*\("
    ),
}

# The null check for a function must be within this many lines to count
LOCALITY_ALLOWANCE = 5


class Violation:
    # the function whose return pointer was not checked
    function: str
    # the name of the variable that should be checked
    variable: str
    # the filename where this violation was found
    filename: str
    # the raw lines of "filename". This is used to print out context lines
    lines: list[str]
    line_number: int

    def __init__(
        self,
        function: str,
        variable: str,
        filename: str,
        filelines: list[str],
        line_number: int,
    ):
        self.function = function
        self.variable = variable
        self.filename = filename
        self.lines = filelines
        self.line_number = line_number

    def determine_null_check(self) -> Union[str, None]:
        """
        Try to guess the appropriate null check that should be added to fix the violation,
        based on the type of the closest following safety macro.
        """
        for line_index in range(self.line_number, len(self.lines)):
            for indicator, fix in AUTOFIX_ELGIBLE.items():
                if indicator in self.lines[line_index]:
                    return fix.replace(VARIABLE_TOKEN, self.variable)
        return None

    def print_info(self):
        # add one to line number for accurate line description, because the first
        # line of a file is line 1, not line 0
        print(
            f"File: {self.filename}:{self.line_number + 1}: nullness of {self.variable} was not checked"
        )
        for i in range(LOCALITY_ALLOWANCE):
            print(
                f"   {(self.line_number + i + 1):4}\t"
                + self.lines[self.line_number + i].strip()
            )
        fix = self.determine_null_check()
        if fix is not None:
            print(f"You should add `{fix.strip()}` after the call to {self.function}")
        print("")


def find_function_usage(function: re.Pattern, file: list[str]) -> list[(str, int)]:
    """
    Return value is a tuple of (variable_name, line number)
    """
    results = []
    for line_number, line in enumerate(file):
        match = function.search(line)
        if match is None:
            continue
        variable = match.group(1)
        results.append((variable, line_number))
    return results


def is_null_checked(variable: str, line_number: int, file: list[str]) -> bool:
    """
    Determine whether `variable` has some null check
    """
    assertions = [s.replace(VARIABLE_TOKEN, variable) for s in NULL_CHECKS]
    for line_index in range(line_number, line_number + LOCALITY_ALLOWANCE):
        for assertion in assertions:
            if assertion in file[line_index]:
                return True
    return False


def autofix(violations: list[Violation]):
    """
    This is a best effort autofix that does not have a guarantee of correctness, but
    should be accurate for most cases. Note that this does not attempt to match
    whitespace, but this can be easily fixed with clang format by running
    codebuild/bin/clang_format_changed_files.sh
    """
    autofix_available: list[(Violation, str)] = []
    for v in violations:
        fix = v.determine_null_check()
        if fix is not None:
            autofix_available.append((v, fix))

    # filename -> list of (file violations, fix)
    failing_files: dict[str, list[(Violation, str)]] = defaultdict(list)
    for v, fix in autofix_available:
        failing_files[v.filename].append((v, fix))

    # sort each list of violations by line number
    for errors in failing_files.values():
        errors.sort(key=lambda v: v[0].line_number)

    # work backwards so that the line numbers are accurate
    for f, errors in failing_files.items():
        errors.reverse()
        for v, fix in errors:
            # to handle linebreaks, made sure that violation line has a semicolon
            # or find the next line with a semicolon
            insert_line_index = v.line_number
            while ";" not in v.lines[insert_line_index]:
                insert_line_index += 1

            # point at the line after the semicolon
            insert_line_index += 1

            v.lines.insert(insert_line_index, fix)

        file = open(v.filename, "w")
        file.writelines(v.lines)
        file.close()


if __name__ == "__main__":
    violations = []
    for root, dirs, files in os.walk("."):
        for file in files:
            # skip all files that aren't c
            # skip s2nc.c because it has different null handling conventions
            if not file.endswith(".c") or file.endswith("s2nc.c"):
                continue

            file_path = os.path.join(root, file)
            file = open(file_path, "r", encoding="utf-8")
            lines = file.readlines()
            file.close()

            for function, detection in FUNCTIONS_TO_CHECK.items():
                locations = find_function_usage(detection, lines)

                for variable, line_number in locations:
                    if not is_null_checked(variable, line_number, lines):
                        violations.append(
                            Violation(function, variable, file_path, lines, line_number)
                        )

    for v in violations:
        v.print_info()

    if "--fix" in sys.argv:
        autofix(violations)

    # if there are violations, exit with an unsuccessful error code
    if len(violations) != 0:
        sys.exit(1)
