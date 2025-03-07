import re
from collections import defaultdict


def parse_test_line(line):
    """Extracts test name and parameters from a test line."""
    match = re.match(r"(.*?)(\[.*\])?$", line.strip())
    if match:
        test_name = match.group(1)
        params = match.group(2) if match.group(2) else ""
        return test_name, params
    return None, None


def extract_test_cases(filename):
    """Reads a test output file and stores test cases in a dictionary."""
    test_cases = defaultdict(set)
    with open(filename, "r") as file:
        for line in file:
            test_name, params = parse_test_line(line)
            if test_name:
                test_cases[test_name].add(params)
    return test_cases


def compare_test_cases(file1, file2):
    """Compares two test output files and identifies missing combinations."""
    tests1 = extract_test_cases(file1)
    tests2 = extract_test_cases(file2)

    missing_combinations = {}
    
    for test in tests1:
        if test in tests2:
            missing_params = tests1[test] - tests2[test]
            if missing_params:
                missing_combinations[test] = missing_params
    
    print("--- Missing Test Combinations ---")
    if missing_combinations:
        for test, params in missing_combinations.items():
            print(f"{test}:")
            for param in sorted(params):
                print(f"  ❌ Missing: {param}")
    else:
        print("✅ No missing test combinations found.")


# Example usage:
# Run the script with two test output files to compare
test_output_1 = "before_collected.txt"  # Replace with actual file
test_output_2 = "collected.txt"  # Replace with actual file

compare_test_cases(test_output_1, test_output_2)
