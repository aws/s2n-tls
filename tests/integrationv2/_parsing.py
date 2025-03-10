import re

ALL_TEST_CERTS = {
    "RSA_1024_SHA256",
    "RSA_1024_SHA384",
    "RSA_1024_SHA512",
    "RSA_2048_SHA256",
    "RSA_2048_SHA384",
    "RSA_2048_SHA512",
    "RSA_3072_SHA256",
    "RSA_3072_SHA384",
    "RSA_3072_SHA512",
    "RSA_4096_SHA256",
    "RSA_4096_SHA384",
    "RSA_4096_SHA512",
    "ECDSA_256",
    "ECDSA_384",
    "ECDSA_521",
    "RSA_PSS_2048_SHA256",
}


def parse_test_line(line):
    """
    Extracts base parameters from a test line, ignoring the test name and dynamically locating the certificate.

    Example:
    Input: "test_buffered_send.py::test_s2n_server_buffered_send[None-1034-RSA_2048_SHA512-TLS1.3-S2N-TLS_AES_128_GCM_SHA256]"
    Output: "None-1034-TLS1.3-S2N-TLS_AES_128_GCM_SHA256"
    """
    match = re.match(r".*?\[(.*?)\]$", line.strip())
    if match:
        parts = match.group(1).split("-")
        # Find and remove the certificate from parts
        filtered_parts = [p for p in parts if p not in ALL_TEST_CERTS]
        return "-".join(filtered_parts)
    return None


def extract_base_params(filename):
    """
    Reads a test output file and extracts a set of unique base parameter combinations.

    Example file content:
    test_buffered_send.py::test_s2n_server_buffered_send[None-1034-RSA_2048_SHA512-TLS1.3-S2N-TLS_AES_128_GCM_SHA256]
    test_buffered_send.py::test_s2n_server_buffered_send[None-1034-RSA_4096_SHA256-TLS1.3-S2N-TLS_AES_128_GCM_SHA256]

    Extracted base parameters:
    {
        "None-1034-TLS1.3-S2N-TLS_AES_128_GCM_SHA256"
    }
    """
    base_params_set = set()
    with open(filename, "r") as file:
        for line in file:
            base_params = parse_test_line(line)
            if base_params:
                base_params_set.add(base_params)
    return base_params_set


def compare_test_cases(file1, file2):
    """
    Compares two test output files, ensuring every base parameter remains covered.

    Example:
    File1 contains:
    test_buffered_send.py::test_s2n_server_buffered_send[None-1034-RSA_2048_SHA512-TLS1.3-S2N-TLS_AES_128_GCM_SHA256]
    test_buffered_send.py::test_s2n_server_buffered_send[None-2048-RSA_4096_SHA256-TLS1.3-OpenSSL-TLS_AES_128_GCM_SHA256]

    File2 contains:
    test_buffered_send.py::test_s2n_server_buffered_send[None-1034-RSA_4096_SHA256-TLS1.3-S2N-TLS_AES_128_GCM_SHA256]

    Missing base parameters output:
    --- Missing Test Combinations ---
    ❌ Entire missing base parameters:
      None-2048-TLS1.3-OpenSSL-TLS_AES_128_GCM_SHA256
    """
    base_params1 = extract_base_params(file1)
    base_params2 = extract_base_params(file2)

    missing_base_params = base_params1 - base_params2

    print("--- Missing Test Combinations ---")
    if missing_base_params:
        print("❌ Entire missing base parameters:")
        for base_params in missing_base_params:
            print(f"  {base_params}")
    else:
        print("✅ No missing test combinations found.")


test_output_1 = "before_collected.txt"
test_output_2 = "collected.txt"

compare_test_cases(test_output_1, test_output_2)
