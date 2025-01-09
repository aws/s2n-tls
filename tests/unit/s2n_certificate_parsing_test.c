/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include "api/s2n.h"
#include "crypto/s2n_crypto.h"
#include "crypto/s2n_openssl_x509.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_tls.h"
#include "utils/s2n_safety.h"

#define CERTIFICATE_1                                                  \
    "MIIBljCCATygAwIBAgIUHxKbtYzLM4Bct5v5Sagb8aZU/BcwCgYIKoZIzj0EAwIw" \
    "HjELMAkGA1UEBhMCVVMxDzANBgNVBAMMBmJyYW5jaDAgFw0yNDAxMjMwMDU3MTha" \
    "GA8yMjAzMDYzMDAwNTcxOFowHDELMAkGA1UEBhMCVVMxDTALBgNVBAMMBGxlYWYw" \
    "WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASAmJKXt9P8hSz9ubntEokFn06+Rexr" \
    "lEujwWUIq5Kl6QwvtfDCzrJN/sUmM5mssjq7pF6XVr6zFcQ6G4BfnwGio1gwVjAU" \
    "BgNVHREEDTALgglsb2NhbGhvc3QwHQYDVR0OBBYEFNlOWJn7XfzC6xORzzjrdnqK" \
    "UlJwMB8GA1UdIwQYMBaAFFkQhpDCJ3bAbXw1tXpmk5Fi7YIGMAoGCCqGSM49BAMC" \
    "A0gAMEUCIB58OBwIruTJIy1f3tUgM/wXoO7fCoU25sMcioHBV9dYAiEA7Ufxa2JF" \
    "I5LP6RGyllsjjnh0MJy1ZMXhw7X6GqFn4Rw="

#define CERTIFICATE_2                                                  \
    "MIIBoDCCAUegAwIBAgIUQud1+tNUPAEBnJLb2Lyl3/vuA4EwCgYIKoZIzj0EAwIw" \
    "HDELMAkGA1UEBhMCVVMxDTALBgNVBAMMBHJvb3QwIBcNMjQwMTIzMDA1NzE4WhgP" \
    "MjIwMzA2MzAwMDU3MThaMB4xCzAJBgNVBAYTAlVTMQ8wDQYDVQQDDAZicmFuY2gw" \
    "WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATfScB9w/LkHBAVXiyKN941555oyBpv" \
    "IZeCNXX+gbSvnS0pNRr35BalgFmij86DaXLl68RrHQsnhZByJvnIplN+o2MwYTAP" \
    "BgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwICBDAdBgNVHQ4EFgQUWRCGkMIn" \
    "dsBtfDW1emaTkWLtggYwHwYDVR0jBBgwFoAUfCtcQDvXYwkR37fHwe/mi7JyQIQw" \
    "CgYIKoZIzj0EAwIDRwAwRAIgaK6aOuCfMwgAASavkZpoxWag49yco4d9AlxIU+rt" \
    "U2UCIHRieWdQICIWSEHdRTXWPPEnOd7A3UmTgoqbMl+Imhy8"

#define CERTIFICATE_3                                                  \
    "MIIBnzCCAUWgAwIBAgIUe0/XdFLyc4+Sj1NMkvbagE8DFaUwCgYIKoZIzj0EAwIw" \
    "HDELMAkGA1UEBhMCVVMxDTALBgNVBAMMBHJvb3QwIBcNMjQwMTIzMDA1NzE4WhgP" \
    "MjIwMzA2MzAwMDU3MThaMBwxCzAJBgNVBAYTAlVTMQ0wCwYDVQQDDARyb290MFkw" \
    "EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEPPtDvucc4UGOdIjED2P/vDxVYDhO5P8s" \
    "7lyys3QZpKapMuc9wOV0cQ6tN9h4kVY+FJocYgqDAl2vv6Rg/wSbl6NjMGEwHQYD" \
    "VR0OBBYEFHwrXEA712MJEd+3x8Hv5ouyckCEMB8GA1UdIwQYMBaAFHwrXEA712MJ" \
    "Ed+3x8Hv5ouyckCEMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgIEMAoG" \
    "CCqGSM49BAMCA0gAMEUCIQCcbhKRAsqQCj2pCXh+9og3sLw9q8nU4xAB9xuV3vPA" \
    "FAIgBxFWfRdu09dtE0IUkLTY0WPxiWaYYrKexlD4wUquqJE="

#define BEGIN_CERT      "BEGIN CERTIFICATE"
#define BEGIN_CERT_LINE "-----" BEGIN_CERT "-----"
#define END_CERT        "END CERTIFICATE"
#define END_CERT_LINE   "-----" END_CERT "-----"

static S2N_RESULT s2n_test_validate_cert(struct s2n_cert *cert, struct s2n_blob *expected)
{
    RESULT_ENSURE_REF(cert);
    RESULT_ENSURE_REF(expected);
    RESULT_ENSURE_EQ(cert->raw.size, expected->size);
    RESULT_ENSURE_EQ(memcmp(cert->raw.data, expected->data, expected->size), 0);
    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    const char *expected_cert_strs[] = {
        CERTIFICATE_1,
        CERTIFICATE_2,
        CERTIFICATE_3,
    };
    struct s2n_blob expected_certs[s2n_array_len(expected_cert_strs)] = { 0 };
    EXPECT_EQUAL(s2n_array_len(expected_certs), s2n_array_len(expected_cert_strs));

    for (size_t i = 0; i < s2n_array_len(expected_certs); i++) {
        const char *base64_cert = expected_cert_strs[i];
        struct s2n_blob *out = &expected_certs[i];

        /* base64 requires more than one character per byte, so the binary
         * output will be smaller than the base64 input.
         */
        EXPECT_SUCCESS(s2n_alloc(out, strlen(base64_cert)));

        struct s2n_stuffer out_stuffer = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_init(&out_stuffer, out));

        DEFER_CLEANUP(struct s2n_stuffer in_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_alloc(&in_stuffer, strlen(base64_cert)));
        EXPECT_SUCCESS(s2n_stuffer_write_str(&in_stuffer, base64_cert));

        EXPECT_SUCCESS(s2n_stuffer_read_base64(&in_stuffer, &out_stuffer));
        out->size = s2n_stuffer_data_available(&out_stuffer);
    }

    struct s2n_test_case {
        const char *name;
        const char *input;
    };

    /* clang-format off */
    const struct s2n_test_case test_cases[] = {
        {
            .name = "basic format",
            .input =
                BEGIN_CERT_LINE "\n"
                CERTIFICATE_1 "\n"
                END_CERT_LINE "\n"
                BEGIN_CERT_LINE "\n"
                CERTIFICATE_2 "\n"
                END_CERT_LINE "\n"
                BEGIN_CERT_LINE "\n"
                CERTIFICATE_3 "\n"
                END_CERT_LINE "\n",
        },
        {
            .name = "no newlines",
            .input =
                BEGIN_CERT_LINE CERTIFICATE_1 END_CERT_LINE
                BEGIN_CERT_LINE CERTIFICATE_2 END_CERT_LINE
                BEGIN_CERT_LINE CERTIFICATE_3 END_CERT_LINE,
        },
        {
            .name = "empty lines",
            .input =
                "\n"
                BEGIN_CERT_LINE "\n"
                CERTIFICATE_1 "\n"
                END_CERT_LINE "\n"
                "\n"
                BEGIN_CERT_LINE "\n"
                CERTIFICATE_2 "\n"
                END_CERT_LINE "\n"
                "\n"
                BEGIN_CERT_LINE "\n"
                CERTIFICATE_3 "\n"
                END_CERT_LINE "\n"
                "\n",
        },
        {
            .name = "double empty lines",
            .input =
                "\n"
                "\n"
                BEGIN_CERT_LINE "\n"
                CERTIFICATE_1 "\n"
                END_CERT_LINE "\n"
                "\n"
                "\n"
                BEGIN_CERT_LINE "\n"
                CERTIFICATE_2 "\n"
                END_CERT_LINE "\n"
                "\n"
                "\n"
                BEGIN_CERT_LINE "\n"
                CERTIFICATE_3 "\n"
                END_CERT_LINE "\n"
                "\n"
                "\n",
        },
        {
            .name = "variable number of newlines",
            .input =
                "\n"
                BEGIN_CERT_LINE "\n"
                CERTIFICATE_1 "\n"
                END_CERT_LINE "\n"
                "\n\n\n"
                BEGIN_CERT_LINE "\n"
                CERTIFICATE_2 "\n"
                END_CERT_LINE "\n"
                BEGIN_CERT_LINE "\n"
                CERTIFICATE_3 "\n"
                END_CERT_LINE "\n"
                "\n\n"
        },
        {
            .name = "whitespace",
            .input =
                "   " BEGIN_CERT_LINE "\n"
                CERTIFICATE_1 "\n"
                END_CERT_LINE "  \n"
                "                 "
                BEGIN_CERT_LINE "\n"
                CERTIFICATE_2 "\n"
                END_CERT_LINE "    \n"
                BEGIN_CERT_LINE "\n"
                CERTIFICATE_3 "\n"
                END_CERT_LINE "  \n",
        },
        {
            .name = "extra dashes",
            .input =
                "-" BEGIN_CERT_LINE "--\n"
                CERTIFICATE_1 "\n"
                "---" END_CERT_LINE "----\n"
                "-----" BEGIN_CERT_LINE "------\n"
                CERTIFICATE_2 "\n"
                END_CERT_LINE "---------------\n"
                "--" BEGIN_CERT_LINE "---\n"
                CERTIFICATE_3 "\n"
                "-" END_CERT_LINE "-\n",
        },
        {
            .name = "64 dashes",
            .input =
                "-----" "-----" "-----" "-----"
                "-----" "-----" "-----" "-----"
                "-----" "-----" "-----" "-----"
                "----"
                BEGIN_CERT
                "-----" "-----" "-----" "-----"
                "-----" "-----" "-----" "-----"
                "-----" "-----" "-----" "-----"
                "----"
                "\n"
                CERTIFICATE_1 "\n"
                END_CERT_LINE "\n"
                BEGIN_CERT_LINE "\n"
                CERTIFICATE_2 "\n"
                END_CERT_LINE "\n"
                BEGIN_CERT_LINE "\n"
                CERTIFICATE_3 "\n"
                END_CERT_LINE "\n",
        },
        {
            .name = "missing dashes",
            .input =
                "--" BEGIN_CERT "--\n"
                CERTIFICATE_1 "\n"
                "---" END_CERT "---\n"
                "----" BEGIN_CERT "----\n"
                CERTIFICATE_2 "\n"
                "--" END_CERT "---\n"
                "---" BEGIN_CERT "----\n"
                CERTIFICATE_3 "\n"
                "----" END_CERT "--\n",
        },
        {
            .name = "delimiters share dashes",
            .input =
                "--" BEGIN_CERT "--" CERTIFICATE_1 "--" END_CERT
                "--" BEGIN_CERT "--" CERTIFICATE_2 "--" END_CERT
                "--" BEGIN_CERT "--" CERTIFICATE_3 "--" END_CERT "--" ,
        },
        {
            .name = "non-certificate data",
            .input =
                "this is not a certificate\n"
                BEGIN_CERT_LINE "\n"
                CERTIFICATE_1 "\n"
                END_CERT_LINE "\n"
                "\n"
                "this is not a certificate either\n"
                "\n"
                BEGIN_CERT_LINE "\n"
                CERTIFICATE_2 "\n"
                END_CERT_LINE "not a certificate\n"
                "not a certificate" BEGIN_CERT_LINE "\n"
                CERTIFICATE_3 "\n"
                END_CERT_LINE "\n",
        },
        {
            .name = "comments",
            .input =
                "# cert1"
                BEGIN_CERT_LINE "\n"
                CERTIFICATE_1 "\n"
                END_CERT_LINE "\n"
                "\n"
                "# cert2"
                BEGIN_CERT_LINE "\n"
                CERTIFICATE_2 "\n"
                END_CERT_LINE "\n"
                "\n"
                "# cert3"
                BEGIN_CERT_LINE "\n"
                CERTIFICATE_3 "\n"
                END_CERT_LINE "\n",
        },
        {
            .name = "comments containing dashes",
            .input =
                "# cert-1\n"
                BEGIN_CERT_LINE "\n"
                CERTIFICATE_1 "\n"
                END_CERT_LINE "\n"
                "\n"
                "# -c-e-r-t-2-\n"
                BEGIN_CERT_LINE "\n"
                CERTIFICATE_2 "\n"
                END_CERT_LINE "\n"
                "\n"
                "# -\n"
                BEGIN_CERT_LINE "\n"
                CERTIFICATE_3 "\n"
                END_CERT_LINE "\n",
        },
        {
            .name = "comments containing other special characters",
            .input =
                "# cert_1\n"
                BEGIN_CERT_LINE "\n"
                CERTIFICATE_1 "\n"
                END_CERT_LINE "\n"
                "\n"
                "# cert #2\n"
                BEGIN_CERT_LINE "\n"
                CERTIFICATE_2 "\n"
                END_CERT_LINE "\n"
                "\n"
                "# cert !@$%! \n"
                BEGIN_CERT_LINE "\n"
                CERTIFICATE_3 "\n"
                END_CERT_LINE "\n",
        },
        {
            .name = "trailing comment",
            .input =
                BEGIN_CERT_LINE "\n"
                CERTIFICATE_1 "\n"
                END_CERT_LINE "\n"
                BEGIN_CERT_LINE "\n"
                CERTIFICATE_2 "\n"
                END_CERT_LINE "\n"
                BEGIN_CERT_LINE "\n"
                CERTIFICATE_3 "\n"
                END_CERT_LINE "\n"
                "# trailing comment \n"
        },
        {
            .name = "trailing whitespace",
            .input =
                BEGIN_CERT_LINE "\n"
                CERTIFICATE_1 "\n"
                END_CERT_LINE "\n"
                BEGIN_CERT_LINE "\n"
                CERTIFICATE_2 "\n"
                END_CERT_LINE "\n"
                BEGIN_CERT_LINE "\n"
                CERTIFICATE_3 "\n"
                END_CERT_LINE "\n"
                "\n"
                "\n",
        },
        {
            .name = "trailing non-certificate data",
            .input =
                BEGIN_CERT_LINE "\n"
                CERTIFICATE_1 "\n"
                END_CERT_LINE "\n"
                BEGIN_CERT_LINE "\n"
                CERTIFICATE_2 "\n"
                END_CERT_LINE "\n"
                BEGIN_CERT_LINE "\n"
                CERTIFICATE_3 "\n"
                END_CERT_LINE "\n"
                "this is not a certificate\n"
                "neither is this",
        },
    };
    /* clang-format on */

    for (size_t i = 0; i < s2n_array_len(test_cases); i++) {
        DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = s2n_cert_chain_and_key_new(),
                s2n_cert_chain_and_key_ptr_free);
        const struct s2n_test_case *test_case = &test_cases[i];

        DEFER_CLEANUP(struct s2n_stuffer input = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_alloc(&input, strlen(test_case->input)));
        EXPECT_SUCCESS(s2n_stuffer_write_str(&input, test_case->input));

        struct s2n_cert_chain *cert_chain = chain_and_key->cert_chain;
        if (s2n_create_cert_chain_from_stuffer(cert_chain, &input) != S2N_SUCCESS) {
            fprintf(stderr, "Failed to parse \"%s\"\n", test_case->name);
            FAIL_MSG("Failed to parse certificate chain input");
        }

        struct s2n_cert *cert = cert_chain->head;
        for (size_t j = 0; j < s2n_array_len(expected_certs); j++) {
            if (s2n_result_is_error(s2n_test_validate_cert(cert, &expected_certs[j]))) {
                fprintf(stderr, "\"%s\" failed to parse cert %zu\n", test_case->name, j);
                FAIL_MSG("Did not correctly read all certificates");
            }
            cert = cert->next;
        }
    }

    /* clang-format off */
    const struct s2n_test_case bad_test_cases[] = {
        {
            .name = "double begin marker",
            .input =
                BEGIN_CERT_LINE "\n"
                BEGIN_CERT_LINE "\n"
                CERTIFICATE_1 "\n"
                END_CERT_LINE "\n"
        },
        {
            .name = "double end marker",
            .input =
                BEGIN_CERT_LINE "\n"
                CERTIFICATE_1 "\n"
                END_CERT_LINE "\n"
                END_CERT_LINE "\n"
        },
        {
            .name = "missing begin marker",
            .input =
                CERTIFICATE_1 "\n"
                END_CERT_LINE "\n"
        },
        {
            .name = "missing end marker",
            .input =
                BEGIN_CERT_LINE "\n"
                CERTIFICATE_1 "\n"
        },
        {
            .name = "no dashes before marker",
            .input =
                BEGIN_CERT "-----\n"
                CERTIFICATE_1 "\n"
                END_CERT_LINE "\n"
        },
        {
            .name = "no dashes after marker",
            .input =
                "-----" BEGIN_CERT "\n"
                CERTIFICATE_1 "\n"
                END_CERT_LINE "\n"
        },
        {
            .name = "single dash before marker",
            .input =
                "-" BEGIN_CERT "-----\n"
                CERTIFICATE_1 "\n"
                END_CERT_LINE "\n"
        },
        {
            .name = "single dash after marker",
            .input =
                "-----" BEGIN_CERT "-\n"
                CERTIFICATE_1 "\n"
                END_CERT_LINE "\n"
        },
        {
            .name = "65 dashes before marker",
            .input =
                "-----" "-----" "-----" "-----"
                "-----" "-----" "-----" "-----"
                "-----" "-----" "-----" "-----"
                "-----"
                BEGIN_CERT "-----\n"
                CERTIFICATE_1 "\n"
                END_CERT_LINE "\n"
        },
        {
            .name = "65 dashes after marker",
            .input =
                "-----" BEGIN_CERT
                "-----" "-----" "-----" "-----"
                "-----" "-----" "-----" "-----"
                "-----" "-----" "-----" "-----"
                "-----" "\n"
                CERTIFICATE_1 "\n"
                END_CERT_LINE "\n"
        },
        {
            .name = "dashes in comment",
            .input =
                "# --cert--\n"
                BEGIN_CERT_LINE "\n"
                CERTIFICATE_1 "\n"
                END_CERT_LINE "\n"
        },
        {
            .name = "multiple certs: trailing marker",
            .input =
                BEGIN_CERT_LINE "\n"
                CERTIFICATE_1 "\n"
                END_CERT_LINE "\n"
                BEGIN_CERT_LINE "\n"
        },
        {
            .name = "multiple certs: trailing partial certificate",
            .input =
                BEGIN_CERT_LINE "\n"
                CERTIFICATE_1 "\n"
                END_CERT_LINE "\n"
                BEGIN_CERT_LINE "\n"
                "MIIBljCCATygAwIBAg\n"
        },
        {
            .name = "multiple certs: missing end marker",
            .input =
                BEGIN_CERT_LINE "\n"
                CERTIFICATE_1 "\n"
                END_CERT_LINE "\n"
                BEGIN_CERT_LINE "\n"
                CERTIFICATE_1 "\n"
        },
    };
    /* clang-format on */

    for (size_t i = 0; i < s2n_array_len(bad_test_cases); i++) {
        DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = s2n_cert_chain_and_key_new(),
                s2n_cert_chain_and_key_ptr_free);
        const struct s2n_test_case *test_case = &bad_test_cases[i];

        DEFER_CLEANUP(struct s2n_stuffer test_input = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_alloc(&test_input, strlen(test_case->input)));
        EXPECT_SUCCESS(s2n_stuffer_write_str(&test_input, test_case->input));

        struct s2n_cert_chain *cert_chain = chain_and_key->cert_chain;
        if (s2n_create_cert_chain_from_stuffer(cert_chain, &test_input) == S2N_SUCCESS) {
            fprintf(stderr, "Successfully parsed invalid cert chain \"%s\"\n", test_case->name);
            FAIL_MSG("Successfully parsed invalid cert chain");
        };
    }

    /* Any case that is invalid for a single certificate should also be invalid
     * for a certificate chain.
     * We do not want to rely solely on our test for 0-length chains.
     */
    const char *valid_cert_chain = test_cases[0].input;
    for (size_t i = 0; i < s2n_array_len(bad_test_cases); i++) {
        const struct s2n_test_case *test_case = &bad_test_cases[i];

        /* The extra character is for an extra newline */
        size_t test_input_size = strlen(test_case->input) + strlen(valid_cert_chain) + 1;

        DEFER_CLEANUP(struct s2n_stuffer test_input = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_alloc(&test_input, test_input_size));
        EXPECT_SUCCESS(s2n_stuffer_write_str(&test_input, valid_cert_chain));

        /* Sanity check: valid chain is valid */
        DEFER_CLEANUP(struct s2n_cert_chain_and_key *good_chain_and_key = s2n_cert_chain_and_key_new(),
                s2n_cert_chain_and_key_ptr_free);
        struct s2n_cert_chain *good_chain = good_chain_and_key->cert_chain;
        EXPECT_SUCCESS(s2n_create_cert_chain_from_stuffer(good_chain, &test_input));

        /* Add the invalid input to the end of the proven valid chain */
        EXPECT_SUCCESS(s2n_stuffer_write_char(&test_input, '\n'));
        EXPECT_SUCCESS(s2n_stuffer_write_str(&test_input, test_case->input));
        EXPECT_SUCCESS(s2n_stuffer_reread(&test_input));

        /* Test: valid chain + invalid test case is sill invalid */
        DEFER_CLEANUP(struct s2n_cert_chain_and_key *bad_chain_and_key = s2n_cert_chain_and_key_new(),
                s2n_cert_chain_and_key_ptr_free);
        struct s2n_cert_chain *bad_chain = bad_chain_and_key->cert_chain;
        if (s2n_create_cert_chain_from_stuffer(bad_chain, &test_input) == S2N_SUCCESS) {
            fprintf(stderr, "Successfully parsed invalid cert chain \"%s\"\n", test_case->name);
            FAIL_MSG("Successfully parsed invalid cert chain");
        };
    }

    for (size_t i = 0; i < s2n_array_len(expected_certs); i++) {
        EXPECT_SUCCESS(s2n_free(&expected_certs[i]));
    }
    END_TEST();
}
