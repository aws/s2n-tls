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

#include "tls/s2n_ech_config.h"

#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_alerts.h"
#include "utils/s2n_array.h"

/* clang-format off */
/* An ECHConfig for "example.com" with config_id 0x2a, X25519, and two
 * cipher suites: HKDF-SHA256 with AES-128-GCM and with ChaCha20Poly1305. */
#define TEST_ECH_PUBLIC_KEY "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
#define TEST_ECH_CONFIG                                          \
    "fe0d"                   /* version */                       \
    "003e"                   /* length */                        \
    TEST_ECH_CONFIG_CONTENTS
#define TEST_ECH_CONFIG_CONTENTS                                 \
    TEST_ECH_CONFIG_CONTENTS_BEFORE_EXTENSIONS                   \
    "0000"                   /* extensions length */
#define TEST_ECH_CONFIG_CONTENTS_BEFORE_EXTENSIONS               \
    "2a"                     /* config_id */                     \
    "0020"                   /* kem_id: X25519 */                \
    "0020"                   /* public_key length */             \
    TEST_ECH_PUBLIC_KEY                                          \
    "0008"                   /* cipher_suites length */          \
    "00010001"               /* HKDF-SHA256, AES-128-GCM */      \
    "00010003"               /* HKDF-SHA256, ChaCha20Poly1305 */ \
    "00"                     /* maximum_name_length */           \
    "0b"                     /* public_name length */            \
    "6578616d706c652e636f6d" /* "example.com" */

/* An ECHConfig with the same layout as TEST_ECH_CONFIG, but with the given
 * config_id, kem_id, and two cipher suites. */
#define TEST_ECH_CONFIG_WITH(config_id, kem_id, suite_1, suite_2) \
    "fe0d" "003e" config_id kem_id "0020" TEST_ECH_PUBLIC_KEY      \
    "0008" suite_1 suite_2 "00" "0b" "6578616d706c652e636f6d" "0000"
/* clang-format on */

/* The size of the ECHConfigList length prefix */
#define TEST_LIST_PREFIX_SIZE 2
/* The size of an ECHConfig's version and length */
#define TEST_CONFIG_HEADER_SIZE 4
/* The size of config_id, kem_id, and the public_key length */
#define TEST_CONTENTS_PUBLIC_KEY_OFFSET 5

/* Writes an ECHConfigList holding one ECHConfig like TEST_ECH_CONFIG, but
 * with one cipher suite and a public_name of `public_name_size` bytes. */
static S2N_RESULT s2n_test_write_ech_config_list(struct s2n_stuffer *out, uint8_t public_name_size)
{
    S2N_CHECKED_BLOB_FROM_HEX(public_key, RESULT_GUARD, TEST_ECH_PUBLIC_KEY);
    uint16_t contents_size = 1 + 2 + 2 + public_key.size + 2 + 4 + 1 + 1 + public_name_size + 2;

    RESULT_GUARD_POSIX(s2n_stuffer_write_uint16(out, 4 + contents_size));
    RESULT_GUARD_POSIX(s2n_stuffer_write_uint16(out, 0xfe0d));
    RESULT_GUARD_POSIX(s2n_stuffer_write_uint16(out, contents_size));
    RESULT_GUARD_POSIX(s2n_stuffer_write_uint8(out, 0x2a));
    RESULT_GUARD_POSIX(s2n_stuffer_write_uint16(out, 0x0020));
    RESULT_GUARD_POSIX(s2n_stuffer_write_uint16(out, public_key.size));
    RESULT_GUARD_POSIX(s2n_stuffer_write(out, &public_key));
    RESULT_GUARD_POSIX(s2n_stuffer_write_uint16(out, 4));
    RESULT_GUARD_POSIX(s2n_stuffer_write_uint16(out, 0x0001));
    RESULT_GUARD_POSIX(s2n_stuffer_write_uint16(out, 0x0001));
    RESULT_GUARD_POSIX(s2n_stuffer_write_uint8(out, 0));
    RESULT_GUARD_POSIX(s2n_stuffer_write_uint8(out, public_name_size));
    for (size_t i = 0; i < public_name_size; i++) {
        RESULT_GUARD_POSIX(s2n_stuffer_write_uint8(out, 'a'));
    }
    RESULT_GUARD_POSIX(s2n_stuffer_write_uint16(out, 0));
    return S2N_RESULT_OK;
}

/* Writes an ECHConfigList holding one ECHConfig whose `contents` are cut
 * after `size` bytes, with the outer lengths matching the cut. */
static S2N_RESULT s2n_test_write_truncated_config(struct s2n_stuffer *out, const struct s2n_blob *contents,
        uint32_t size)
{
    RESULT_ENSURE_LTE(size, UINT16_MAX - TEST_CONFIG_HEADER_SIZE);
    RESULT_GUARD_POSIX(s2n_stuffer_write_uint16(out, TEST_CONFIG_HEADER_SIZE + size));
    RESULT_GUARD_POSIX(s2n_stuffer_write_uint16(out, 0xfe0d));
    RESULT_GUARD_POSIX(s2n_stuffer_write_uint16(out, size));
    RESULT_GUARD_POSIX(s2n_stuffer_write_bytes(out, contents->data, size));
    return S2N_RESULT_OK;
}

/* Writes an ECHConfigList holding one ECHConfig with the smallest fields
 * and as many empty extensions as fit, with types 0, 1, 2, and so on. If
 * `repeat_first` is set, the last extension has the first one's type. */
static S2N_RESULT s2n_test_write_max_extensions_list(struct s2n_stuffer *out, uint16_t *extension_count,
        bool repeat_first)
{
    /* config_id, kem_id, a 1-byte public_key, one cipher suite,
     * maximum_name_length, a 1-byte public_name, and the extensions length */
    const uint16_t fields_size = 1 + 2 + (2 + 1) + (2 + 4) + 1 + (1 + 1) + 2;
    const uint16_t max_contents_size = UINT16_MAX - TEST_CONFIG_HEADER_SIZE;
    *extension_count = (max_contents_size - fields_size) / 4;
    uint16_t extensions_size = *extension_count * 4;
    uint16_t contents_size = fields_size + extensions_size;

    RESULT_GUARD_POSIX(s2n_stuffer_write_uint16(out, TEST_CONFIG_HEADER_SIZE + contents_size));
    RESULT_GUARD_POSIX(s2n_stuffer_write_uint16(out, 0xfe0d));
    RESULT_GUARD_POSIX(s2n_stuffer_write_uint16(out, contents_size));
    RESULT_GUARD_POSIX(s2n_stuffer_write_uint8(out, 0x2a));
    RESULT_GUARD_POSIX(s2n_stuffer_write_uint16(out, 0x0020));
    RESULT_GUARD_POSIX(s2n_stuffer_write_uint16(out, 1));
    RESULT_GUARD_POSIX(s2n_stuffer_write_uint8(out, 0xa0));
    RESULT_GUARD_POSIX(s2n_stuffer_write_uint16(out, 4));
    RESULT_GUARD_POSIX(s2n_stuffer_write_uint16(out, 0x0001));
    RESULT_GUARD_POSIX(s2n_stuffer_write_uint16(out, 0x0001));
    RESULT_GUARD_POSIX(s2n_stuffer_write_uint8(out, 0));
    RESULT_GUARD_POSIX(s2n_stuffer_write_uint8(out, 1));
    RESULT_GUARD_POSIX(s2n_stuffer_write_uint8(out, 'a'));
    RESULT_GUARD_POSIX(s2n_stuffer_write_uint16(out, extensions_size));
    for (uint16_t i = 0; i < *extension_count; i++) {
        bool last = (i + 1 == *extension_count);
        RESULT_GUARD_POSIX(s2n_stuffer_write_uint16(out, (repeat_first && last) ? 0 : i));
        RESULT_GUARD_POSIX(s2n_stuffer_write_uint16(out, 0));
    }
    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* A malformed config is the application's error, not the peer's */
    {
        EXPECT_EQUAL(s2n_error_get_type(S2N_ERR_ECH_INVALID_CONFIG), S2N_ERR_T_USAGE);
        uint8_t alert = 0;
        EXPECT_FAILURE_WITH_ERRNO(s2n_error_get_alert(S2N_ERR_ECH_INVALID_CONFIG, &alert), S2N_ERR_NO_ALERT);
    };

    /*
     *= https://www.rfc-editor.org/rfc/rfc9849#section-4
     *= type=test
     *# The client-facing server advertises a sequence of ECH configurations
     *# to clients, serialized as follows.
     *#
     *#     ECHConfig ECHConfigList<4..2^16-1>;
     */
    {
        /* A single-config list parses into its fields, and `raw` holds the
         * whole ECHConfig */
        S2N_BLOB_FROM_HEX(list, "0042" TEST_ECH_CONFIG);
        S2N_BLOB_FROM_HEX(public_key, TEST_ECH_PUBLIC_KEY);

        DEFER_CLEANUP(struct s2n_array *configs = s2n_array_new(sizeof(struct s2n_ech_config)),
                s2n_array_free_p);
        EXPECT_NOT_NULL(configs);
        EXPECT_OK(s2n_ech_config_list_parse(&list, configs));

        uint32_t count = 0;
        EXPECT_OK(s2n_array_num_elements(configs, &count));
        EXPECT_EQUAL(count, 1);

        struct s2n_ech_config *config = NULL;
        EXPECT_OK(s2n_array_get(configs, 0, (void **) &config));
        EXPECT_EQUAL(config->raw.data, list.data + TEST_LIST_PREFIX_SIZE);
        EXPECT_EQUAL(config->raw.size, list.size - TEST_LIST_PREFIX_SIZE);
        EXPECT_EQUAL(config->config_id, 0x2a);
        EXPECT_EQUAL(config->kem_id, 0x0020);
        EXPECT_EQUAL(config->public_key.size, public_key.size);
        EXPECT_BYTEARRAY_EQUAL(config->public_key.data, public_key.data, public_key.size);
        EXPECT_EQUAL(config->cipher_suites.size, 8);
        EXPECT_EQUAL(config->maximum_name_length, 0);
        EXPECT_EQUAL(config->public_name.size, strlen("example.com"));
        EXPECT_BYTEARRAY_EQUAL(config->public_name.data, "example.com", strlen("example.com"));
        EXPECT_EQUAL(config->extensions.size, 0);
    };

    /* A non-zero maximum_name_length is parsed */
    {
        S2N_BLOB_FROM_HEX(list,
                "0042"
                "fe0d"
                "003e"
                "2a"
                "0020"
                "0020" TEST_ECH_PUBLIC_KEY "0008"
                "00010001"
                "00010003"
                "40" /* maximum_name_length */
                "0b"
                "6578616d706c652e636f6d"
                "0000");
        DEFER_CLEANUP(struct s2n_array *configs = s2n_array_new(sizeof(struct s2n_ech_config)),
                s2n_array_free_p);
        EXPECT_NOT_NULL(configs);
        EXPECT_OK(s2n_ech_config_list_parse(&list, configs));
        struct s2n_ech_config *config = NULL;
        EXPECT_OK(s2n_array_get(configs, 0, (void **) &config));
        EXPECT_EQUAL(config->maximum_name_length, 0x40);
    };

    /*
     *= https://www.rfc-editor.org/rfc/rfc9849#section-4
     *= type=test
     *# Clients MUST ignore any
     *# ECHConfig structure with a version they do not support.
     */
    {
        /* An ECHConfig with an unknown version is skipped, and the rest of
         * the list still parses. The unknown contents need not be a valid
         * ECHConfigContents. */
        S2N_BLOB_FROM_HEX(list,
                "004a"
                "fe0c" /* unknown version */
                "0004"
                "deadbeef" TEST_ECH_CONFIG);

        DEFER_CLEANUP(struct s2n_array *configs = s2n_array_new(sizeof(struct s2n_ech_config)),
                s2n_array_free_p);
        EXPECT_NOT_NULL(configs);
        EXPECT_OK(s2n_ech_config_list_parse(&list, configs));

        uint32_t count = 0;
        EXPECT_OK(s2n_array_num_elements(configs, &count));
        EXPECT_EQUAL(count, 1);

        struct s2n_ech_config *config = NULL;
        EXPECT_OK(s2n_array_get(configs, 0, (void **) &config));
        EXPECT_EQUAL(config->config_id, 0x2a);
        /* `raw` starts after the list length and the skipped 8-byte config */
        EXPECT_EQUAL(config->raw.data, list.data + TEST_LIST_PREFIX_SIZE + 8);
        EXPECT_EQUAL(config->raw.size, list.size - TEST_LIST_PREFIX_SIZE - 8);

        /* The smallest list, a single empty ECHConfig with an unknown
         * version, parses to no configs */
        S2N_BLOB_FROM_HEX(minimal_list, "0004"
                                        "fe0c"
                                        "0000");
        DEFER_CLEANUP(struct s2n_array *no_configs = s2n_array_new(sizeof(struct s2n_ech_config)),
                s2n_array_free_p);
        EXPECT_NOT_NULL(no_configs);
        EXPECT_OK(s2n_ech_config_list_parse(&minimal_list, no_configs));
        EXPECT_OK(s2n_array_num_elements(no_configs, &count));
        EXPECT_EQUAL(count, 0);
    };

    /*
     *= https://www.rfc-editor.org/rfc/rfc9849#section-4
     *= type=test
     *#         opaque public_name<1..255>;
     */
    {
        /* An empty public_name is rejected */
        {
            DEFER_CLEANUP(struct s2n_stuffer input = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, 0));
            EXPECT_OK(s2n_test_write_ech_config_list(&input, 0));
            struct s2n_blob list = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&list, input.blob.data, s2n_stuffer_data_available(&input)));

            DEFER_CLEANUP(struct s2n_array *configs = s2n_array_new(sizeof(struct s2n_ech_config)),
                    s2n_array_free_p);
            EXPECT_NOT_NULL(configs);
            EXPECT_ERROR_WITH_ERRNO(s2n_ech_config_list_parse(&list, configs), S2N_ERR_ECH_INVALID_CONFIG);
        };

        /* One-byte and 255-byte public_names parse */
        uint8_t public_name_sizes[] = { 1, UINT8_MAX };
        for (size_t i = 0; i < s2n_array_len(public_name_sizes); i++) {
            DEFER_CLEANUP(struct s2n_stuffer input = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, 0));
            EXPECT_OK(s2n_test_write_ech_config_list(&input, public_name_sizes[i]));
            struct s2n_blob list = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&list, input.blob.data, s2n_stuffer_data_available(&input)));

            DEFER_CLEANUP(struct s2n_array *configs = s2n_array_new(sizeof(struct s2n_ech_config)),
                    s2n_array_free_p);
            EXPECT_NOT_NULL(configs);
            EXPECT_OK(s2n_ech_config_list_parse(&list, configs));

            struct s2n_ech_config *config = NULL;
            EXPECT_OK(s2n_array_get(configs, 0, (void **) &config));
            EXPECT_EQUAL(config->public_name.size, public_name_sizes[i]);
            EXPECT_EQUAL(config->raw.size, list.size - TEST_LIST_PREFIX_SIZE);
        }
    };

    /* The parser is structural: it keeps configs whatever their KEM, cipher
     * suites, public_key length, or extensions, and leaves support to the
     * caller */
    {
        S2N_BLOB_FROM_HEX(list,
                "0108"
                /* DHKEM(P-256, HKDF-SHA256) */
                TEST_ECH_CONFIG_WITH("01", "0010", "00010001", "00010003")
                /* Only HKDF-SHA384 suites, and an unknown AEAD */
                TEST_ECH_CONFIG_WITH("02", "0020", "00020001", "00010004")
                /* An X25519 public_key of 31 bytes */
                "fe0d"
                "0039"
                "03"
                "0020"
                "001f"
                "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbe"
                "0004"
                "00010001"
                "00"
                "0b"
                "6578616d706c652e636f6d"
                "0000"
                /* A mandatory extension */
                "fe0d"
                "0043"
                "04"
                "0020"
                "0020" TEST_ECH_PUBLIC_KEY "0008"
                "00010001"
                "00010003"
                "00"
                "0b"
                "6578616d706c652e636f6d"
                "0005"
                "8001"
                "0001"
                "00");

        DEFER_CLEANUP(struct s2n_array *configs = s2n_array_new(sizeof(struct s2n_ech_config)),
                s2n_array_free_p);
        EXPECT_NOT_NULL(configs);
        EXPECT_OK(s2n_ech_config_list_parse(&list, configs));

        uint32_t count = 0;
        EXPECT_OK(s2n_array_num_elements(configs, &count));
        EXPECT_EQUAL(count, 4);
        for (uint32_t i = 0; i < count; i++) {
            struct s2n_ech_config *config = NULL;
            EXPECT_OK(s2n_array_get(configs, i, (void **) &config));
            EXPECT_EQUAL(config->config_id, i + 1);
        }
    };

    /* A config's cipher suites can be read one at a time */
    {
        S2N_BLOB_FROM_HEX(list, "0042" TEST_ECH_CONFIG_WITH("01", "0020", "00010002", "00020003"));
        DEFER_CLEANUP(struct s2n_array *configs = s2n_array_new(sizeof(struct s2n_ech_config)),
                s2n_array_free_p);
        EXPECT_NOT_NULL(configs);
        EXPECT_OK(s2n_ech_config_list_parse(&list, configs));
        struct s2n_ech_config *config = NULL;
        EXPECT_OK(s2n_array_get(configs, 0, (void **) &config));

        uint16_t count = 0;
        EXPECT_OK(s2n_ech_config_get_cipher_suite_count(config, &count));
        EXPECT_EQUAL(count, 2);

        uint16_t kdf_id = 0;
        uint16_t aead_id = 0;
        EXPECT_OK(s2n_ech_config_get_cipher_suite(config, 0, &kdf_id, &aead_id));
        EXPECT_EQUAL(kdf_id, 0x0001);
        EXPECT_EQUAL(aead_id, 0x0002);
        EXPECT_OK(s2n_ech_config_get_cipher_suite(config, 1, &kdf_id, &aead_id));
        EXPECT_EQUAL(kdf_id, 0x0002);
        EXPECT_EQUAL(aead_id, 0x0003);
        EXPECT_ERROR_WITH_ERRNO(s2n_ech_config_get_cipher_suite(config, 2, &kdf_id, &aead_id),
                S2N_ERR_INVALID_ARGUMENT);
    };

    /* A mandatory extension is one whose type has the high bit set, wherever
     * it appears */
    {
        struct {
            const char *extensions;
            bool mandatory;
        } cases[] = {
            { .extensions = "7fff"
                            "0000",
                    .mandatory = false },
            { .extensions = "1234"
                            "0000"
                            "8000"
                            "0001"
                            "00",
                    .mandatory = true },
        };
        for (size_t i = 0; i < s2n_array_len(cases); i++) {
            S2N_BLOB_FROM_HEX(extensions, cases[i].extensions);
            struct s2n_ech_config config = { .extensions = extensions };
            bool mandatory = !cases[i].mandatory;
            EXPECT_OK(s2n_ech_config_has_mandatory_extension(&config, &mandatory));
            EXPECT_EQUAL(mandatory, cases[i].mandatory);
        }

        struct s2n_ech_config no_extensions = { 0 };
        bool mandatory = true;
        EXPECT_OK(s2n_ech_config_has_mandatory_extension(&no_extensions, &mandatory));
        EXPECT_FALSE(mandatory);
    };

    /*
     *= https://www.rfc-editor.org/rfc/rfc9849#section-4
     *= type=test
     *#     struct {
     *#         ECHConfigExtensionType type;
     *#         opaque data<0..2^16-1>;
     *#     } ECHConfigExtension;
     */
    {
        /* Well-formed extensions are kept as they appear on the wire */
        S2N_BLOB_FROM_HEX(list,
                "004f"
                "fe0d"
                "004b" TEST_ECH_CONFIG_CONTENTS_BEFORE_EXTENSIONS
                "000d" /* extensions length */
                "1234"
                "0000" /* empty extension */
                "7ffe"
                "0005"
                "0102030405");
        S2N_BLOB_FROM_HEX(extensions, "1234"
                                      "0000"
                                      "7ffe"
                                      "0005"
                                      "0102030405");

        DEFER_CLEANUP(struct s2n_array *configs = s2n_array_new(sizeof(struct s2n_ech_config)),
                s2n_array_free_p);
        EXPECT_NOT_NULL(configs);
        EXPECT_OK(s2n_ech_config_list_parse(&list, configs));
        struct s2n_ech_config *config = NULL;
        EXPECT_OK(s2n_array_get(configs, 0, (void **) &config));
        EXPECT_EQUAL(config->extensions.size, extensions.size);
        EXPECT_BYTEARRAY_EQUAL(config->extensions.data, extensions.data, extensions.size);

        /* Malformed extensions are rejected */
        const char *malformed_lists[] = {
            /* An extension with only part of its type */
            "0043"
            "fe0d"
            "003f" TEST_ECH_CONFIG_CONTENTS_BEFORE_EXTENSIONS "0001"
            "12",
            /* An extension with no data length */
            "0044"
            "fe0d"
            "0040" TEST_ECH_CONFIG_CONTENTS_BEFORE_EXTENSIONS "0002"
            "1234",
            /* An extension whose data is shorter than its length */
            "0047"
            "fe0d"
            "0043" TEST_ECH_CONFIG_CONTENTS_BEFORE_EXTENSIONS "0005"
            "1234"
            "0002"
            "01",
        };
        for (size_t i = 0; i < s2n_array_len(malformed_lists); i++) {
            S2N_BLOB_FROM_HEX(malformed, malformed_lists[i]);
            DEFER_CLEANUP(struct s2n_array *malformed_configs = s2n_array_new(sizeof(struct s2n_ech_config)),
                    s2n_array_free_p);
            EXPECT_NOT_NULL(malformed_configs);
            EXPECT_ERROR_WITH_ERRNO(s2n_ech_config_list_parse(&malformed, malformed_configs),
                    S2N_ERR_ECH_INVALID_CONFIG);
        }

        /* Reading a malformed extension list fails */
        S2N_BLOB_FROM_HEX(malformed_extensions, "1234"
                                                "0002"
                                                "01");
        struct s2n_ech_config malformed_config = { .extensions = malformed_extensions };
        bool mandatory = false;
        EXPECT_ERROR_WITH_ERRNO(s2n_ech_config_has_mandatory_extension(&malformed_config, &mandatory),
                S2N_ERR_ECH_INVALID_CONFIG);
    };

    /*
     *= https://www.rfc-editor.org/rfc/rfc9849#section-4.2
     *= type=test
     *# ECH configuration extensions follow the same interpretation rules as
     *# TLS extensions: extensions MAY appear in any order, but there MUST
     *# NOT be more than one extension of the same type in the extensions
     *# block.
     */
    {
        /* Two extensions of the same type are rejected, even when not adjacent */
        {
            S2N_BLOB_FROM_HEX(list,
                    "004e"
                    "fe0d"
                    "004a" TEST_ECH_CONFIG_CONTENTS_BEFORE_EXTENSIONS
                    "000c" /* extensions length */
                    "1234"
                    "0000"
                    "5678"
                    "0000"
                    "1234"
                    "0000");
            DEFER_CLEANUP(struct s2n_array *configs = s2n_array_new(sizeof(struct s2n_ech_config)),
                    s2n_array_free_p);
            EXPECT_NOT_NULL(configs);
            EXPECT_ERROR_WITH_ERRNO(s2n_ech_config_list_parse(&list, configs), S2N_ERR_ECH_INVALID_CONFIG);
        };

        /* Two configs may each use the same extension type */
        {
            S2N_BLOB_FROM_HEX(list,
                    "008c"
                    "fe0d"
                    "0042" TEST_ECH_CONFIG_CONTENTS_BEFORE_EXTENSIONS
                    "0004"
                    "1234"
                    "0000"
                    "fe0d"
                    "0042" TEST_ECH_CONFIG_CONTENTS_BEFORE_EXTENSIONS
                    "0004"
                    "1234"
                    "0000");
            DEFER_CLEANUP(struct s2n_array *configs = s2n_array_new(sizeof(struct s2n_ech_config)),
                    s2n_array_free_p);
            EXPECT_NOT_NULL(configs);
            EXPECT_OK(s2n_ech_config_list_parse(&list, configs));
            uint32_t count = 0;
            EXPECT_OK(s2n_array_num_elements(configs, &count));
            EXPECT_EQUAL(count, 2);
        };

        /* The most extensions that fit in a list, each a different type,
         * parse; repeating the first type in the last one is rejected */
        bool repeat_first[] = { false, true };
        for (size_t i = 0; i < s2n_array_len(repeat_first); i++) {
            DEFER_CLEANUP(struct s2n_stuffer input = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, 0));
            uint16_t extension_count = 0;
            EXPECT_OK(s2n_test_write_max_extensions_list(&input, &extension_count, repeat_first[i]));
            EXPECT_EQUAL(extension_count, 16378);
            EXPECT_TRUE(s2n_stuffer_data_available(&input) <= TEST_LIST_PREFIX_SIZE + UINT16_MAX);
            struct s2n_blob list = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&list, input.blob.data, s2n_stuffer_data_available(&input)));

            DEFER_CLEANUP(struct s2n_array *configs = s2n_array_new(sizeof(struct s2n_ech_config)),
                    s2n_array_free_p);
            EXPECT_NOT_NULL(configs);
            if (repeat_first[i]) {
                EXPECT_ERROR_WITH_ERRNO(s2n_ech_config_list_parse(&list, configs), S2N_ERR_ECH_INVALID_CONFIG);
            } else {
                EXPECT_OK(s2n_ech_config_list_parse(&list, configs));
                struct s2n_ech_config *config = NULL;
                EXPECT_OK(s2n_array_get(configs, 0, (void **) &config));
                EXPECT_EQUAL(config->extensions.size, extension_count * 4);
            }
        }
    };

    /* Malformed lists are rejected */
    {
        const char *malformed_lists[] = {
            /* An empty ECHConfigList */
            "0000",
            /* An ECHConfigList shorter than the minimum of four bytes */
            "0003"
            "fe0d"
            "00",
            /* Trailing bytes after the ECHConfigList */
            "0042" TEST_ECH_CONFIG "00",
            /* Trailing bytes after the last ECHConfig, inside the list */
            "0043" TEST_ECH_CONFIG "00",
            /* Trailing bytes inside the ECHConfigContents */
            "0043"
            "fe0d"
            "003f" TEST_ECH_CONFIG_CONTENTS "00",
            /* An empty public_key */
            "001e"
            "fe0d"
            "001a"
            "2a"
            "0020"
            "0000"
            "0004"
            "00010001"
            "00"
            "0b"
            "6578616d706c652e636f6d"
            "0000",
            /* Empty cipher_suites */
            "003a"
            "fe0d"
            "0036"
            "2a"
            "0020"
            "0020" TEST_ECH_PUBLIC_KEY "0000"
            "00"
            "0b"
            "6578616d706c652e636f6d"
            "0000",
            /* cipher_suites that are not a whole number of HpkeSymmetricCipherSuites */
            "0040"
            "fe0d"
            "003c"
            "2a"
            "0020"
            "0020" TEST_ECH_PUBLIC_KEY "0006"
            "00010001"
            "0001"
            "00"
            "0b"
            "6578616d706c652e636f6d"
            "0000",
        };
        for (size_t i = 0; i < s2n_array_len(malformed_lists); i++) {
            S2N_BLOB_FROM_HEX(list, malformed_lists[i]);
            DEFER_CLEANUP(struct s2n_array *configs = s2n_array_new(sizeof(struct s2n_ech_config)),
                    s2n_array_free_p);
            EXPECT_NOT_NULL(configs);
            EXPECT_ERROR_WITH_ERRNO(s2n_ech_config_list_parse(&list, configs), S2N_ERR_ECH_INVALID_CONFIG);
        }

        /* A malformed config after a valid one fails the whole list, unlike
         * a config with an unknown version, and restores `configs` */
        {
            S2N_BLOB_FROM_HEX(valid_list, "0042" TEST_ECH_CONFIG);
            S2N_BLOB_FROM_HEX(partly_valid_list,
                    "0047" TEST_ECH_CONFIG
                    "fe0d"
                    "0001"
                    "00");
            DEFER_CLEANUP(struct s2n_array *configs = s2n_array_new(sizeof(struct s2n_ech_config)),
                    s2n_array_free_p);
            EXPECT_NOT_NULL(configs);
            EXPECT_OK(s2n_ech_config_list_parse(&valid_list, configs));
            EXPECT_ERROR_WITH_ERRNO(s2n_ech_config_list_parse(&partly_valid_list, configs),
                    S2N_ERR_ECH_INVALID_CONFIG);

            uint32_t count = 0;
            EXPECT_OK(s2n_array_num_elements(configs, &count));
            EXPECT_EQUAL(count, 1);
            struct s2n_ech_config *config = NULL;
            EXPECT_OK(s2n_array_get(configs, 0, (void **) &config));
            EXPECT_EQUAL(config->public_key.data,
                    valid_list.data + TEST_LIST_PREFIX_SIZE + TEST_CONFIG_HEADER_SIZE + TEST_CONTENTS_PUBLIC_KEY_OFFSET);
        };

        /* Every truncation of a valid list is rejected */
        S2N_BLOB_FROM_HEX(list, "0042" TEST_ECH_CONFIG);
        for (uint32_t size = 0; size < list.size; size++) {
            struct s2n_blob truncated = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&truncated, list.data, size));
            DEFER_CLEANUP(struct s2n_array *configs = s2n_array_new(sizeof(struct s2n_ech_config)),
                    s2n_array_free_p);
            EXPECT_NOT_NULL(configs);
            EXPECT_ERROR_WITH_ERRNO(s2n_ech_config_list_parse(&truncated, configs), S2N_ERR_ECH_INVALID_CONFIG);
        }

        /* Every truncation of a config's contents is rejected, with the list
         * and config lengths rewritten to match, so each cut reaches the
         * field it falls in */
        S2N_BLOB_FROM_HEX(contents, TEST_ECH_CONFIG_CONTENTS);
        for (uint32_t size = 0; size < contents.size; size++) {
            DEFER_CLEANUP(struct s2n_stuffer input = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, 0));
            EXPECT_OK(s2n_test_write_truncated_config(&input, &contents, size));
            struct s2n_blob truncated = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&truncated, input.blob.data, s2n_stuffer_data_available(&input)));
            DEFER_CLEANUP(struct s2n_array *configs = s2n_array_new(sizeof(struct s2n_ech_config)),
                    s2n_array_free_p);
            EXPECT_NOT_NULL(configs);
            EXPECT_ERROR_WITH_ERRNO(s2n_ech_config_list_parse(&truncated, configs), S2N_ERR_ECH_INVALID_CONFIG);
        }
    };

    /* An array of the wrong element type is refused */
    {
        S2N_BLOB_FROM_HEX(list, "0042" TEST_ECH_CONFIG);
        DEFER_CLEANUP(struct s2n_array *configs = s2n_array_new(sizeof(uint8_t)), s2n_array_free_p);
        EXPECT_NOT_NULL(configs);
        EXPECT_ERROR_WITH_ERRNO(s2n_ech_config_list_parse(&list, configs), S2N_ERR_SAFETY);
    };

    END_TEST();
}
