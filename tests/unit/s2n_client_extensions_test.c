/*
 * Copyright 2015 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include "s2n_test.h"

#include <sys/wait.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>

#include <s2n.h>

#include "tls/s2n_connection.h"
#include "tls/s2n_handshake.h"

#define ZERO_TO_THIRTY_ONE  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, \
                            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F

static char certificate[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDLjCCAhYCCQDL1lr6N8/gvzANBgkqhkiG9w0BAQUFADBZMQswCQYDVQQGEwJB\n"
    "VTETMBEGA1UECBMKU29tZS1TdGF0ZTEhMB8GA1UEChMYSW50ZXJuZXQgV2lkZ2l0\n"
    "cyBQdHkgTHRkMRIwEAYDVQQDEwlsb2NhbGhvc3QwHhcNMTQwNTEwMTcwODIzWhcN\n"
    "MjQwNTA3MTcwODIzWjBZMQswCQYDVQQGEwJBVTETMBEGA1UECBMKU29tZS1TdGF0\n"
    "ZTEhMB8GA1UEChMYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMRIwEAYDVQQDEwls\n"
    "b2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDIltaUmHg+\n"
    "G7Ida2XCtEQx1YeWDX41U2zBKbY0lT+auXf81cT3dYTdfJblb+v4CTWaGNofogcz\n"
    "ebm8B2/OF9F+WWkKAJhKsTPAE7/SNAdi4Eqv4FfNbWKkGb4xacxxb4PH2XP9V3Ch\n"
    "J6lMSI3V68FmEf4kcEN14V8vufIC5HE/LT4gCPDJ4UfUUbAgEhSebT6r/KFYB5T3\n"
    "AeDc1VdnaaRblrP6KwM45vTs0Ii09/YrlzBxaTPMjLGCKa8JMv8PW2R0U9WCqHmz\n"
    "BH+W3Q9xPrfhCInm4JWob8WgM1NuiYuzFB0CNaQcdMS7h0aZEAVnayhQ96/Padpj\n"
    "KNE0Lur9nUxbAgMBAAEwDQYJKoZIhvcNAQEFBQADggEBAGRV71uRt/1dADsMD9fg\n"
    "JvzW89jFAN87hXCRhTWxfXhYMzknxJ5WMb2JAlaMc/gTpiDiQBkbvB+iJe5AepgQ\n"
    "WbyxPJNtSlA9GfKBz1INR5cFsOL27VrBoMYHMaolveeslc1AW2HfBtXWXeWSEF7F\n"
    "QNgye8ZDPNzeSWSI0VyK2762wsTgTuUhHAaJ45660eX57+e8IvaM7xOEfBPDKYtU\n"
    "0a28ZuhvSr2akJtGCwcs2J6rs6I+rV84UktDxFC9LUezBo8D9FkMPLoPKKNH1dXR\n"
    "6LO8GOkqWUrhPIEmfy9KYes3q2ZX6svk4rwBtommHRv30kPxnnU1YXt52Ri+XczO\n"
    "wEs=\n"
    "-----END CERTIFICATE-----\n";

static char private_key[] =
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEpAIBAAKCAQEAyJbWlJh4PhuyHWtlwrREMdWHlg1+NVNswSm2NJU/mrl3/NXE\n"
    "93WE3XyW5W/r+Ak1mhjaH6IHM3m5vAdvzhfRfllpCgCYSrEzwBO/0jQHYuBKr+BX\n"
    "zW1ipBm+MWnMcW+Dx9lz/VdwoSepTEiN1evBZhH+JHBDdeFfL7nyAuRxPy0+IAjw\n"
    "yeFH1FGwIBIUnm0+q/yhWAeU9wHg3NVXZ2mkW5az+isDOOb07NCItPf2K5cwcWkz\n"
    "zIyxgimvCTL/D1tkdFPVgqh5swR/lt0PcT634QiJ5uCVqG/FoDNTbomLsxQdAjWk\n"
    "HHTEu4dGmRAFZ2soUPevz2naYyjRNC7q/Z1MWwIDAQABAoIBAHrkryLrJwAmR8Hu\n"
    "grH/b6h4glFUgvZ43jCaNZ+RsR5Cc1jcP4i832Izat+26oNUYRrADyNCSdcnxLuG\n"
    "cuF5hkg6zzfplWRtnJ8ZenR2m+/gKuIGOMULN1wCyZvMjg0RnVNbzsxwPfj+K6Mo\n"
    "8H0Xq621aFc60JnwMjkzWyqaeyeQogn1pqybuL6Dm2huvN49LR64uHuDUStTRX33\n"
    "ou1fVWXOJ1kealYPbRPj8pDa31omB8q5Cf8Qe/b9anqyi9CsP17QbVg9k2IgoLlj\n"
    "agqOc0u/opOTZB4tqJbqsIdEhc5LD5RUkYJsw00Iq0RSiKTfiWSPyOFw99Y9Act0\n"
    "cbIIxEECgYEA8/SOsQjoUX1ipRvPbfO3suV1tU1hLCQbIpv7WpjNr1kHtngjzQMP\n"
    "dU/iriUPGF1H+AxJJcJQfCVThV1AwFYVKb/LCrjaxlneZSbwfehpjo+xQGaNYG7Q\n"
    "1vQuBVejuYk/IvpZltQOdm838DjvYyWDMh4dcMFIycXxEg+oHxf/s+8CgYEA0n4p\n"
    "GBuLUNx9vv3e84BcarLaOF7wY7tb8z2oC/mXztMZpKjovTH0PvePgI5/b3KQ52R0\n"
    "8zXHVX/4lSQVtCuhOVwKOCQq97/Zhlp5oTTShdQ0Qa1GQRl5wbTS6hrYEWSi9AQP\n"
    "BVUPZ+RIcxx00DfBNURkId8xEpvCOmvySN8sUlUCgYAtXmHbEqkB3qulwRJGhHi5\n"
    "UGsfmJBlwSE6wn9wTdKStZ/1k0o1KkiJrJ2ffUzdXxuvSbmgyA5nyBlMSBdurZOp\n"
    "+/0qtU4abUQq058OC1b2KEryix/nuzQjha25WJ8eNiQDwUNABZfa9rwUdMIwUh2g\n"
    "CHG5Mnjy7Vjz3u2JOtFXCQKBgQCVRo1EIHyLauLuaMINM9HWhWJGqeWXBM8v0GD1\n"
    "pRsovQKpiHQNgHizkwM861GqqrfisZZSyKfFlcynkACoVmyu7fv9VoD2VCMiqdUq\n"
    "IvjNmfE5RnXVQwja+668AS+MHi+GF77DTFBxoC5VHDAnXfLyIL9WWh9GEBoNLnKT\n"
    "hVm8RQKBgQCB9Skzdftc+14a4Vj3NCgdHZHz9mcdPhzJXUiQyZ3tYhaytX9E8mWq\n"
    "pm/OFqahbxw6EQd86mgANBMKayD6B1Id1INqtXN1XYI50bSs1D2nOGsBM7MK9aWD\n"
    "JXlJ2hwsIc4q9En/LR3GtBaL84xTHGfznNylNhXi7GbO1wNMJuAukA==\n"
    "-----END RSA PRIVATE KEY-----\n";

int main(int argc, char **argv)
{
    BEGIN_TEST();

    EXPECT_SUCCESS(setenv("S2N_ENABLE_INSECURE_CLIENT", "1", 0));
    EXPECT_SUCCESS(s2n_init());

    /* Client doens't use the server name extension. */
    {
        struct s2n_connection *client_conn;
        struct s2n_connection *server_conn;
        struct s2n_config *server_config;
        int client_more;
        int server_more;
        int server_to_client[2];
        int client_to_server[2];

        /* Create nonblocking pipes */
        EXPECT_SUCCESS(pipe(server_to_client));
        EXPECT_SUCCESS(pipe(client_to_server));
        for (int i = 0; i < 2; i++) {
           EXPECT_NOT_EQUAL(fcntl(server_to_client[i], F_SETFL, fcntl(server_to_client[i], F_GETFL) | O_NONBLOCK), -1);
           EXPECT_NOT_EQUAL(fcntl(client_to_server[i], F_SETFL, fcntl(client_to_server[i], F_GETFL) | O_NONBLOCK), -1);
        }

        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_read_fd(client_conn, server_to_client[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(client_conn, client_to_server[1]));

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_read_fd(server_conn, client_to_server[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(server_conn, server_to_client[1]));

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key(server_config, certificate, private_key));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        do {
            int ret;
            ret = s2n_negotiate(client_conn, &client_more);
            EXPECT_TRUE(ret == 0 || client_more);
            ret = s2n_negotiate(server_conn, &server_more);
            EXPECT_TRUE(ret == 0 || server_more);
        } while (client_more || server_more);

        /* Verify that the server didn't receive the server name. */
        EXPECT_NULL(s2n_get_server_name(server_conn));

        EXPECT_SUCCESS(s2n_shutdown(client_conn, &client_more));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_shutdown(server_conn, &server_more));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));

        EXPECT_SUCCESS(s2n_config_free(server_config));

        for (int i = 0; i < 2; i++) {
           EXPECT_SUCCESS(close(server_to_client[i]));
           EXPECT_SUCCESS(close(client_to_server[i]));
        }
    }

    /* Client uses the server name extension. */
    {
        struct s2n_connection *client_conn;
        struct s2n_connection *server_conn;
        struct s2n_config *server_config;
        int client_more;
        int server_more;
        int server_to_client[2];
        int client_to_server[2];

        const char *sent_server_name = "awesome.amazonaws.com";
        const char *received_server_name;

        /* Create nonblocking pipes */
        EXPECT_SUCCESS(pipe(server_to_client));
        EXPECT_SUCCESS(pipe(client_to_server));
        for (int i = 0; i < 2; i++) {
            EXPECT_NOT_EQUAL(fcntl(server_to_client[i], F_SETFL, fcntl(server_to_client[i], F_GETFL) | O_NONBLOCK), -1);
            EXPECT_NOT_EQUAL(fcntl(client_to_server[i], F_SETFL, fcntl(client_to_server[i], F_GETFL) | O_NONBLOCK), -1);
        }

        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_read_fd(client_conn, server_to_client[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(client_conn, client_to_server[1]));

        /* Set the server name */
        EXPECT_SUCCESS(s2n_set_server_name(client_conn, sent_server_name));

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_read_fd(server_conn, client_to_server[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(server_conn, server_to_client[1]));

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key(server_config, certificate, private_key));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        do {
            int ret;
            ret = s2n_negotiate(client_conn, &client_more);
            EXPECT_TRUE(ret == 0 || client_more);
            ret = s2n_negotiate(server_conn, &server_more);
            EXPECT_TRUE(ret == 0 || server_more);
        } while (client_more || server_more);

        /* Verify that the server name was received intact. */
        EXPECT_NOT_NULL(received_server_name = s2n_get_server_name(server_conn));
        EXPECT_EQUAL(strlen(received_server_name), strlen(sent_server_name));
        EXPECT_BYTEARRAY_EQUAL(received_server_name, sent_server_name, strlen(received_server_name));

        EXPECT_SUCCESS(s2n_shutdown(client_conn, &client_more));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_shutdown(server_conn, &server_more));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));

        EXPECT_SUCCESS(s2n_config_free(server_config));
        for (int i = 0; i < 2; i++) {
            EXPECT_SUCCESS(close(server_to_client[i]));
            EXPECT_SUCCESS(close(client_to_server[i]));
        }
    }

    /* Client sends multiple server names. */
    {
        struct s2n_connection *server_conn;
        struct s2n_config *server_config;
        int server_more;
        int server_to_client[2];
        int client_to_server[2];
        const char *sent_server_name = "svr";
        const char *received_server_name;

        uint8_t client_extensions[] = {
            /* Extension type TLS_EXTENSION_SERVER_NAME */
            0x00, 0x00,
            /* Extension size */
            0x00, 0x0C,
            /* All server names len */
            0x00, 0x0A,
            /* First server name type - host name */
            0x00,
            /* First server name len */
            0x00, 0x03,
            /* First server name, matches sent_server_name */
            's', 'v', 'r',
            /* Second server name type - host name */
            0x00,
            /* Second server name len */
            0x00, 0x01,
            /* Second server name */
            0xFF,
        };
        int client_extensions_len = sizeof(client_extensions);
        uint8_t client_hello_message[] = {
            /* Protocol version TLS 1.2 */
            0x03, 0x03,
            /* Client random */
            ZERO_TO_THIRTY_ONE,
            /* SessionID len - 32 bytes */
            0x20,
            /* Session ID */
            ZERO_TO_THIRTY_ONE,
            /* Cipher suites len */
            0x00, 0x02,
            /* Cipher suite - TLS_RSA_WITH_AES_128_CBC_SHA256 */
            0x00, 0x3C,
            /* Compression methods len */
            0x01,
            /* Compression method - none */
            0x00,
            /* Extensions len */
            (client_extensions_len >> 8) & 0xff, (client_extensions_len & 0xff),
        };
        int body_len = sizeof(client_hello_message) + client_extensions_len;
        uint8_t message_header[] = {
            /* Handshake message type CLIENT HELLO */
            0x01,
            /* Body len */
            (body_len >> 16) & 0xff, (body_len >> 8) & 0xff, (body_len & 0xff),
        };
        int message_len = sizeof(message_header) + body_len;
        uint8_t record_header[] = {
            /* Record type HANDSHAKE */
            0x16,
            /* Protocol version TLS 1.2 */
            0x03, 0x03,
            /* Message len */
            (message_len >> 8) & 0xff, (message_len & 0xff),
        };

        /* Create nonblocking pipes */
        EXPECT_SUCCESS(pipe(server_to_client));
        EXPECT_SUCCESS(pipe(client_to_server));
        for (int i = 0; i < 2; i++) {
            EXPECT_NOT_EQUAL(fcntl(server_to_client[i], F_SETFL, fcntl(server_to_client[i], F_GETFL) | O_NONBLOCK), -1);
            EXPECT_NOT_EQUAL(fcntl(client_to_server[i], F_SETFL, fcntl(client_to_server[i], F_GETFL) | O_NONBLOCK), -1);
        }

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_read_fd(server_conn, client_to_server[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(server_conn, server_to_client[1]));

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key(server_config, certificate, private_key));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        /* Send the client hello */
        EXPECT_EQUAL(write(client_to_server[1], record_header, sizeof(record_header)), sizeof(record_header));
        EXPECT_EQUAL(write(client_to_server[1], message_header, sizeof(message_header)), sizeof(message_header));
        EXPECT_EQUAL(write(client_to_server[1], client_hello_message, sizeof(client_hello_message)), sizeof(client_hello_message));
        EXPECT_EQUAL(write(client_to_server[1], client_extensions, sizeof(client_extensions)), sizeof(client_extensions));

        /* Verify that the CLIENT HELLO is accepted */
        s2n_negotiate(server_conn, &server_more);
        EXPECT_EQUAL(server_more, 1);
        EXPECT_EQUAL(server_conn->handshake.state, CLIENT_KEY);

        /* Verify that the server name was received intact. */
        EXPECT_NOT_NULL(received_server_name = s2n_get_server_name(server_conn));
        EXPECT_EQUAL(strlen(received_server_name), strlen(sent_server_name));
        EXPECT_BYTEARRAY_EQUAL(received_server_name, sent_server_name, strlen(received_server_name));

        EXPECT_SUCCESS(s2n_shutdown(server_conn, &server_more));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));

        EXPECT_SUCCESS(s2n_config_free(server_config));
        for (int i = 0; i < 2; i++) {
            EXPECT_SUCCESS(close(server_to_client[i]));
            EXPECT_SUCCESS(close(client_to_server[i]));
        }
    }

    END_TEST();
    return 0;
}

