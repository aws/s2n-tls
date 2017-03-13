/*
 * Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <sys/poll.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>

#include <s2n.h>

#include "utils/s2n_random.h"

#include "tls/s2n_connection.h"
#include "tls/s2n_handshake.h"

#define MAX_BUF_SIZE 10000

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

static char dhparams[] =
    "-----BEGIN DH PARAMETERS-----\n"
    "MIIBCAKCAQEAy1+hVWCfNQoPB+NA733IVOONl8fCumiz9zdRRu1hzVa2yvGseUSq\n"
    "Bbn6k0FQ7yMED6w5XWQKDC0z2m0FI/BPE3AjUfuPzEYGqTDf9zQZ2Lz4oAN90Sud\n"
    "luOoEhYR99cEbCn0T4eBvEf9IUtczXUZ/wj7gzGbGG07dLfT+CmCRJxCjhrosenJ\n"
    "gzucyS7jt1bobgU66JKkgMNm7hJY4/nhR5LWTCzZyzYQh2HM2Vk4K5ZqILpj/n0S\n"
    "5JYTQ2PVhxP+Uu8+hICs/8VvM72DznjPZzufADipjC7CsQ4S6x/ecZluFtbb+ZTv\n"
    "HI5CnYmkAwJ6+FSWGaZQDi8bgerFk9RWwwIBAg==\n"
    "-----END DH PARAMETERS-----\n";

int buffer_read(void *io_context, uint8_t *buf, uint32_t len)
{
    struct s2n_stuffer *in_buf;
    int n_read, n_avail;
    
    if (buf == NULL) {
        return 0;
    }

    in_buf = (struct s2n_stuffer *) io_context;
    if (in_buf == NULL) {
        errno = EINVAL;
        return -1;
    }
   
    // read the number of bytes requested or less if it isn't available
    n_avail = s2n_stuffer_data_available(in_buf);
    n_read = (len < n_avail) ? len : n_avail;

    if (n_read == 0) {
        errno = EAGAIN;
        return -1;
    }

    s2n_stuffer_read_bytes(in_buf, buf, n_read);
    return n_read;
}

int buffer_write(void *io_context, const uint8_t *buf, uint32_t len)
{
    struct s2n_stuffer *out;

    if (buf == NULL) {
        return 0;
    }
    
    out = (struct s2n_stuffer *) io_context;
    if (out == NULL) {
        errno = EINVAL;
        return -1;
    }

    if (s2n_stuffer_write_bytes(out, buf, len) < 0) {
        errno = EAGAIN;
        return -1;
    }

    return len;
}

int mock_client(int writefd, int readfd)
{
    struct s2n_connection *conn;
    struct s2n_config *config;
    s2n_blocked_status blocked;
    int result = 0;

    conn = s2n_connection_new(S2N_CLIENT);
    config = s2n_config_new();
    s2n_connection_set_config(conn, config);

    // Unlike the server, the client just passes ownership of I/O to s2n
    s2n_connection_set_read_fd(conn, readfd);
    s2n_connection_set_write_fd(conn, writefd);

    result = s2n_negotiate(conn, &blocked);
    if (result < 0) {
        _exit(1);
    }

    s2n_shutdown(conn, &blocked);
    s2n_connection_free(conn);
    s2n_config_free(config);
    s2n_cleanup();

    _exit(0);
}

/**
 * This test creates a server, client, and a pair of pipes. The client uses the
 * pipes directly for I/O in s2n. The server copies data from the pipes into
 * stuffers and manages s2n I/O with a set of I/O callbacks that read and write
 * from the stuffers. 
 */
int main(int argc, char **argv)
{
    struct s2n_connection *conn;
    struct s2n_config *config;
    s2n_blocked_status blocked;
    int status;
    pid_t pid;
    int server_to_client[2];
    int client_to_server[2];
   
    struct s2n_stuffer in, out;

    BEGIN_TEST();

    EXPECT_SUCCESS(setenv("S2N_ENABLE_CLIENT_MODE", "1", 0));

    EXPECT_NOT_NULL(config = s2n_config_new());
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key(config, certificate, private_key));
    EXPECT_SUCCESS(s2n_config_add_dhparams(config, dhparams));

    /* Create a pipe */
    EXPECT_SUCCESS(pipe(server_to_client));
    EXPECT_SUCCESS(pipe(client_to_server));

    /* Create a child process */
    pid = fork();
    if (pid == 0) {
        /* This is the child process, close the read end of the pipe */
        EXPECT_SUCCESS(close(client_to_server[0]));
        EXPECT_SUCCESS(close(server_to_client[1]));

        /* Run the client */
        mock_client(client_to_server[1], server_to_client[0]);
    }

    /* This is the parent, close the write end of the pipe */
    EXPECT_SUCCESS(close(client_to_server[1]));
    EXPECT_SUCCESS(close(server_to_client[0]));

    EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
    EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

    EXPECT_FAILURE(s2n_connection_use_corked_io(conn));

    /* Set up our I/O callbacks. Use stuffers for the "I/O context" */
    EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&in, 0));
    EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&out, 0));

    EXPECT_SUCCESS(s2n_connection_set_recv_cb(conn, &buffer_read));
    EXPECT_SUCCESS(s2n_connection_set_send_cb(conn, &buffer_write));
    EXPECT_SUCCESS(s2n_connection_set_recv_ctx(conn, &in));
    EXPECT_SUCCESS(s2n_connection_set_send_ctx(conn, &out));
    
    /* Make our pipes non-blocking */
    EXPECT_NOT_EQUAL(fcntl(client_to_server[0], F_SETFL, fcntl(client_to_server[0], F_GETFL) | O_NONBLOCK), -1);
    EXPECT_NOT_EQUAL(fcntl(server_to_client[1], F_SETFL, fcntl(server_to_client[1], F_GETFL) | O_NONBLOCK), -1);

    /* Negotiate the handshake. */
    do {
        int ret;
        
        ret = s2n_negotiate(conn, &blocked);
        EXPECT_TRUE(ret == 0 || (blocked && (errno == EAGAIN || errno == EWOULDBLOCK)));
        
        // check to see if we need to copy more over from the pipes to the buffers
        // to continue the handshake
        s2n_stuffer_recv_from_fd(&in, client_to_server[0], MAX_BUF_SIZE);
        s2n_stuffer_send_to_fd(&out, server_to_client[1], s2n_stuffer_data_available(&out));
    } while (blocked);
   
    /* Shutdown after negotiating */
    uint8_t server_shutdown=0;
    do {
        int ret;
        
        ret = s2n_shutdown(conn, &blocked);
        EXPECT_TRUE(ret == 0 || (blocked && (errno == EAGAIN || errno == EWOULDBLOCK)));
        if (ret == 0) {
            server_shutdown = 1;
        }
        
        s2n_stuffer_recv_from_fd(&in, client_to_server[0], MAX_BUF_SIZE);
        s2n_stuffer_send_to_fd(&out, server_to_client[1], s2n_stuffer_data_available(&out));
    } while (!server_shutdown);
    
    EXPECT_SUCCESS(s2n_connection_free(conn));

    /* Clean up */
    EXPECT_EQUAL(waitpid(-1, &status, 0), pid);
    EXPECT_EQUAL(status, 0);
    EXPECT_SUCCESS(s2n_config_free(config));
    END_TEST();

    return 0;
}

