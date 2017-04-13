/*
 * Copyright 2014 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <s2n.h>

#include "tls/s2n_connection.h"
#include "tls/s2n_handshake.h"

static char certificate_pkcs1[] =
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

static char certificate_pkcs8[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIC+zCCAeOgAwIBAgIJAMiNZTj8T8e5MA0GCSqGSIb3DQEBCwUAMBMxETAPBgNV\n"
    "BAMMCEZha2VSb290MCAXDTE2MDUwNDAxNTkyMVoYDzIxMTYwNDEwMDE1OTIxWjAT\n"
    "MREwDwYDVQQDDAhGYWtlUm9vdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC\n"
    "ggEBAPYIikkRhfkcEO0qkkE8UmveNoNOEagljN8l2a1G7CpiZzePKab5zOaLKj87\n"
    "ARMqAtgbgN5DgryM5WXuvPmrQ5+E5XOnHRJEHgNwEdzXjQy0SLg8R/HqHGPclVcD\n"
    "2SgkKC6JzYlMWPAYvb0W1ybLuJwenYkHW3FXGvAMvz0U9grQaZBH5COi3HBvE+x3\n"
    "S9WebNffMq5Iqjl3TPZxKovqEudsEo8Z7cyfuyqx+MiU8JfJUcDtm3pDKSJNqc6I\n"
    "QTLB9+g8W0eDJcrUWxeOVS5j0OzDMd3QelCl+sUVlUoxmxW4s5jJCfZ7TmXdaaPt\n"
    "kwayyZeNNWm1bnFlMWq+49JYF60CAwEAAaNQME4wHQYDVR0OBBYEFKbs8WpcHDYa\n"
    "SPSdS3foQIiZNWkhMB8GA1UdIwQYMBaAFKbs8WpcHDYaSPSdS3foQIiZNWkhMAwG\n"
    "A1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAOVV+JsUp0O0A0OHAVUrnDML\n"
    "15lGEaUct3k0N9Rgg3x9kymZ2fVEhFJScmXwtedUJv0UyliCnG4ONWDOHILpkFK6\n"
    "iavqNT5WlhLoj4/R4ngr1zwhWPwxtnYyiCUuZ7xxSON9h/jHft12X9pWn0K/3xEp\n"
    "62OeF7ZPeQ8x6c4LBTc2nTh2O58BoSIDeCTIWB08NaejeQTxU8RM+cC3r/kUZNs4\n"
    "66TLhX5cf0LLi3Z82uIlLPDlQgOmUDPQ0J6iRxQTwYhCbn8mrBQJF/q0znH5H+TG\n"
    "w6jItt4omOiI8qUNhNpo5zABE9Jhqqo05j26NGJLqepQfdSmBCIphwyikKE4pOU=\n"
    "-----END CERTIFICATE-----\n";



static char private_key_pkcs1[] =
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

static char private_key_pkcs8[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQD2CIpJEYX5HBDt\n"
    "KpJBPFJr3jaDThGoJYzfJdmtRuwqYmc3jymm+czmiyo/OwETKgLYG4DeQ4K8jOVl\n"
    "7rz5q0OfhOVzpx0SRB4DcBHc140MtEi4PEfx6hxj3JVXA9koJCguic2JTFjwGL29\n"
    "Ftcmy7icHp2JB1txVxrwDL89FPYK0GmQR+QjotxwbxPsd0vVnmzX3zKuSKo5d0z2\n"
    "cSqL6hLnbBKPGe3Mn7sqsfjIlPCXyVHA7Zt6QykiTanOiEEywffoPFtHgyXK1FsX\n"
    "jlUuY9DswzHd0HpQpfrFFZVKMZsVuLOYyQn2e05l3Wmj7ZMGssmXjTVptW5xZTFq\n"
    "vuPSWBetAgMBAAECggEABsLbUgC6Rss/p9TYqhRHS5GSu+8ESzOk+Gjo33soeE21\n"
    "+m/jvCP3PoqqgYxUjjtEUr4Gv5TpXdcdYry50r6jIBod2BzKjrryfDOzOfdud9/o\n"
    "c6+sZniBiTkBnZ+Mcy7zL7w3usMvWoHDjRO4m+dTTm8E80QRfj7fjaM8CiiuTkO4\n"
    "J20tPF9DXtlVocW/Suu2//uTQl1JwHYRN6e+WViwGJlJ+oACDdSItaWvFjgGg+Yg\n"
    "0TvlwTvTBCbyfXp+gyDRJJTSf8d5KVO8g6PVQLb3IUTyutkfEmFCahLF1qxDNkbn\n"
    "TkzXleAFq2iST1OB7aGtra1WSSIx1w/KWozWhFEY3QKBgQD+Yy/364v2AjnfC5gJ\n"
    "2ahKZrapsmgwS/dgql4Pbs5I5mTSzM2U89h5vymquHZrExHvTD28pmr6/F1zRKqi\n"
    "V1qXOW6I5snIlw/SM6qbFmO0zi2nIcgYDuyRS62abnTe81+FLHKjDHq1xbB3rMwj\n"
    "T+yvC21Zmk9Btb9W9rFaFvmVawKBgQD3l8vILcjCBqCZN2IplTDZ2Y1Hv6wmqtw4\n"
    "PblFUUUXAUIDqZE1MRucpndJGg2k8V1OXLSQD78gpd9ZTZlkocn8jq8/4oE51kCB\n"
    "ll9DwLGG1fAWWR9HvzCOqyE0gVHcCirm5Wwqixs94Ig9vgPVnGQfeMpvkn5XxBY6\n"
    "xy3v6TG1RwKBgQCIdgTBZaXK7h7FO57vicbxQnAyT/X8EoQ9YqbaeIJIMO9c9WhC\n"
    "wxwZEyby4ckEX1J7n9ZuYId64+3ta6RtOZbrEG/vGH6eEAr4o6adU0FhOEjdIw4H\n"
    "edoFhyc1dJNVFhDji5hjRsp8v/ON/y/ysWkx7VtXeaOSiECAEg3JWhHAyQKBgDof\n"
    "h3ZJ0TxDRAZT6xZp8JrjqHf0dhxpteL6EnlEV9zLrcygTPdYvOusZIpjtFpJUycn\n"
    "OjgriinG5sTXI7BtDrbcZCWyLbX/JwuE2n5USRinNoJ4j5BPQL3tTJE/3pCyTln/\n"
    "98GRAGcpQ7KC3fGSkiqVN6izkjdWUAWiZpVQgBvXAoGBALgHeKV+vxeAfQp6oe0O\n"
    "k+hCTq7hDHYCU8Xs4JLZXyAvb/4uITylxmH+X39ChzYKfxan+N+Jhb7diLs5uisR\n"
    "IcSz6ZB7d8k6sIJb5cpn/uuJ5sSjM5j4ps8oIjOSVqGQ9YgpTNHwfTzRDcHTSY+a\n"
    "16DS6oS2eYJBcaz55xKuXkjT\n"
    "-----END PRIVATE KEY-----\n";



static char dhparams[] =
    "-----BEGIN DH PARAMETERS-----\n"
    "MIIBCAKCAQEAy1+hVWCfNQoPB+NA733IVOONl8fCumiz9zdRRu1hzVa2yvGseUSq\n"
    "Bbn6k0FQ7yMED6w5XWQKDC0z2m0FI/BPE3AjUfuPzEYGqTDf9zQZ2Lz4oAN90Sud\n"
    "luOoEhYR99cEbCn0T4eBvEf9IUtczXUZ/wj7gzGbGG07dLfT+CmCRJxCjhrosenJ\n"
    "gzucyS7jt1bobgU66JKkgMNm7hJY4/nhR5LWTCzZyzYQh2HM2Vk4K5ZqILpj/n0S\n"
    "5JYTQ2PVhxP+Uu8+hICs/8VvM72DznjPZzufADipjC7CsQ4S6x/ecZluFtbb+ZTv\n"
    "HI5CnYmkAwJ6+FSWGaZQDi8bgerFk9RWwwIBAg==\n"
    "-----END DH PARAMETERS-----\n";

#define SUPPORTED_CERTIFICATE_FORMATS (2)

static char *certificates[SUPPORTED_CERTIFICATE_FORMATS] = { certificate_pkcs1, certificate_pkcs8};
static char *private_keys[SUPPORTED_CERTIFICATE_FORMATS] = { private_key_pkcs1, private_key_pkcs8};

void mock_client(int writefd, int readfd)
{
    char buffer[0xffff];
    struct s2n_connection *conn;
    s2n_blocked_status blocked;

    /* Give the server a chance to listen */
    sleep(1);

    conn = s2n_connection_new(S2N_CLIENT);
    conn->server_protocol_version = S2N_TLS12;
    conn->client_protocol_version = S2N_TLS12;
    conn->actual_protocol_version = S2N_TLS12;

    s2n_connection_set_read_fd(conn, readfd);
    s2n_connection_set_write_fd(conn, writefd);

    s2n_negotiate(conn, &blocked);

    for (int i = 1; i < 0xffff; i += 100) {
        for (int j = 0; j < i; j++) {
            buffer[j] = 33;
        }

        s2n_send(conn, buffer, i, &blocked);
    }

    int shutdown_rc = -1;
    while(shutdown_rc != 0) {
        shutdown_rc = s2n_shutdown(conn, &blocked);
    }

    s2n_connection_free(conn);

    /* Give the server a chance to a void a sigpipe */
    sleep(1);

    _exit(0);
}

int main(int argc, char **argv)
{
    struct s2n_connection *conn;
    struct s2n_config *config;
    s2n_blocked_status blocked;
    int status;
    pid_t pid;
    int server_to_client[2];
    int client_to_server[2];

    BEGIN_TEST();

    EXPECT_SUCCESS(setenv("S2N_ENABLE_CLIENT_MODE", "1", 0));

    for (int cert = 0; cert < SUPPORTED_CERTIFICATE_FORMATS; cert++) {

        for (int is_dh_key_exchange = 0; is_dh_key_exchange <= 1; is_dh_key_exchange++) {
            /* Create a pipe */
            EXPECT_SUCCESS(pipe(server_to_client));
            EXPECT_SUCCESS(pipe(client_to_server));



            /* Create a child process */
            pid = fork();
            if (pid == 0) {
                /* This is the child process, close the read end of the pipe */
                EXPECT_SUCCESS(close(client_to_server[0]));
                EXPECT_SUCCESS(close(server_to_client[1]));

                /* Write the fragmented hello message */
                mock_client(client_to_server[1], server_to_client[0]);
            }

            /* This is the parent */
            EXPECT_SUCCESS(close(client_to_server[1]));
            EXPECT_SUCCESS(close(server_to_client[0]));

            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            conn->server_protocol_version = S2N_TLS12;
            conn->client_protocol_version = S2N_TLS12;
            conn->actual_protocol_version = S2N_TLS12;

            EXPECT_NOT_NULL(config = s2n_config_new());

            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key(config, certificates[cert], private_keys[cert]));
            if (is_dh_key_exchange) {
                EXPECT_SUCCESS(s2n_config_add_dhparams(config, dhparams));
            }

            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            /* Set up the connection to read from the fd */
            EXPECT_SUCCESS(s2n_connection_set_read_fd(conn, client_to_server[0]));
            EXPECT_SUCCESS(s2n_connection_set_write_fd(conn, server_to_client[1]));

            /* Negotiate the handshake. */
            EXPECT_SUCCESS(s2n_negotiate(conn, &blocked));

            char buffer[0xffff];
            for (int i = 1; i < 0xffff; i += 100) {
                char * ptr = buffer;
                int size = i;

                do {
                    int bytes_read = 0;
                    EXPECT_SUCCESS(bytes_read = s2n_recv(conn, ptr, size, &blocked));

                    size -= bytes_read;
                    ptr += bytes_read;
                } while(size);

                for (int j = 0; j < i; j++) {
                    EXPECT_EQUAL(buffer[j], 33);
                }
            }

            int shutdown_rc = -1;
            do {
                shutdown_rc = s2n_shutdown(conn, &blocked);
                EXPECT_TRUE(shutdown_rc == 0 || (errno == EAGAIN && blocked));
            } while(shutdown_rc != 0);

            EXPECT_SUCCESS(s2n_connection_free(conn));

            EXPECT_SUCCESS(s2n_config_free(config));

            /* Clean up */
            EXPECT_EQUAL(waitpid(-1, &status, 0), pid);
            EXPECT_EQUAL(status, 0);
        }
    }

    END_TEST();
    return 0;
}
