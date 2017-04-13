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

#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <errno.h>

#include <s2n.h>

#include "tls/s2n_connection.h"
#include "tls/s2n_handshake.h"
#include "tls/s2n_cipher_preferences.h"
#include "tls/s2n_cipher_suites.h"
#include "utils/s2n_safety.h"

static char certificate_chain[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIICrTCCAZUCAn3VMA0GCSqGSIb3DQEBBQUAMB4xHDAaBgNVBAMME3MyblRlc3RJ\n"
    "bnRlcm1lZGlhdGUwIBcNMTYwMzMwMTg1NzQzWhgPMjExNjAzMDYxODU3NDNaMBgx\n"
    "FjAUBgNVBAMMDXMyblRlc3RTZXJ2ZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw\n"
    "ggEKAoIBAQDRw6AuYXAeRT0YuptCfJjRB/EDJyyGXnv+8TV2H1WJWhMLk8qND27r\n"
    "79A6EjbVmJaOV9qrokVqpDmXS712Z3BDprJ+1LFMymm3A+AFuK/skeGy0skik+Tg\n"
    "MmFT5XBVvmsw4uB1S9uUqktHauXgjhFPPsfvk4ewL4LulVEN2TEeI1Odj4CaMxAO\n"
    "Iuowm8wI2OHVzRHlrRmyJ9hYGuHHQ2TaTGIjr3WpAFuXi9pHGGMYa0uXAVPmgjdE\n"
    "XZ8t46u/ZKQ9W1uJkZEVKhcijT7G2VBrsBUq0CDiL+TDaGfthnBzUc9zt4fx/S/3\n"
    "qulC2WbKI3xrasQyjrsHTAJ75Md3rK09AgMBAAEwDQYJKoZIhvcNAQEFBQADggEB\n"
    "AHHkXNA9BtgAebZC2zriW4hRfeIkJMOwvfKBXHTuY5iCLD1otis6AZljcCKXM6O9\n"
    "489eHBC4T6mJwVsXhH+/ccEKqNRD2bUfQgOij32PsteV1eOHfHIFqdJmnBVb8tYa\n"
    "jxUvy7UQvXrPqaHbODrHe+7f7r1YCzerujiP5SSHphY3GQq88KemfFczp/4GnYas\n"
    "sE50OYe7DQcB4zvnxmAXp51JIN4ooktUU9oKIM5y2cgEWdmJzeqPANYxf0ZIPlTg\n"
    "ETknKw1Dzf8wlK5mFbbG4LPQh1mkDVcwQV3ogG6kGMRa7neH+6SFkNpAKuPCoje4\n"
    "NAE+WQ5ve1wk7nIRTQwDAF4=\n"
    "-----END CERTIFICATE-----\n"
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDKTCCAhGgAwIBAgICVxYwDQYJKoZIhvcNAQEFBQAwFjEUMBIGA1UEAwwLczJu\n"
    "VGVzdFJvb3QwIBcNMTYwMzMwMTg1NzA5WhgPMjExNjAzMDYxODU3MDlaMB4xHDAa\n"
    "BgNVBAMME3MyblRlc3RJbnRlcm1lZGlhdGUwggEiMA0GCSqGSIb3DQEBAQUAA4IB\n"
    "DwAwggEKAoIBAQDM/i3eclxYcvedPCEnVe6A/HYsYPeP1qKBZQhbpuuX061jFZKw\n"
    "lecb0eau1PORLbcsYK40u3xUzoA5u6Q0ebDuqPbqSJkCazsh66cu9STl8ubbk7oI\n"
    "8LJjUJFhhy2Jmm9krXhPyRscU+CXOCZ2G1GhBqTI8cgMYhEVHwb3qy1EHg6G3n4W\n"
    "AjV+cKQcbUytq8DRmVe0bNJxDOX8ivzfAp3lUIwub+JfpxrWIUhb3iVGj5CauI98\n"
    "bNFHTWwYp7tviIIi21Q+L3nExCyE4yTUP/mebBZ62JnbvsWSs3r3//Am5d8G3WdY\n"
    "BXsERoDoLBvHnqlO/oo4ppGCRI7GkDroACi/AgMBAAGjdzB1MAwGA1UdEwQFMAMB\n"
    "Af8wHQYDVR0OBBYEFGqUKVWVlL03sHuOggFACdlHckPBMEYGA1UdIwQ/MD2AFE2X\n"
    "AbNDryMlBpMNI6Ce927uUFwToRqkGDAWMRQwEgYDVQQDDAtzMm5UZXN0Um9vdIIJ\n"
    "ANDUkH+UYdz1MA0GCSqGSIb3DQEBBQUAA4IBAQA3O3S9VT0EC1yG4xyNNUZ7+CzF\n"
    "uFA6uiO38ygcN5Nz1oNPy2eQer7vYmrHtqN6gS/o1Ag5F8bLRCqeuZTsOG80O29H\n"
    "kNhs5xYprdU82AqcaWwEd0kDrhC5rEvs6fj1J0NKmmhbovYxuDboj0a7If7HEqX0\n"
    "NizyU3M3JONPZgadchZ+F5DosatF1Bpt/gsQRy383IogQ0/FS+juHCCc4VIUemuk\n"
    "YY1J8o5XdrGWrPBBiudTWqCobe+N541b+YLWbajT5UKzvSqJmcqpPTniJGc9eZxc\n"
    "z3cCNd3cKa9bK51stEnQSlA7PQXYs3K+TD3EmSn/G2x6Hmfr7lrpbIhEaD+y\n"
    "-----END CERTIFICATE-----\n"
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDATCCAemgAwIBAgIJANDUkH+UYdz1MA0GCSqGSIb3DQEBCwUAMBYxFDASBgNV\n"
    "BAMMC3MyblRlc3RSb290MCAXDTE2MDMzMDE4NTYzOVoYDzIxMTYwMzA2MTg1NjM5\n"
    "WjAWMRQwEgYDVQQDDAtzMm5UZXN0Um9vdDCCASIwDQYJKoZIhvcNAQEBBQADggEP\n"
    "ADCCAQoCggEBAMY5532000oaeed7Jmo3ssx1723ZDLpn3WGz6FxpWM0zsKA/YvdD\n"
    "7J6qXDvfxU6dZlmsCS+bSNAqpARKmKsBEDPTsdLmrN1V1clOxvKm6GvU1eloRTw6\n"
    "xukEUXJ+uxrQMLYvSJBiCBVGI+UYNCK5c6guNMRYBCGdk5/iayjmK0Nxz1918Cx9\n"
    "z4va8HPAgYIz0ogOdYB21O9FQGPdH1mYqRzljcSsZ7EFo1P8HJr8oKK76ZeYi2or\n"
    "pjzMHGnlufHaul508wQPeFAMa1Tku3HyGZRaieRAck6+QcO2NujXxKNyCBlWON23\n"
    "FQTuBjN/CAl74MZtcAM2hVSmpm9t4cWVN5MCAwEAAaNQME4wHQYDVR0OBBYEFE2X\n"
    "AbNDryMlBpMNI6Ce927uUFwTMB8GA1UdIwQYMBaAFE2XAbNDryMlBpMNI6Ce927u\n"
    "UFwTMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAAXkVvQdXDmozPix\n"
    "uZi1o9cw4Si0syqfJ4sSunrzPbbmw/Qxhth5V7XGrnsQVNxamgnbzpjGhiBF6isM\n"
    "ldj33zQYtke+ojOjFlhEvrPo6eW29RkLBEtJadGs2bkMLztJbf+cbH2u6irzr6S4\n"
    "3OgVOSuB+zG56ksTnEVmum+C/8tSIAyi3eaoStPcgEU8+3/KMrH7uuenmTOCKdD1\n"
    "FvSDHXT9qPgTttVQGXbXzJEr5tGE+Py6yib5uoJ0dJZNtjs7HOQEDk5J0wZaX0DC\n"
    "MShYLiN5qLJAk0qwl+js488BJ18M9dg4TxdBYFkwHSzKXSj9TJN77Bb0RZr8LL9T\n"
    "r9IyvfU=\n"
    "-----END CERTIFICATE-----\n";

static char private_key[] =
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEpAIBAAKCAQEA0cOgLmFwHkU9GLqbQnyY0QfxAycshl57/vE1dh9ViVoTC5PK\n"
    "jQ9u6+/QOhI21ZiWjlfaq6JFaqQ5l0u9dmdwQ6ayftSxTMpptwPgBbiv7JHhstLJ\n"
    "IpPk4DJhU+VwVb5rMOLgdUvblKpLR2rl4I4RTz7H75OHsC+C7pVRDdkxHiNTnY+A\n"
    "mjMQDiLqMJvMCNjh1c0R5a0ZsifYWBrhx0Nk2kxiI691qQBbl4vaRxhjGGtLlwFT\n"
    "5oI3RF2fLeOrv2SkPVtbiZGRFSoXIo0+xtlQa7AVKtAg4i/kw2hn7YZwc1HPc7eH\n"
    "8f0v96rpQtlmyiN8a2rEMo67B0wCe+THd6ytPQIDAQABAoIBAF3evYAD+riRI5Y9\n"
    "a92FBJ4Gf8R5c2NuRO8B4nrJ6u1ccclsieg2T90lpHlYTVGoxzdL+X91Trs6Ysti\n"
    "CZdDEuozXw2DARTsQAK2qTnmPFQRtH7h9UCUDoiGAygYNP0qCa4G2YukNs+Apc9/\n"
    "9v9WlEhyP+bmjoI5wM4j4/HekCx7syHuiqJ74//oTzNamT0aWHwgXAUmEYZ/1+nT\n"
    "0KInmtmIOFgsWHcojwQ6sZJ3eVvy66EqHLZKQYZa2tx0YjrEJMQi1drg6VV+lLCR\n"
    "rEtsoltgdN2G9v3P6KrHXsrCYaaZKhog9B1OSI2Amv3YWZHXppK12+aSy774lUUz\n"
    "qVur5cECgYEA7oCOQoRZo76wztS+yDeq173B2gPHKSIrWvaLDkCAPOQPVzJZ4Qc+\n"
    "8OEDU6HB9P0MYDsKBxZY85uzWP+dAlsmcL0C86WibOuYERPKQIcAn3KSzFiIxH3R\n"
    "OAbaLtSLN3lDAH50PhP9BguiSfBjI6w4Qsr7jlQgdpzG4h4LjvotbWMCgYEA4SdT\n"
    "QQJhHiLtBFo91ItRUzhePvUDfV8XvNfAwZj8cY2+oenkK2+bp35xteBV6Gu1cYnd\n"
    "V2yFgzMZ/jDvqfUn/8EVAGvEFrLtsUpXeyHhgmVT490RsPxC9xU9jf5LsvZ4zjsj\n"
    "CsFZW0JnhKkF6M5wztWtO3yKCilmXSOIFvorTN8CgYEAoK2LKdTwbxhxFWbOgSS/\n"
    "vEji6HXTHysd+lJOrHNX8a3Th/MsCiZPiQiOrTE08k/onown3U547uXelf7fUE8I\n"
    "PruX2X2lR6wQ7rBeecp56PHPZEvhGD+LTCuRoise/2h6c0K+HXRp6kC8PQPuRoIo\n"
    "BRerEeArXr2QX5XOQ6zYHfECgYEAp0L9mDfaSfcMOMWJVVJCEh639PEzrHluOv3U\n"
    "1n1+XCU+zy3gMVxyN9W5R7HmYAlT+4q9geq+rJ7T2oAkKxBSrK6VmYB1ZZ968NAX\n"
    "eQPMcYAw+AAM2nwsiz2eQtP9DHAJgrtv5teIOEF2gZjHKRHjv+QBE0YLjkz/HIX+\n"
    "3YLvk+UCgYAgpAWk4YW4dAcZ8Y04Ke2pjMvEu44hHphOmk6AZl0Xl9tJwxlV8GVx\n"
    "o3L4hbjHqyJo3+DZZYM7udMx9axbX9JHYRaLNJpc8UxQZj7d3TehC9Dw9/DzhIy/\n"
    "6sml30j/GHvnW5DOlpsdNKDlxoFX+hncXYIjyVTGRNdsSwa4VVm+Xw==\n"
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

static int try_handshake(struct s2n_connection *server_conn, struct s2n_connection *client_conn)
{
    s2n_blocked_status server_blocked;
    s2n_blocked_status client_blocked;

    int tries = 0;
    do {
        int client_rc = s2n_negotiate(client_conn, &client_blocked);
        if (!(client_rc == 0 || (client_blocked && errno == EAGAIN))) {
            return -1;
        }

        int server_rc = s2n_negotiate(server_conn, &server_blocked);
        if (!(server_rc == 0 || (server_blocked && errno == EAGAIN))) {
            return -1;
        }

        tries += 1;
        if (tries == 100) {
            return -1;
        }
    } while (client_blocked || server_blocked);

    uint8_t server_shutdown = 0;
    uint8_t client_shutdown = 0;
    do {
        if (!server_shutdown) {
            int server_rc = s2n_shutdown(server_conn, &server_blocked);
            if (server_rc == 0) {
                server_shutdown = 1;
            } else if (!(server_blocked && errno == EAGAIN)) {
                return -1;
            }
        }

        if (!client_shutdown) {
            int client_rc = s2n_shutdown(client_conn, &client_blocked);
            if (client_rc == 0) {
                client_shutdown = 1;
            } else if (!(client_blocked && errno == EAGAIN)) {
                return -1;
            }
        }
    } while (!server_shutdown || !client_shutdown);

    return 0;
}

int main(int argc, char **argv)
{
    struct s2n_config *server_config;
    const struct s2n_cipher_preferences *default_cipher_preferences;

    BEGIN_TEST();

    EXPECT_SUCCESS(setenv("S2N_ENABLE_CLIENT_MODE", "1", 0));

    EXPECT_NOT_NULL(server_config = s2n_config_new());
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key(server_config, certificate_chain, private_key));
    EXPECT_SUCCESS(s2n_config_add_dhparams(server_config, dhparams));
    EXPECT_NOT_NULL(default_cipher_preferences = server_config->cipher_preferences);

    /* Verify that a handshake succeeds for every available cipher in the default list. For unavailable ciphers,
     * make sure that we fail the handshake. */
    for (int cipher_idx = 0; cipher_idx < default_cipher_preferences->count; cipher_idx++) {
        struct s2n_cipher_preferences server_cipher_preferences;
        struct s2n_connection *client_conn;
        struct s2n_connection *server_conn;
        int server_to_client[2];
        int client_to_server[2];
        struct s2n_cipher_suite *cur_cipher = default_cipher_preferences->suites[cipher_idx];
        uint8_t expect_failure = 0;

        /* Expect failure if the libcrypto we're building with can't support the cipher */
        if (!cur_cipher->available) {
            expect_failure = 1;
        }

        /* Craft a cipher preference with a cipher_idx cipher
           NOTE: Its safe to use memcpy as the address of server_cipher_preferences
           will never be NULL */
        memcpy(&server_cipher_preferences, default_cipher_preferences, sizeof(server_cipher_preferences));
        server_cipher_preferences.count = 1;
        server_cipher_preferences.suites = &cur_cipher;
        server_config->cipher_preferences = &server_cipher_preferences;

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
        client_conn->server_protocol_version = S2N_TLS12;
        client_conn->client_protocol_version = S2N_TLS12;
        client_conn->actual_protocol_version = S2N_TLS12;

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_read_fd(server_conn, client_to_server[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(server_conn, server_to_client[1]));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));
        server_conn->server_protocol_version = S2N_TLS12;
        server_conn->client_protocol_version = S2N_TLS12;
        server_conn->actual_protocol_version = S2N_TLS12;

        if (!expect_failure) {
            EXPECT_SUCCESS(try_handshake(server_conn, client_conn));
        } else {
            EXPECT_FAILURE(try_handshake(server_conn, client_conn));
        }

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));

        for (int i = 0; i < 2; i++) {
           EXPECT_SUCCESS(close(server_to_client[i]));
           EXPECT_SUCCESS(close(client_to_server[i]));
        }
    }

    EXPECT_SUCCESS(s2n_config_free(server_config));

    END_TEST();
    return 0;
}

