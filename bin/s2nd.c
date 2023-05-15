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

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <netdb.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef S2N_INTERN_LIBCRYPTO
    #include <openssl/crypto.h>
    #include <openssl/err.h>
#endif

#include "api/s2n.h"
#include "api/unstable/npn.h"
#include "common.h"
#include "utils/s2n_safety.h"

#define MAX_CERTIFICATES 50

/*
 * s2nd is an example server that uses many s2n-tls APIs.
 * It is intended for testing purposes only, and should not be used in production.
 */

static char default_certificate_chain[] =
        "-----BEGIN CERTIFICATE-----"
        "MIIDHTCCAgWgAwIBAgIUPxywpg3/+VHmj8jJSvK62XC06zMwDQYJKoZIhvcNAQEL"
        "BQAwHjEcMBoGA1UEAwwTczJuVGVzdEludGVybWVkaWF0ZTAgFw0yMDAxMjQwMTEw"
        "MjFaGA8yMTE5MTIzMTAxMTAyMVowGDEWMBQGA1UEAwwNczJuVGVzdFNlcnZlcjCC"
        "ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJUbMpdROM6cjb8xgr5kgKHn"
        "JVDfhbLg4pxBwWwlayb6/N60JLG9KzWAWhZBmz+Px6kr/1dL6+bL3mLuNBCQpYBS"
        "Pee2n7KL9PvsMYZmnYFyn94bXbjBCRxGR+a9lcGHLlZ4C+rrLNi9pUwxf7VIRglR"
        "zwHWAFg5xTX6lCmziNM4OMkq8lHkLopHDUg5yI4VTc3EEGqDIf3+0BheIHcUFbIW"
        "kFOjRDdL3lMGKEj0+LErzzbhJczBlRMqSMiuYeaWgORLpRNtMeNmbR8oLJFchpF0"
        "A9fIO2/Yg+nclcDDhsUBkkfcIKRySGDumKLuYM+hOHp5vQo8tcvyQ6s3U5YULQUC"
        "AwEAAaNXMFUwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUkVKVmfjICpx4fkvJO6YJ"
        "mdoKz3owDgYDVR0PAQH/BAQDAgPoMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMBMA0G"
        "CSqGSIb3DQEBCwUAA4IBAQBXoWDI1Gi9snC4K6S7E0AoLmGEPUWzc4fd4Cbj9PRp"
        "mSKpsJOYjmneIV34WqnvUXrBkkzblEb9RdszN96WuRAaZJQegRtKOWN5Iggd4sHM"
        "8XEx/LeJHc08uSb2d/TnhhOPALoJl/w6M5e6yOezCEJorsOXuVBcbuEKfne7oMA1"
        "GziFnVPtwiwXxsX16KilsQRylnK0bV/x1BOgYByCDcXorMndsAYjn4yG1D4l8TbC"
        "kCtK1bafEVoASpOFQ8tSeOXBL7Fvw9mFFzs3/ajBTz2nBLDsnP8XH5C/vy8wNGSd"
        "Tdcs7DRLYhNJxYopcMgCwyyCAtEFcHkovCSrJ6HUl/ko"
        "-----END CERTIFICATE-----"
        "-----BEGIN CERTIFICATE-----"
        "MIIDCTCCAfGgAwIBAgIUfdybeOdDMd7cPXk6RTcEqeM3IEIwDQYJKoZIhvcNAQEL"
        "BQAwFjEUMBIGA1UEAwwLczJuVGVzdFJvb3QwIBcNMjAwMTI0MDEwOTUzWhgPMjEx"
        "OTEyMzEwMTA5NTNaMB4xHDAaBgNVBAMME3MyblRlc3RJbnRlcm1lZGlhdGUwggEi"
        "MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC2NsDkrZjYbyVeF1R9337y9OHM"
        "C2xSRGB6SHrVG1bQZlPxI+E6DqDJcMB4tFLkA7AJxxRLxA7KvO9PzcHAlsqvYcMV"
        "gOSAjUZ0Eiwwf6Rtgo2yByj2n1K5XDN3bpt1rROD0BIEnaU9GZd3U0QUYHBRfp0E"
        "IdeWuRrlFbPpWXnBaQB/2jEfCuZzpPOiKMWt99GQ4bFBOSzpYdXLALGfb15Kr6RF"
        "YoMlsyeijNeePxLeYgracu+vzJLvEzx1U7OGnlWz+VKBw/mz3gABqFfxurN5E8yb"
        "4AWJ5kEUJobYcxwe+DoimPdPTWgByJlMpKjfIbnroz/oTZMiNfUCtKT3GTejAgMB"
        "AAGjRTBDMBIGA1UdEwEB/wQIMAYBAf8CAQEwHQYDVR0OBBYEFEasSJIPBZTXyYjI"
        "CN2m1Ttz3sUJMA4GA1UdDwEB/wQEAwIBhjANBgkqhkiG9w0BAQsFAAOCAQEAxveh"
        "GKJPu7DXjoMePzlRGML2iIDT6MgKpsMnO5sNgUbJTFV3KeuASRm1SXVrVFHcQDov"
        "l9P10ff0J9KOVrRCawMZZxjjtNAIrSW0G7fwmTgJMTuM5vaaGRjKy018LApcr//Q"
        "Nwjh4sw9KOtNIE9krT06kli9zjsgr/EWwPCHSin8oONDgCNn1WgtrSMexsF1BSzU"
        "OTq+nyn4nOPOEUthjmepG2eDkd17MNJ6GdKYnFRmC+ctSH028akERhz+EtavU4Cd"
        "2eSFTKtbxOuZXyfsOwjhrufp/Ss9i57x3XotBNJ8Fv7VpxI19+Zag4DMGzd3Pisu"
        "Q1VpfValnMGtVWPleg=="
        "-----END CERTIFICATE-----"
        "-----BEGIN CERTIFICATE-----"
        "MIIC/jCCAeagAwIBAgIUFFjxpSf0mUsrVbyLPQhccDYfixowDQYJKoZIhvcNAQEL"
        "BQAwFjEUMBIGA1UEAwwLczJuVGVzdFJvb3QwIBcNMjAwMTI0MDEwODIyWhgPMjEx"
        "OTEyMzEwMTA4MjJaMBYxFDASBgNVBAMMC3MyblRlc3RSb290MIIBIjANBgkqhkiG"
        "9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz3AaOAlkcxJHryCI9SfwB9q4PA53hv5tz4ZL"
        "be37b69v58mfP+D18cWIBHUmkmN6gWWoWZ/9hv75pxcNXW0zPn7+wOVvXLUjtmkq"
        "1IGT/mykhasw00viaBFAuBHZ5iLwfc4/cjUFAPVCKLmfv5Xs7TJVzWA/0mR4r1h8"
        "uFqqXczkVMklIbsOIrlZXz8ifQs3DpFA2FeoziEh+Pcb4c3QBPgCHFDEGyTSdqo9"
        "+NbS+iRlw0T6tqUOpC0DdKXo/3mJNBmy4XPahTi9zgsu7b+UVqemL7eXXf/iSr5y"
        "iwJKJjz+N/rLpcF1VJtF8q0fpHagzljQaN7/emjg7BplUUyLawIDAQABo0IwQDAP"
        "BgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTDmXkyQEJ7ZciyE4KF7wAJKDxMfDAO"
        "BgNVHQ8BAf8EBAMCAYYwDQYJKoZIhvcNAQELBQADggEBAFobyhsc7mYoGaA7N4Pp"
        "it+MQZZNzWte5vWal/3/2V7ZGrJsgeCPwLblzzTmey85RilX6ovMQHEqT1vBFSHq"
        "nntMZnHkEl2QLU8XopJWR4MXK7LzjjQYaXiZhGbJbtylVSfATAa/ZzdgjBx1C8aD"
        "IM1+ELGCP/UHD0YEJkFoxSUwXGAXoV8I+cPDAWHC6VnC4mY8qubhx95FpX02ERnz"
        "1Cw2YWtntyO8P52dEJD1+0EJjtVX4Bj5wwgJHHbDkPP1IzFrR/uBC2LCjtRY+UtZ"
        "kfoDfWu2tslkLK7/LaC5qZyCPKnpPHLLz8gUWKlvbuejM99FTlBg/tcH+bv5x7WB"
        "MZ8="
        "-----END CERTIFICATE-----";

static char default_private_key[] =
        "-----BEGIN RSA PRIVATE KEY-----"
        "MIIEogIBAAKCAQEAlRsyl1E4zpyNvzGCvmSAoeclUN+FsuDinEHBbCVrJvr83rQk"
        "sb0rNYBaFkGbP4/HqSv/V0vr5sveYu40EJClgFI957afsov0++wxhmadgXKf3htd"
        "uMEJHEZH5r2VwYcuVngL6uss2L2lTDF/tUhGCVHPAdYAWDnFNfqUKbOI0zg4ySry"
        "UeQuikcNSDnIjhVNzcQQaoMh/f7QGF4gdxQVshaQU6NEN0veUwYoSPT4sSvPNuEl"
        "zMGVEypIyK5h5paA5EulE20x42ZtHygskVyGkXQD18g7b9iD6dyVwMOGxQGSR9wg"
        "pHJIYO6You5gz6E4enm9Cjy1y/JDqzdTlhQtBQIDAQABAoIBAGTaSJXg8jON4LJ5"
        "op11DSx1U+An0B71zVEziMjFZnyvN2rLHia6dQdzEXwMVB3h+oKKp+M8DwvEyV7R"
        "D5ZEwCzTc9vOwqXZ1JKxZ64oqlBsX4WzrOjSaH8fanK/uRN1g/ooqKb0+xh+7ddj"
        "g6XyhKy5EPOE9Ca4rJOeMakjLmDuleQecT/DixYV6azhfaJoD70XZJWv3YzSpu/X"
        "Ma+i3of0alsG/lROjNtEXE3nKzcTUgyAUoQeYRwCVpgssg/4VAUPJNDP4dVmxW8f"
        "eNmjlTyXmR9S08SXkqmCHe2mBUsZY9nqcDE6ZWILZKFWIfZD9W+j2ce0FMvcc9kz"
        "psxaUQECgYEAxqwsb5aQy6HBF54tdkHbUQEJMelSLNW0G1GUrcLB7eqL7qo3dUA8"
        "8PDQ/dTwmmJ7aE0SK2xkQDVKXNbV4OvUNgP6tbzLWEbvmuFAEg5X1jFH2VSdwQhl"
        "RDwTQw3wPZ5udy64L6gmsdDch+I7l1v4ex66RWFW+4WIs1altsLiJa0CgYEAwCGW"
        "2cjtZ3kIzWgxf7DdnoUTwBM1ATBUYvx7uqVq+dbc/p8cSeMSPz3LUluaVJ2EOjEV"
        "QWhx0Ih5qeitzReHRU0OHgxEgjbpJwhseD9O5POSd+fE3TtDQArOxyw4CIJKk4Z2"
        "QmqzaO/LboN3Tp+/N9zfVoNZKHcCNra/uKNTH7kCgYA3QFazSdpG51s96D2Yb8RA"
        "iNs3yD2UPnJyToPctxcbxWjZHPmDYDQShcZ5cSjgppbPcO+mp+RRfwCJRS4B+VPx"
        "GbY1qKWcjU3BcvdQjjCbXuUuabvdnSocieCJe2zelhr+hj2u80KfnQhXufD8rRUz"
        "mF4RQXrhREe6KFS5uQUPmQKBgE4rXFyvSyfWLqajxb/WDdT4/9gd+GrLZwn+/7go"
        "pSWRLcjKo4/MOxhP4/FWI6xZifrDDYrXG7dkT1u5tzzCXd7sQtom05jHDoU7ACbM"
        "WyT7lJQEUCxSeEIOI6MVcpbDq+PpySOsleIT7gjApEHw7LOlwZhJSHUWNmhcYhSV"
        "HrTBAoGADAvBqV7JItjm2+qkXXEdPVzOunqjQdnXZjMAJ75PhHnLCCfnTRu53hT3"
        "JxDETLLa/r42PlqGZ6bqSW+C+ObgYOvvySqvX8CE9o208ZwCLjHYxuYLH/86Lppr"
        "ggF9KQ0xWz7Km3GXv5+bwM5bcgt1A/s6sZCimXuj3Fle3RqOTF0="
        "-----END RSA PRIVATE KEY-----";

#define OPT_BUFFERED_SEND 1000

void usage()
{
    /* clang-format off */
    fprintf(stderr, "usage: s2nd [options] host port\n");
    fprintf(stderr, " host: hostname or IP address to listen on\n");
    fprintf(stderr, " port: port to listen on\n");
    fprintf(stderr, "\n Options:\n\n");
    fprintf(stderr, "  -a [protocol]\n");
    fprintf(stderr, "  --alpn [protocol]\n");
    fprintf(stderr, "    Sets a single application protocol supported by this server.\n");
    fprintf(stderr, "  -c [version_string]\n");
    fprintf(stderr, "  --ciphers [version_string]\n");
    fprintf(stderr, "    Set the cipher preference version string. Defaults to \"default\". See USAGE-GUIDE.md\n");
    fprintf(stderr, "  --enter-fips-mode\n");
    fprintf(stderr, "    Enter libcrypto's FIPS mode. The linked version of OpenSSL must be built with the FIPS module.\n");
    fprintf(stderr, "  --cert\n");
    fprintf(stderr, "    Path to a PEM encoded certificate [chain]. Option can be repeated to load multiple certs.\n");
    fprintf(stderr, "  --key\n");
    fprintf(stderr, "    Path to a PEM encoded private key that matches cert. Option can be repeated to load multiple certs.\n");
    fprintf(stderr, "  -m\n");
    fprintf(stderr, "  --mutualAuth\n");
    fprintf(stderr, "    Request a Client Certificate. Any RSA Certificate will be accepted.\n");
    fprintf(stderr, "  -n\n");
    fprintf(stderr, "  --negotiate\n");
    fprintf(stderr, "    Only perform tls handshake and then shutdown the connection\n");
    fprintf(stderr, "  --parallelize\n");
    fprintf(stderr, "    Create a new Connection handler thread for each new connection. Useful for tests with lots of connections.\n");
    fprintf(stderr, "    Warning: this option isn't compatible with TLS Resumption, since each thread gets its own Session cache.\n");
    fprintf(stderr, "  --prefer-low-latency\n");
    fprintf(stderr, "    Prefer low latency by clamping maximum outgoing record size at 1500.\n");
    fprintf(stderr, "  --prefer-throughput\n");
    fprintf(stderr, "    Prefer throughput by raising maximum outgoing record size to 16k\n");
    fprintf(stderr, "  --enable-mfl\n");
    fprintf(stderr, "    Accept client's TLS maximum fragment length extension request\n");
    fprintf(stderr, "  --ocsp\n");
    fprintf(stderr, "    Path to a DER formatted OCSP response for stapling\n");
    fprintf(stderr, "  -s\n");
    fprintf(stderr, "  --self-service-blinding\n");
    fprintf(stderr, "    Don't introduce 10-30 second delays on TLS Handshake errors. \n");
    fprintf(stderr, "    Warning: this should only be used for testing since skipping blinding may allow timing side channels.\n");
    fprintf(stderr, "  -t,--ca-file [file path]\n");
    fprintf(stderr, "    Location of trust store CA file (PEM format). If neither -t or -d are specified. System defaults will be used.");
    fprintf(stderr, "    This option is only used if mutual auth is enabled.\n");
    fprintf(stderr, "  -d,--ca-dir [directory path]\n");
    fprintf(stderr, "    Directory containing hashed trusted certs. If neither -t or -d are specified. System defaults will be used.");
    fprintf(stderr, "    This option is only used if mutual auth is enabled.\n");
    fprintf(stderr, "  -i,--insecure\n");
    fprintf(stderr, "    Turns off certification validation altogether.\n");
    fprintf(stderr, "  --stk-file\n");
    fprintf(stderr, "    Location of key file used for encryption and decryption of session ticket.\n");
    fprintf(stderr, "  -T,--no-session-ticket\n");
    fprintf(stderr, "    Disable session ticket for resumption.\n");
    fprintf(stderr, "  -C,--corked-io\n");
    fprintf(stderr, "    Turn on corked io\n");
    fprintf(stderr, "  --non-blocking\n");
    fprintf(stderr, "    Set the non-blocking flag on the connection's socket.\n");
    fprintf(stderr, "  -w --https-server\n");
    fprintf(stderr, "    Run s2nd in a simple https server mode.\n");
    fprintf(stderr, "  -b --https-bench <bytes>\n");
    fprintf(stderr, "    Send number of bytes in https server mode to test throughput.\n");
    fprintf(stderr, "  -L --key-log <path>\n");
    fprintf(stderr, "    Enable NSS key logging into the provided path\n");
    fprintf(stderr, "  -P --psk <psk-identity,psk-secret,psk-hmac-alg> \n"
                    "    A comma-separated list of psk parameters in this order: psk_identity, psk_secret and psk_hmac_alg.\n"
                    "    Note that the maximum number of permitted psks is 10, the psk-secret is hex-encoded, and whitespace is not allowed before or after the commas.\n"
                    "    Ex: --psk psk_id,psk_secret,SHA256 --psk shared_id,shared_secret,SHA384.\n");
    fprintf(stderr, "  -E, --max-early-data \n");
    fprintf(stderr, "    Sets maximum early data allowed in session tickets. \n");
    fprintf(stderr, "  -N --npn \n");
    fprintf(stderr, "    Indicates support for the NPN extension. The '--alpn' option MUST be used with this option to signal the protocols supported.");
    fprintf(stderr, "  -h,--help\n");
    fprintf(stderr, "    Display this message and quit.\n");
    fprintf(stderr, "  --buffered-send <buffer size>\n");
    fprintf(stderr, "    Set s2n_send to buffer up to <buffer size> bytes before sending records over the wire.\n");
    fprintf(stderr, "  -X, --max-conns <max connections>\n");
    fprintf(stderr, "    Sets the max number of connections s2nd will accept before shutting down.\n");
    /* clang-format on */
    exit(1);
}

int handle_connection(int fd, struct s2n_config *config, struct conn_settings settings)
{
    struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
    if (!conn) {
        print_s2n_error("Error getting new s2n connection");
        S2N_ERROR_PRESERVE_ERRNO();
    }

    s2n_setup_server_connection(conn, fd, config, settings);

    if (negotiate(conn, fd) != S2N_SUCCESS) {
        if (settings.mutual_auth) {
            if (!s2n_connection_client_cert_used(conn)) {
                print_s2n_error("Error: Mutual Auth was required, but not negotiated");
            }
        }

        /* Error is printed in negotiate */
        S2N_ERROR_PRESERVE_ERRNO();
    }

    GUARD_EXIT(s2n_connection_free_handshake(conn), "Error freeing handshake memory after negotiation");

    if (settings.https_server) {
        https(conn, settings.https_bench);
    } else if (!settings.only_negotiate) {
        bool stop_echo = false;
        echo(conn, fd, &stop_echo);
    }

    GUARD_RETURN(wait_for_shutdown(conn, fd), "Error closing connection");

    GUARD_RETURN(s2n_connection_wipe(conn), "Error wiping connection");

    GUARD_RETURN(s2n_connection_free(conn), "Error freeing connection");

    return 0;
}

int main(int argc, char *const *argv)
{
    struct addrinfo hints, *ai;
    int r, sockfd = 0;

    /* required args */
    const char *host = NULL;
    const char *port = NULL;

    const char *ocsp_response_file_path = NULL;
    const char *session_ticket_key_file_path = NULL;
    const char *cipher_prefs = "default";
    const char *alpn = NULL;
    const char *key_log_path = NULL;

    /* The certificates provided by the user. If there are none provided, we will use the hardcoded default cert.
     * The associated private key for each cert will be at the same index in private_keys. If the user mixes up the
     * order of --cert --key for a given cert/key pair, s2n will fail to load the cert and s2nd will exit.
     */
    int num_user_certificates = 0;
    int num_user_private_keys = 0;
    const char *certificates[MAX_CERTIFICATES] = { 0 };
    const char *private_keys[MAX_CERTIFICATES] = { 0 };

    struct conn_settings conn_settings = { 0 };
    int fips_mode = 0;
    int parallelize = 0;
    int non_blocking = 0;
    long int bytes = 0;
    conn_settings.session_ticket = 1;
    conn_settings.session_cache = 1;
    conn_settings.max_conns = -1;
    conn_settings.psk_list_len = 0;
    int max_early_data = 0;
    uint32_t send_buffer_size = 0;
    bool npn = false;

    struct option long_options[] = {
        { "ciphers", required_argument, NULL, 'c' },
        { "enable-mfl", no_argument, NULL, 'e' },
        { "enter-fips-mode", no_argument, NULL, 'f' },
        { "help", no_argument, NULL, 'h' },
        { "key", required_argument, NULL, 'k' },
        { "prefer-low-latency", no_argument, NULL, 'l' },
        { "mutualAuth", no_argument, NULL, 'm' },
        { "negotiate", no_argument, NULL, 'n' },
        { "ocsp", required_argument, NULL, 'o' },
        { "parallelize", no_argument, &parallelize, 1 },
        { "prefer-throughput", no_argument, NULL, 'p' },
        { "cert", required_argument, NULL, 'r' },
        { "self-service-blinding", no_argument, NULL, 's' },
        { "ca-dir", required_argument, 0, 'd' },
        { "ca-file", required_argument, 0, 't' },
        { "insecure", no_argument, 0, 'i' },
        { "stk-file", required_argument, 0, 'a' },
        { "no-session-ticket", no_argument, 0, 'T' },
        { "corked-io", no_argument, 0, 'C' },
        { "max-conns", optional_argument, 0, 'X' },
        { "tls13", no_argument, 0, '3' },
        { "https-server", no_argument, 0, 'w' },
        { "https-bench", required_argument, 0, 'b' },
        { "alpn", required_argument, 0, 'A' },
        { "npn", no_argument, 0, 'N' },
        { "non-blocking", no_argument, 0, 'B' },
        { "key-log", required_argument, 0, 'L' },
        { "psk", required_argument, 0, 'P' },
        { "max-early-data", required_argument, 0, 'E' },
        { "buffered-send", required_argument, 0, OPT_BUFFERED_SEND },
        /* Per getopt(3) the last element of the array has to be filled with all zeros */
        { 0 },
    };
    while (1) {
        int option_index = 0;
        int c = getopt_long(argc, argv, "c:hmnst:d:iTCX::wb:A:P:E:", long_options, &option_index);
        if (c == -1) {
            break;
        }

        switch (c) {
            case 0:
                /* getopt_long() returns 0 if an option.flag is non-null (Eg "parallelize") */
                break;
            case 'C':
                conn_settings.use_corked_io = 1;
                break;
            case 'c':
                cipher_prefs = optarg;
                break;
            case 'e':
                conn_settings.enable_mfl = 1;
                break;
            case 'f':
                fips_mode = 1;
                break;
            case 'h':
                usage();
                break;
            case 'k':
                if (num_user_private_keys == MAX_CERTIFICATES) {
                    fprintf(stderr, "Cannot support more than %d certificates!\n", MAX_CERTIFICATES);
                    exit(1);
                }
                private_keys[num_user_private_keys] = load_file_to_cstring(optarg);
                num_user_private_keys++;
                break;
            case 'l':
                conn_settings.prefer_low_latency = 1;
                break;
            case 'm':
                conn_settings.mutual_auth = 1;
                break;
            case 'n':
                conn_settings.only_negotiate = 1;
                break;
            case 'o':
                ocsp_response_file_path = optarg;
                break;
            case 'p':
                conn_settings.prefer_throughput = 1;
                break;
            case 'r':
                if (num_user_certificates == MAX_CERTIFICATES) {
                    fprintf(stderr, "Cannot support more than %d certificates!\n", MAX_CERTIFICATES);
                    exit(1);
                }
                certificates[num_user_certificates] = load_file_to_cstring(optarg);
                num_user_certificates++;
                break;
            case 's':
                conn_settings.self_service_blinding = 1;
                break;
            case 'd':
                conn_settings.ca_dir = optarg;
                break;
            case 't':
                conn_settings.ca_file = optarg;
                break;
            case 'i':
                conn_settings.insecure = 1;
                break;
            case 'a':
                session_ticket_key_file_path = optarg;
                break;
            case 'T':
                conn_settings.session_ticket = 0;
                break;
            case '3':
                /* Do nothing -- this argument is deprecated */
                break;
            case 'X':
                if (optarg == NULL) {
                    conn_settings.max_conns = 1;
                } else {
                    conn_settings.max_conns = atoi(optarg);
                }
                break;
            case 'w':
                fprintf(stdout, "Running s2nd in simple https server mode\n");
                conn_settings.https_server = 1;
                break;
            case 'b':
                bytes = strtoul(optarg, NULL, 10);
                GUARD_EXIT(bytes, "https-bench bytes needs to be some positive long value.");
                conn_settings.https_bench = bytes;
                break;
            case OPT_BUFFERED_SEND: {
                intmax_t send_buffer_size_scanned_value = strtoimax(optarg, 0, 10);
                if (send_buffer_size_scanned_value > UINT32_MAX || send_buffer_size_scanned_value < 0) {
                    fprintf(stderr, "<buffer size> must be a positive 32 bit value\n");
                    exit(1);
                }
                send_buffer_size = (uint32_t) send_buffer_size_scanned_value;
                break;
            }
            case 'A':
                alpn = optarg;
                break;
            case 'B':
                non_blocking = 1;
                break;
            case 'L':
                key_log_path = optarg;
                break;
            case 'P':
                if (conn_settings.psk_list_len >= S2N_MAX_PSK_LIST_LENGTH) {
                    fprintf(stderr, "Error setting psks, maximum number of psks permitted is 10.\n");
                    exit(1);
                }
                conn_settings.psk_optarg_list[conn_settings.psk_list_len++] = optarg;
                break;
            case 'E':
                max_early_data = atoi(optarg);
                break;
            case 'N':
                npn = true;
                break;
            case '?':
            default:
                fprintf(stdout, "getopt_long returned: %d", c);
                usage();
                break;
        }
    }

    if (conn_settings.prefer_throughput && conn_settings.prefer_low_latency) {
        fprintf(stderr, "prefer-throughput and prefer-low-latency options are mutually exclusive\n");
        exit(1);
    }

    if (optind < argc) {
        host = argv[optind++];
    }

    /* cppcheck-suppress duplicateCondition */
    if (optind < argc) {
        port = argv[optind++];
    }

    if (!host || !port) {
        usage();
    }

    if (setvbuf(stdin, NULL, _IONBF, 0) < 0) {
        fprintf(stderr, "Error disabling buffering for stdin\n");
        exit(1);
    }

    if (setvbuf(stdout, NULL, _IONBF, 0) < 0) {
        fprintf(stderr, "Error disabling buffering for stdout\n");
        exit(1);
    }

    memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        fprintf(stderr, "Error disabling SIGPIPE\n");
        exit(1);
    }

    if ((r = getaddrinfo(host, port, &hints, &ai)) < 0) {
        fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(r));
        exit(1);
    }

    if ((sockfd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)) == -1) {
        fprintf(stderr, "socket error: %s\n", strerror(errno));
        exit(1);
    }

    r = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &r, sizeof(int)) < 0) {
        fprintf(stderr, "setsockopt error: %s\n", strerror(errno));
        exit(1);
    }

    if (bind(sockfd, ai->ai_addr, ai->ai_addrlen) < 0) {
        fprintf(stderr, "bind error: %s\n", strerror(errno));
        exit(1);
    }

    if (listen(sockfd, 1) == -1) {
        fprintf(stderr, "listen error: %s\n", strerror(errno));
        exit(1);
    }

    if (fips_mode) {
#ifndef S2N_INTERN_LIBCRYPTO
    #if defined(OPENSSL_FIPS) || defined(OPENSSL_IS_AWSLC)
        if (FIPS_mode_set(1) == 0) {
            unsigned long fips_rc = ERR_get_error();
            char ssl_error_buf[256]; /* Openssl claims you need no more than 120 bytes for error strings */
            fprintf(stderr, "s2nd failed to enter FIPS mode with RC: %lu; String: %s\n", fips_rc, ERR_error_string(fips_rc, ssl_error_buf));
            exit(1);
        }
        printf("s2nd entered FIPS mode\n");
    #else
        fprintf(stderr, "Error entering FIPS mode. s2nd was not built against a FIPS-capable libcrypto.\n");
        exit(1);
    #endif
#endif
    }

    GUARD_EXIT(s2n_init(), "Error running s2n_init()");

    printf("Listening on %s:%s\n", host, port);

    struct s2n_config *config = s2n_config_new();
    if (!config) {
        print_s2n_error("Error getting new s2n config");
        exit(1);
    }

    if (num_user_certificates != num_user_private_keys) {
        fprintf(stderr, "Mismatched certificate(%d) and private key(%d) count!\n", num_user_certificates, num_user_private_keys);
        exit(1);
    }

    int num_certificates = 0;
    if (num_user_certificates == 0) {
        certificates[0] = default_certificate_chain;
        private_keys[0] = default_private_key;
        num_certificates = 1;
    } else {
        num_certificates = num_user_certificates;
    }

    for (int i = 0; i < num_certificates; i++) {
        struct s2n_cert_chain_and_key *chain_and_key = s2n_cert_chain_and_key_new();
        GUARD_EXIT(s2n_cert_chain_and_key_load_pem(chain_and_key, certificates[i], private_keys[i]), "Error getting certificate/key");

        if (ocsp_response_file_path) {
            int fd = open(ocsp_response_file_path, O_RDONLY);
            if (fd < 0) {
                fprintf(stderr, "Error opening OCSP response file: '%s'\n", strerror(errno));
                exit(1);
            }

            struct stat st = { 0 };
            if (fstat(fd, &st) < 0) {
                fprintf(stderr, "Error fstat-ing OCSP response file: '%s'\n", strerror(errno));
                exit(1);
            }

            uint8_t *ocsp_response = mmap(0, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
            if (s2n_cert_chain_and_key_set_ocsp_data(chain_and_key, ocsp_response, st.st_size) < 0) {
                fprintf(stderr, "Error adding ocsp response: '%s'\n", s2n_strerror(s2n_errno, "EN"));
                exit(1);
            }

            close(fd);
        }

        GUARD_EXIT(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key), "Error setting certificate/key");
    }

    s2n_set_common_server_config(max_early_data, config, conn_settings, cipher_prefs, session_ticket_key_file_path);

    if (parallelize) {
        struct sigaction sa;

        sa.sa_handler = SIG_IGN;
#if defined(SA_NOCLDWAIT)
        sa.sa_flags = SA_NOCLDWAIT;
#endif
        sigemptyset(&sa.sa_mask);
        sigaction(SIGCHLD, &sa, NULL);
    }

    if (alpn) {
        const char *protocols[] = { alpn };
        GUARD_EXIT(s2n_config_set_protocol_preferences(config, protocols, s2n_array_len(protocols)), "Failed to set alpn");
    }

    if (send_buffer_size != 0) {
        GUARD_EXIT(s2n_config_set_send_buffer_size(config, send_buffer_size), "Error setting send buffer size.");
    }

    if (npn) {
        GUARD_EXIT(s2n_config_set_npn(config, 1), "Error setting npn support");
    }

    FILE *key_log_file = NULL;

    if (key_log_path) {
        key_log_file = fopen(key_log_path, "a");
        GUARD_EXIT(key_log_file == NULL ? S2N_FAILURE : S2N_SUCCESS, "Failed to open key log file");
        GUARD_EXIT(
                s2n_config_set_key_log_cb(
                        config,
                        key_log_callback,
                        (void *) key_log_file),
                "Failed to set key log callback");
    }

    int fd;
    while ((fd = accept(sockfd, ai->ai_addr, &ai->ai_addrlen)) > 0) {
        if (non_blocking) {
            int flags = fcntl(sockfd, F_GETFL, 0);
            if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
                fprintf(stderr, "fcntl error: %s\n", strerror(errno));
                exit(1);
            }
        }

        if (!parallelize) {
            int rc = handle_connection(fd, config, conn_settings);
            close(fd);
            if (rc < 0) {
                exit(rc);
            }

            /* If max_conns was set, then exit after it is reached. Otherwise
             * unlimited connections are allow, so ignore the variable. */
            if (conn_settings.max_conns > 0) {
                if (conn_settings.max_conns-- == 1) {
                    GUARD_EXIT(s2n_cleanup(), "Error running s2n_cleanup()");
                    exit(0);
                }
            }
        } else {
            /* Fork Process, one for the Acceptor (parent), and another for the Handler (child). */
            pid_t child_pid = fork();

            if (child_pid == 0) {
                /* This is the Child Handler Thread. We should handle the connection, then exit. */
                int rc = handle_connection(fd, config, conn_settings);
                close(fd);
                _exit(rc);
            } else if (child_pid == -1) {
                close(fd);
                print_s2n_error("Error calling fork(). Acceptor unable to start handler.");
                exit(1);
            } else {
                /* This is the parent Acceptor Thread, continue listening for new connections */
                close(fd);
                continue;
            }
        }
    }

    if (key_log_file) {
        fclose(key_log_file);
    }

    GUARD_EXIT(s2n_cleanup(), "Error running s2n_cleanup()");

    return 0;
}
