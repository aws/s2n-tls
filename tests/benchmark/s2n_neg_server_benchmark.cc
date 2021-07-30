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

#include <benchmark/benchmark.h>
#include <iostream>

#include <stdlib.h>
#include <string.h>
#include <cstring>

#include <vector>
#define STDIO_BUFSIZE  10240
#define DEBUG_PRINT 0
#define DEBUG_CIPHER 0
#define ITERATIONS 50

extern "C" {
#define S2N_ECC_EVP_SUPPORTED_CURVES_COUNT 4

#include <netinet/tcp.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <poll.h>
#include <netdb.h>

#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <getopt.h>
#include <strings.h>
#include <errno.h>
#include <fcntl.h>

#include <s2n.h>
#include "bin/common.h"
#include <error/s2n_errno.h>
#include <openssl/err.h>
#include <openssl/crypto.h>


#include "tls/s2n_config.h"
#include "tls/s2n_cipher_suites.h"
#include "utils/s2n_safety.h"
#include <error/s2n_errno.h>

#include "stuffer/s2n_stuffer.h"
#include "utils/s2n_random.h"
#include "tests/s2n_test.h"
#include "tests/testlib/s2n_testlib.h"
#define MAX_CERTIFICATES 50
}

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

static char ecdsa_certificate_chain[] =
        "-----BEGIN CERTIFICATE-----"
        "MIICaTCCAe6gAwIBAgIUMxUae+azda1MSZ3escJfJTZwRakwCgYIKoZIzj0EAwIw"
        "XzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAldBMRAwDgYDVQQHDAdTZWF0dGxlMQ8w"
        "DQYDVQQKDAZBbWF6b24xDDAKBgNVBAsMA3MybjESMBAGA1UEAwwJbG9jYWxob3N0"
        "MCAXDTIwMTIwNDA3NTEwMloYDzIxMjAxMTEwMDc1MTAyWjBfMQswCQYDVQQGEwJV"
        "UzELMAkGA1UECAwCV0ExEDAOBgNVBAcMB1NlYXR0bGUxDzANBgNVBAoMBkFtYXpv"
        "bjEMMAoGA1UECwwDczJuMRIwEAYDVQQDDAlsb2NhbGhvc3QwdjAQBgcqhkjOPQIB"
        "BgUrgQQAIgNiAATKnuIe71mHURO5txnECf+mBzSZFKVindnFBoqCG3AIT4mZDqFK"
        "aCKjyLLPRdG9GOagEZzHhIlKCHgrngt9MMS6kcDSfohGAHGnNYHg8DBkDnp1zive"
        "KHMUcAQjcJQGpCujaTBnMB0GA1UdDgQWBBSSYvAHZOZ/spxQuKK11lykmTDhDjAf"
        "BgNVHSMEGDAWgBSSYvAHZOZ/spxQuKK11lykmTDhDjAPBgNVHRMBAf8EBTADAQH/"
        "MBQGA1UdEQQNMAuCCTEyNy4wLjAuMTAKBggqhkjOPQQDAgNpADBmAjEAjByIcQY6"
        "TczA32zfkSCVHFEnPQ2ZXZXzLLvZB1SqOwBpEqjIrRAZk0QuQouEAO7EAjEAhPUd"
        "HpsJz7U+DMG1UBrMnXZoLONyBfbnHoz5P+jnYI5ySxDPzqFBkNDKriI2cTc/"
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

static char ecdsa_private_key[] =
        "-----BEGIN EC PRIVATE KEY-----"
        "MIGkAgEBBDCmRUplaFjwGMUdl0HdbG5Tm17w9kk3ncU62a1fyl/seOTt8GIP2Mjk"
        "N3uliGfCeSqgBwYFK4EEACKhZANiAATKnuIe71mHURO5txnECf+mBzSZFKVindnF"
        "BoqCG3AIT4mZDqFKaCKjyLLPRdG9GOagEZzHhIlKCHgrngt9MMS6kcDSfohGAHGn"
        "NYHg8DBkDnp1ziveKHMUcAQjcJQGpCs="
        "-----END EC PRIVATE KEY-----";

static char dhparams[] =
        "-----BEGIN DH PARAMETERS-----\n"
        "MIIBCAKCAQEAy1+hVWCfNQoPB+NA733IVOONl8fCumiz9zdRRu1hzVa2yvGseUSq\n"
        "Bbn6k0FQ7yMED6w5XWQKDC0z2m0FI/BPE3AjUfuPzEYGqTDf9zQZ2Lz4oAN90Sud\n"
        "luOoEhYR99cEbCn0T4eBvEf9IUtczXUZ/wj7gzGbGG07dLfT+CmCRJxCjhrosenJ\n"
        "gzucyS7jt1bobgU66JKkgMNm7hJY4/nhR5LWTCzZyzYQh2HM2Vk4K5ZqILpj/n0S\n"
        "5JYTQ2PVhxP+Uu8+hICs/8VvM72DznjPZzufADipjC7CsQ4S6x/ecZluFtbb+ZTv\n"
        "HI5CnYmkAwJ6+FSWGaZQDi8bgerFk9RWwwIBAg==\n"
        "-----END DH PARAMETERS-----\n";

static const uint8_t hex_inverse[256] = {
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        0,   1,   2,   3,   4,   5,   6,   7,   8,   9, 255, 255, 255, 255, 255, 255,
        255,  10,  11,  12,  13,  14,  15, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255,  10,  11,  12,  13,  14,  15, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
};

uint8_t ticket_key_name[16] = "2016.07.26.15\0";

uint8_t default_ticket_key[32] = {0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc,
                                  0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63, 0x90, 0xb6, 0xc7, 0x3b,
                                  0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2,
                                  0xb3, 0xe5 };

#define MAX_KEY_LEN 32
#define MAX_VAL_LEN 255

struct session_cache_entry {
    uint8_t key[MAX_KEY_LEN];
    uint8_t key_len;
    uint8_t value[MAX_VAL_LEN];
    uint8_t value_len;
};

struct session_cache_entry session_cache[256];


void print_s2n_error(const char *app_error)
{
    fprintf(stderr, "[%d] %s: '%s' : '%s'\n", getpid(), app_error, s2n_strerror(s2n_errno, "EN"),
            s2n_strerror_debug(s2n_errno, "EN"));
}

static int wait_for_event(int fd, s2n_blocked_status blocked)
{
    struct pollfd reader = {fd, 0};

    switch (blocked) {
        case S2N_NOT_BLOCKED:
            return S2N_SUCCESS;
        case S2N_BLOCKED_ON_READ:
            reader.events |= POLLIN;
            break;
        case S2N_BLOCKED_ON_WRITE:
            reader.events |= POLLOUT;
            break;
        case S2N_BLOCKED_ON_EARLY_DATA:
        case S2N_BLOCKED_ON_APPLICATION_INPUT:
            // This case is not encountered by the s2nc/s2nd applications,
            //but is detected for completeness
            return S2N_SUCCESS;
    }

    if (poll(&reader, 1, -1) < 0) {
        fprintf(stderr, "Failed to poll connection: %s\n", strerror(errno));

        S2N_ERROR_PRESERVE_ERRNO();
    }

    return S2N_SUCCESS;
}

int key_log_callback(void *file, struct s2n_connection *conn, uint8_t *logline, size_t len)
{
    if (fwrite(logline, 1, len, (FILE *)file) != len) {
        return S2N_FAILURE;
    }

    if (fprintf((FILE *)file, "\n") < 0) {
        return S2N_FAILURE;
    }

    return fflush((FILE *)file);
}

int s2n_str_hex_to_bytes(const unsigned char *hex, uint8_t *out_bytes, uint32_t max_out_bytes_len)
{
    GUARD_EXIT_NULL(hex);
    GUARD_EXIT_NULL(out_bytes);

    uint32_t len_with_spaces = strlen((const char *)hex);
    size_t i = 0, j = 0;
    while (j < len_with_spaces) {
        if (hex[j] == ' ') {
            j++;
            continue;
        }

        uint8_t high_nibble = hex_inverse[hex[j]];
        if (high_nibble == 255) {
            fprintf(stderr, "Invalid HEX encountered\n");
            return S2N_FAILURE;
        }

        uint8_t low_nibble = hex_inverse[hex[j + 1]];
        if (low_nibble == 255) {
            fprintf(stderr, "Invalid HEX encountered\n");
            return S2N_FAILURE;
        }

        if(max_out_bytes_len < i) {
            fprintf(stderr, "Insufficient memory for bytes buffer, try increasing the allocation size\n");
            return S2N_FAILURE;
        }
        out_bytes[i] = high_nibble << 4 | low_nibble;

        i++;
        j+=2;
    }

    return S2N_SUCCESS;
}

static int s2n_get_psk_hmac_alg(s2n_psk_hmac *psk_hmac, char *hmac_str)
{
    GUARD_EXIT_NULL(psk_hmac);
    GUARD_EXIT_NULL(hmac_str);

    if (strcmp(hmac_str, "SHA256") == 0) {
        *psk_hmac = S2N_PSK_HMAC_SHA256;
    } else if (strcmp(hmac_str, "SHA384") == 0) {
        *psk_hmac = S2N_PSK_HMAC_SHA384;
    } else {
        return S2N_FAILURE;
    }
    return S2N_SUCCESS;
}

static int s2n_setup_external_psk(struct s2n_psk **psk, char *params)
{
    GUARD_EXIT_NULL(psk);
    GUARD_EXIT_NULL(params);

    size_t token_idx = 0;
    for (char *token = strtok(params, ","); token != NULL; token = strtok(NULL, ","), token_idx++) {
        switch (token_idx) {
            case 0:
                GUARD_EXIT(s2n_psk_set_identity(*psk, (const uint8_t *)token, strlen(token)),
                           "Error setting psk identity\n");
                break;
            case 1: {
                uint32_t max_secret_len = strlen(token)/2;
                uint8_t *secret = (uint8_t*)malloc(max_secret_len);
                GUARD_EXIT_NULL(secret);
                GUARD_EXIT(s2n_str_hex_to_bytes((const unsigned char *)token, secret, max_secret_len), "Error converting hex-encoded psk secret to bytes\n");
                GUARD_EXIT(s2n_psk_set_secret(*psk, secret, max_secret_len), "Error setting psk secret\n");
                free(secret);
            }
                break;
            case 2: {
                s2n_psk_hmac psk_hmac_alg = (s2n_psk_hmac)0;
                GUARD_EXIT(s2n_get_psk_hmac_alg(&psk_hmac_alg, token), "Invalid psk hmac algorithm\n");
                GUARD_EXIT(s2n_psk_set_hmac(*psk, psk_hmac_alg), "Error setting psk hmac algorithm\n");
            }
                break;
            default:
                break;
        }
    }

    return S2N_SUCCESS;
}

int s2n_setup_external_psk_list(struct s2n_connection *conn, char *psk_optarg_list[S2N_MAX_PSK_LIST_LENGTH], size_t psk_list_len)
{
    GUARD_EXIT_NULL(conn);
    GUARD_EXIT_NULL(psk_optarg_list);

    for (size_t i = 0; i < psk_list_len; i++) {
        struct s2n_psk *psk = s2n_external_psk_new();
        GUARD_EXIT_NULL(psk);
        GUARD_EXIT(s2n_setup_external_psk(&psk, psk_optarg_list[i]), "Error setting external PSK parameters\n");
        GUARD_EXIT(s2n_connection_append_psk(conn, psk), "Error appending psk to the connection\n");
        GUARD_EXIT(s2n_psk_free(&psk), "Error freeing psk\n");
    }
    return S2N_SUCCESS;
}

int early_data_recv(struct s2n_connection *conn)
{
    uint32_t max_early_data_size = 0;
    GUARD_RETURN(s2n_connection_get_max_early_data_size(conn, &max_early_data_size), "Error getting max early data size");
    if (max_early_data_size == 0) {
        return S2N_SUCCESS;
    }

    ssize_t total_data_recv = 0;
    ssize_t data_recv = 0;
    bool server_success = 0;
    s2n_blocked_status blocked = (s2n_blocked_status)0;
    uint8_t *early_data_received = (uint8_t*)malloc(max_early_data_size);
    GUARD_EXIT_NULL(early_data_received);

    do {
        server_success = (s2n_recv_early_data(conn, early_data_received + total_data_recv,
                                              max_early_data_size - total_data_recv, &data_recv, &blocked) >= S2N_SUCCESS);
        total_data_recv += data_recv;
    } while (!server_success);

    if (total_data_recv > 0) {
        fprintf(stdout, "Early Data received: ");
        for (size_t i = 0; i < (size_t)total_data_recv; i++) {
            fprintf(stdout, "%c", early_data_received[i]);
        }
        fprintf(stdout, "\n");
    }

    free(early_data_received);

    return S2N_SUCCESS;
}

int cache_store_callback(struct s2n_connection *conn, void *ctx, uint64_t ttl, const void *key, uint64_t key_size, const void *value, uint64_t value_size)
{
    struct session_cache_entry *cache = (session_cache_entry*)ctx;
    POSIX_ENSURE_INCLUSIVE_RANGE(1, key_size, MAX_KEY_LEN);
    POSIX_ENSURE_INCLUSIVE_RANGE(1, value_size, MAX_VAL_LEN);

    uint8_t idx = ((const uint8_t *)key)[0];

    memcpy(cache[idx].key, key, key_size);
    memcpy(cache[idx].value, value, value_size);

    cache[idx].key_len = key_size;
    cache[idx].value_len = value_size;

    return 0;
}

int cache_retrieve_callback(struct s2n_connection *conn, void *ctx, const void *key, uint64_t key_size, void *value, uint64_t * value_size)
{
    struct session_cache_entry *cache = (session_cache_entry*)ctx;

    POSIX_ENSURE_INCLUSIVE_RANGE(1, key_size, MAX_KEY_LEN);

    uint8_t idx = ((const uint8_t *)key)[0];

    POSIX_ENSURE(cache[idx].key_len == key_size, S2N_ERR_INVALID_ARGUMENT);
    POSIX_ENSURE(memcmp(cache[idx].key, key, key_size) == 0, S2N_ERR_INVALID_ARGUMENT);
    POSIX_ENSURE(*value_size >= cache[idx].value_len, S2N_ERR_INVALID_ARGUMENT);

    *value_size = cache[idx].value_len;
    memcpy(value, cache[idx].value, cache[idx].value_len);

    for (uint64_t i = 0; i < key_size; i++) {
        printf("%02x", ((const uint8_t *)key)[i]);
    }
    printf("\n");

    return 0;
}

int cache_delete_callback(struct s2n_connection *conn, void *ctx, const void *key, uint64_t key_size)
{
    struct session_cache_entry *cache = (session_cache_entry*)ctx;

    POSIX_ENSURE_INCLUSIVE_RANGE(1, key_size, MAX_KEY_LEN);

    uint8_t idx = ((const uint8_t *)key)[0];

    if (cache[idx].key_len != 0) {
        POSIX_ENSURE(cache[idx].key_len == key_size, S2N_ERR_INVALID_ARGUMENT);
        POSIX_ENSURE(memcmp(cache[idx].key, key, key_size) == 0, S2N_ERR_INVALID_ARGUMENT);
    }

    cache[idx].key_len = 0;
    cache[idx].value_len = 0;

    return 0;
}

static uint8_t unsafe_verify_host_fn(const char *host_name, size_t host_name_len, void *data)
{
    return 1;
}


struct conn_settings {
    unsigned mutual_auth:1;
    unsigned self_service_blinding:1;
    unsigned only_negotiate:1;
    unsigned prefer_throughput:1;
    unsigned prefer_low_latency:1;
    unsigned enable_mfl:1;
    unsigned session_ticket:1;
    unsigned session_cache:1;
    unsigned insecure:1;
    unsigned use_corked_io:1;
    unsigned https_server:1;
    uint32_t https_bench;
    int max_conns;
    const char *ca_dir;
    const char *ca_file;
    char *psk_optarg_list[S2N_MAX_PSK_LIST_LENGTH];
    size_t psk_list_len;
};

int negotiate(struct s2n_connection *conn, int fd)
{
    s2n_blocked_status blocked;
    while (s2n_negotiate(conn, &blocked) != S2N_SUCCESS) {
        if (s2n_error_get_type(s2n_errno) != S2N_ERR_T_BLOCKED) {
            fprintf(stderr, "Failed to negotiate: '%s'. %s\n",
                    s2n_strerror(s2n_errno, "EN"),
                    s2n_strerror_debug(s2n_errno, "EN"));
            fprintf(stderr, "Alert: %d\n",
                    s2n_connection_get_alert(conn));
            S2N_ERROR_PRESERVE_ERRNO();
        }

        if (wait_for_event(fd, blocked) != S2N_SUCCESS) {
            S2N_ERROR_PRESERVE_ERRNO();
        }
    }

    /* Now that we've negotiated, print some parameters */
    int client_hello_version;
    int client_protocol_version;
    int server_protocol_version;
    int actual_protocol_version;

    if ((client_hello_version = s2n_connection_get_client_hello_version(conn)) < 0) {
        fprintf(stderr, "Could not get client hello version\n");
        POSIX_BAIL(S2N_ERR_CLIENT_HELLO_VERSION);
    }
    if ((client_protocol_version = s2n_connection_get_client_protocol_version(conn)) < 0) {
        fprintf(stderr, "Could not get client protocol version\n");
        POSIX_BAIL(S2N_ERR_CLIENT_PROTOCOL_VERSION);
    }
    if ((server_protocol_version = s2n_connection_get_server_protocol_version(conn)) < 0) {
        fprintf(stderr, "Could not get server protocol version\n");
        POSIX_BAIL(S2N_ERR_SERVER_PROTOCOL_VERSION);
    }
    if ((actual_protocol_version = s2n_connection_get_actual_protocol_version(conn)) < 0) {
        fprintf(stderr, "Could not get actual protocol version\n");
        POSIX_BAIL(S2N_ERR_ACTUAL_PROTOCOL_VERSION);
    }
    if(DEBUG_PRINT) {
        printf("CONNECTED:\n");
        printf("Handshake: %s\n", s2n_connection_get_handshake_type_name(conn));
        printf("Client hello version: %d\n", client_hello_version);
        printf("Client protocol version: %d\n", client_protocol_version);
        printf("Server protocol version: %d\n", server_protocol_version);
        printf("Actual protocol version: %d\n", actual_protocol_version);
    }

    if (s2n_get_server_name(conn)) {
        if(DEBUG_PRINT)
            printf("Server name: %s\n", s2n_get_server_name(conn));
    }

    if (s2n_get_application_protocol(conn)) {
        if(DEBUG_PRINT)
            printf("Application protocol: %s\n", s2n_get_application_protocol(conn));
    }

    if(DEBUG_PRINT) {
        printf("Curve: %s\n", s2n_connection_get_curve(conn));
        printf("KEM: %s\n", s2n_connection_get_kem_name(conn));
        printf("KEM Group: %s\n", s2n_connection_get_kem_group_name(conn));
    }

    uint32_t length;
    const uint8_t *status = s2n_connection_get_ocsp_response(conn, &length);
    if (status && length > 0) {
        fprintf(stderr, "OCSP response received, length %u\n", length);
    }

    if(DEBUG_CIPHER)
        printf("Cipher negotiated: %s\n", s2n_connection_get_cipher(conn));

    bool session_resumed = s2n_connection_is_session_resumed(conn);
    if (session_resumed) {
        printf("Resumed session\n");
    }

    uint16_t identity_length = 0;
    GUARD_EXIT(s2n_connection_get_negotiated_psk_identity_length(conn, &identity_length), "Error getting negotiated psk identity length from the connection\n");
    if (identity_length != 0 && !session_resumed) {
        uint8_t *identity = (uint8_t*)malloc(identity_length);
        GUARD_EXIT_NULL(identity);
        GUARD_EXIT(s2n_connection_get_negotiated_psk_identity(conn, identity, identity_length), "Error getting negotiated psk identity from the connection\n");
        if(DEBUG_PRINT)
            printf("Negotiated PSK identity: %s\n", identity);
        free(identity);
    }

    s2n_early_data_status_t early_data_status = (s2n_early_data_status_t)0;
    GUARD_EXIT(s2n_connection_get_early_data_status(conn, &early_data_status), "Error getting early data status");
    const char *status_str = NULL;
    switch(early_data_status) {
        case S2N_EARLY_DATA_STATUS_OK: status_str = "IN PROGRESS"; break;
        case S2N_EARLY_DATA_STATUS_NOT_REQUESTED: status_str = "NOT REQUESTED"; break;
        case S2N_EARLY_DATA_STATUS_REJECTED: status_str = "REJECTED"; break;
        case S2N_EARLY_DATA_STATUS_END: status_str = "ACCEPTED"; break;
    }
    GUARD_EXIT_NULL(status_str);

    if(DEBUG_PRINT)
        printf("s2n is ready\n");
    return 0;
}

int handle_connection(int fd, struct s2n_config *config, struct conn_settings settings, int suite_num)
{
    struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
    if (!conn) {
        print_s2n_error("Error getting new s2n connection");
        S2N_ERROR_PRESERVE_ERRNO();
    }

    if (settings.self_service_blinding) {
        s2n_connection_set_blinding(conn, S2N_SELF_SERVICE_BLINDING);
    }

    if (settings.mutual_auth) {
        GUARD_RETURN(s2n_config_set_client_auth_type(config, S2N_CERT_AUTH_REQUIRED), "Error setting client auth type");

        if (settings.ca_dir || settings.ca_file) {
            GUARD_RETURN(s2n_config_set_verification_ca_location(config, settings.ca_file, settings.ca_dir), "Error adding verify location");
        }

        if (settings.insecure) {
            GUARD_RETURN(s2n_config_disable_x509_verification(config), "Error disabling X.509 validation");
        }
    }

    GUARD_RETURN(s2n_connection_set_config(conn, config), "Error setting configuration");

    if (settings.prefer_throughput) {
        GUARD_RETURN(s2n_connection_prefer_throughput(conn), "Error setting prefer throughput");
    }

    if (settings.prefer_low_latency) {
        GUARD_RETURN(s2n_connection_prefer_low_latency(conn), "Error setting prefer low latency");
    }

    GUARD_RETURN(s2n_connection_set_fd(conn, fd), "Error setting file descriptor");

    if (settings.use_corked_io) {
        GUARD_RETURN(s2n_connection_use_corked_io(conn), "Error setting corked io");
    }

    GUARD_RETURN(
            s2n_setup_external_psk_list(conn, settings.psk_optarg_list, settings.psk_list_len),
            "Error setting external psk list");

    GUARD_RETURN(early_data_recv(conn), "Error receiving early data");

    if (negotiate(conn, fd) != S2N_SUCCESS) {
        if (settings.mutual_auth) {
            if (!s2n_connection_client_cert_used(conn)) {
                print_s2n_error("Error: Mutual Auth was required, but not negotiated");
            }
        }

        S2N_ERROR_PRESERVE_ERRNO();
    }

    GUARD_EXIT(s2n_connection_free_handshake(conn), "Error freeing handshake memory after negotiation");

    s2n_blocked_status blocked;
    s2n_shutdown(conn, &blocked);

    GUARD_RETURN(s2n_connection_wipe(conn), "Error wiping connection");

    GUARD_RETURN(s2n_connection_free(conn), "Error freeing connection");

    return 0;
}



int main(int argc, char** argv) {
    struct addrinfo hints, *ai;
    int r, sockfd = 0;

    const char *host = "localhost";
    const char *port = "8000";

    const char *session_ticket_key_file_path = NULL;
    const char *cipher_prefs = "test_all_tls12";


    int num_user_certificates = 0;
    int num_user_private_keys = 0;
    const char *certificates[MAX_CERTIFICATES] = {0};
    const char *private_keys[MAX_CERTIFICATES] = {0};

    struct conn_settings conn_settings = {0};


    int parallelize = 0;

    conn_settings.session_ticket = 1;
    conn_settings.session_cache = 0;
    conn_settings.max_conns = -1;
    conn_settings.psk_list_len = 0;

    //ENABLING CORKED IO
    conn_settings.use_corked_io = 1;

    int max_early_data = 0;

    s2n_init();

    if (conn_settings.prefer_throughput && conn_settings.prefer_low_latency) {
        fprintf(stderr, "prefer-throughput and prefer-low-latency options are mutually exclusive\n");
        exit(1);
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
        printf("Error: %d\n", r);
        printf("Errno: %s\n", strerror(errno));
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

    if (DEBUG_PRINT)
        printf("Listening on %s:%s\n", host, port);

    struct s2n_config *config = s2n_config_new();
    if (!config) {
        print_s2n_error("Error getting new s2n config");
        exit(1);
    }

    GUARD_EXIT(s2n_config_set_server_max_early_data_size(config, max_early_data),
               "Error setting max early data");

    GUARD_EXIT(s2n_config_add_dhparams(config, dhparams), "Error adding DH parameters");

    GUARD_EXIT(s2n_config_set_cipher_preferences(config, cipher_prefs), "Error setting cipher prefs");

    GUARD_EXIT(s2n_config_set_cache_store_callback(config, cache_store_callback, session_cache),
               "Error setting cache store callback");

    GUARD_EXIT(s2n_config_set_cache_retrieve_callback(config, cache_retrieve_callback, session_cache),
               "Error setting cache retrieve callback");

    GUARD_EXIT(s2n_config_set_cache_delete_callback(config, cache_delete_callback, session_cache),
               "Error setting cache retrieve callback");

    if (conn_settings.enable_mfl) {
        GUARD_EXIT(s2n_config_accept_max_fragment_length(config),
                   "Error enabling TLS maximum fragment length extension in server");
    }

    if (s2n_config_set_verify_host_callback(config, unsafe_verify_host_fn, NULL)) {
        print_s2n_error("Failure to set hostname verification callback");
        exit(1);
    }

    if (conn_settings.session_ticket) {
        GUARD_EXIT(s2n_config_set_session_tickets_onoff(config, 1), "Error enabling session tickets");
    }

    if (conn_settings.session_cache) {
        GUARD_EXIT(s2n_config_set_session_cache_onoff(config, 1), "Error enabling session cache using id");
    }

    if (conn_settings.session_ticket || conn_settings.session_cache) {
        /* Key initialization */
        uint8_t *st_key;
        uint32_t st_key_length;

        if (session_ticket_key_file_path) {
            int fd = open(session_ticket_key_file_path, O_RDONLY);
            GUARD_EXIT(fd, "Error opening session ticket key file");

            struct stat st;
            GUARD_EXIT(fstat(fd, &st), "Error fstat-ing session ticket key file");

            st_key = (uint8_t *) mmap(0, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
            st_key_length = st.st_size;

            close(fd);
        } else {
            st_key = default_ticket_key;
            st_key_length = sizeof(default_ticket_key);
        }

        if (s2n_config_add_ticket_crypto_key(config, ticket_key_name, strlen((char *) ticket_key_name), st_key,
                                             st_key_length, 0) != 0) {
            fprintf(stderr, "Error adding ticket key: '%s'\n", s2n_strerror(s2n_errno, "EN"));
            exit(1);
        }
    }

    for (int j = 0; j < 36 ; ++j) {
        int suite_num = j;
        int repeats = 0;
        if (num_user_certificates != num_user_private_keys) {
            fprintf(stderr, "Mismatched certificate(%d) and private key(%d) count!\n", num_user_certificates,
                    num_user_private_keys);
            exit(1);
        }

        int num_certificates = 0;
        if (num_user_certificates == 0) {
            if (suite_num < 29) {
                certificates[0] = default_certificate_chain;
                private_keys[0] = default_private_key;
                num_certificates = 1;
            }
            else {
                certificates[0] = ecdsa_certificate_chain;
                private_keys[0] = ecdsa_private_key;
                num_certificates = 1;
            }
        } else {
            num_certificates = num_user_certificates;
        }

        //Modify cert/key if using ECDSA
        for (int i = 0; i < num_certificates; i++) {
            struct s2n_cert_chain_and_key *chain_and_key = s2n_cert_chain_and_key_new();
            GUARD_EXIT(s2n_cert_chain_and_key_load_pem(chain_and_key, certificates[i], private_keys[i]),
                       "Error getting certificate/key");

            GUARD_EXIT(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key),
                       "Error setting certificate/key");
        }

        //Complete benchmark for specified number of iterations
        for(repeats = 0; repeats < ITERATIONS; repeats++) {
            int fd;
            bool stop_listen = false;
            while ((!stop_listen) && (fd = accept(sockfd, ai->ai_addr, &ai->ai_addrlen)) > 0) {
                if (!parallelize) {

                    int rc = handle_connection(fd, config, conn_settings,suite_num);
                    stop_listen = true;
                    close(fd);

                    if (rc < 0) {
                        exit(rc);
                    }

                    /* If max_conns was set, then exit after it is reached. Otherwise
                     * unlimited connections are allow, so ignore the variable. */
                    if (conn_settings.max_conns > 0) {
                        if (conn_settings.max_conns-- == 1) {
                            exit(0);
                        }
                    }
                }
            }
        }
    }
    close(sockfd);
    s2n_cleanup();
    return 0;
}