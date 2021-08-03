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

//certificate chain was taken from bin/s2nd.c
static uint8_t ticket_key_name[16] = "2016.07.26.15\0";

static uint8_t default_ticket_key[32] = {0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc,
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

//rsa_1024_sha512_client_cert.pem - Expires: Jul 8th, 2117
static char rsa_certificate_chain[] =
        "-----BEGIN CERTIFICATE-----"
        "MIICeDCCAeGgAwIBAgIJAMWWsYNZd821MA0GCSqGSIb3DQEBDQUAMF8xCzAJBgNV"
        "BAYTAlVTMQswCQYDVQQIDAJXQTEQMA4GA1UEBwwHU2VhdHRsZTEPMA0GA1UECgwG"
        "QW1hem9uMQwwCgYDVQQLDANzMm4xEjAQBgNVBAMMCWxvY2FsaG9zdDAgFw0xNzA4"
        "MDEyMjQzMzJaGA8yMTE3MDcwODIyNDMzMlowXzELMAkGA1UEBhMCVVMxCzAJBgNV"
        "BAgMAldBMRAwDgYDVQQHDAdTZWF0dGxlMQ8wDQYDVQQKDAZBbWF6b24xDDAKBgNV"
        "BAsMA3MybjESMBAGA1UEAwwJbG9jYWxob3N0MIGfMA0GCSqGSIb3DQEBAQUAA4GN"
        "ADCBiQKBgQDfur5Wn20gbZo3AI9MTbXkjWIy95bHWFflhPuHJ6/fSdfiCc70XoCC"
        "n7PK7joP5dDnYEscciSLe6ngbsiXzi+6KbwvMT/0wZLHV1D+JEdcqg1nDQ8ZeFGk"
        "rnJRLrhhO4UEumRO6cXm5gLjRNI8wENo3s/C6yfKG3HxxlyHsyZ28wIDAQABozow"
        "ODALBgNVHQ8EBAMCBDAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwFAYDVR0RBA0wC4IJ"
        "MTI3LjAuMC4xMA0GCSqGSIb3DQEBDQUAA4GBAJFKwY88G4IGEu7JMdjCV742fCym"
        "JPFKjap6MW3oWVcbS8YMeaaghORgs0eB93ZH+tL3Z5eFL3QnLzrp75UqNA8YJrX2"
        "Pc95zCdDsPARNPLThZNboDExYFFXTt2bRANtdhLmSVGWX2SIoVWb+AypQRXBXUtJ"
        "5AQKE8xaETMUzKxr"
        "-----END CERTIFICATE-----";
//ecdsa_p384_pkcs1_cert.pem - Expires: Nov 10th, 2120
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

//rsa_1024_sha512_client_key.pem
static char rsa_private_key[] =
        "-----BEGIN PRIVATE KEY-----"
        "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAN+6vlafbSBtmjcA"
        "j0xNteSNYjL3lsdYV+WE+4cnr99J1+IJzvRegIKfs8ruOg/l0OdgSxxyJIt7qeBu"
        "yJfOL7opvC8xP/TBksdXUP4kR1yqDWcNDxl4UaSuclEuuGE7hQS6ZE7pxebmAuNE"
        "0jzAQ2jez8LrJ8obcfHGXIezJnbzAgMBAAECgYEArLa8M6D1nKAf+jALb8taDOt8"
        "kH4EPzYa/MuxZYAkzEp0R0JtKsc9jBl/sbxAxH8Uy1nSAk63mZpI5UKAxnhc7Hch"
        "akhSpMzD1T/+aKKR2zrnfGsamg3dQSX/NcCAaxF4ESrzGaDozRl3gFEii0vMH5HN"
        "50n6GTGcji9U6Sh+1GECQQD9xG4Sb8GnlyOgTApzLSRBCxhI5ng0e8jMB36im8Gp"
        "6i0Ct1B12IJY/pkD9L2+tgElaFHvjivRW+V/TRMK3ENjAkEA4bKofA8il/+v+zBx"
        "xD83BmQqjdHDql1HglYeRYD9iIgXmD3jjIBiqYBfR4uMI9th/ydTZIHBKhAO1qhF"
        "Gf97MQJAWuvbKD3kW6B6Qj+cauHcoHVSMSRqIxvKuNdilu5JeBCQKe32JRL6uNoX"
        "huRUa5UYWgfDe5ortuo/EtpRnU2H0wJBAJama0IL1DqDKBNR3c5xp6fzelgZmTKB"
        "evbrxt7737+fn6g2P0oMdE7R6kdWRV+10y6+MDLZTXdnKpBr11woJTECQGkoOKtp"
        "p+VC2OuraZMo6u3qPW80KdsrouSZRrErjndP5ch51H6ArPAnKMptS+b0LTR9yT6L"
        "xyNSMxtopzO5B4M="
        "-----END PRIVATE KEY-----";

//ecdsa_p384_pkcs1_key.pem
static char ecdsa_private_key[] =
        "-----BEGIN EC PRIVATE KEY-----"
        "MIGkAgEBBDCmRUplaFjwGMUdl0HdbG5Tm17w9kk3ncU62a1fyl/seOTt8GIP2Mjk"
        "N3uliGfCeSqgBwYFK4EEACKhZANiAATKnuIe71mHURO5txnECf+mBzSZFKVindnF"
        "BoqCG3AIT4mZDqFKaCKjyLLPRdG9GOagEZzHhIlKCHgrngt9MMS6kcDSfohGAHGn"
        "NYHg8DBkDnp1ziveKHMUcAQjcJQGpCs="
        "-----END EC PRIVATE KEY-----";

//dhparams_2048.pem
static char dhparams[] =
        "-----BEGIN DH PARAMETERS-----\n"
        "MIIBCAKCAQEAy1+hVWCfNQoPB+NA733IVOONl8fCumiz9zdRRu1hzVa2yvGseUSq\n"
        "Bbn6k0FQ7yMED6w5XWQKDC0z2m0FI/BPE3AjUfuPzEYGqTDf9zQZ2Lz4oAN90Sud\n"
        "luOoEhYR99cEbCn0T4eBvEf9IUtczXUZ/wj7gzGbGG07dLfT+CmCRJxCjhrosenJ\n"
        "gzucyS7jt1bobgU66JKkgMNm7hJY4/nhR5LWTCzZyzYQh2HM2Vk4K5ZqILpj/n0S\n"
        "5JYTQ2PVhxP+Uu8+hICs/8VvM72DznjPZzufADipjC7CsQ4S6x/ecZluFtbb+ZTv\n"
        "HI5CnYmkAwJ6+FSWGaZQDi8bgerFk9RWwwIBAg==\n"
        "-----END DH PARAMETERS-----\n";
