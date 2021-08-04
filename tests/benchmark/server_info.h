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

static uint8_t unsafe_verify_host_fn(const char *host_name, size_t host_name_len, void *data) {
    return 1;
}


struct conn_settings {
    unsigned mutual_auth: 1;
    unsigned self_service_blinding: 1;
    unsigned only_negotiate: 1;
    unsigned prefer_throughput: 1;
    unsigned prefer_low_latency: 1;
    unsigned enable_mfl: 1;
    unsigned session_ticket: 1;
    unsigned session_cache: 1;
    unsigned insecure: 1;
    unsigned use_corked_io: 1;
    unsigned https_server: 1;
    uint32_t https_bench;
    int max_conns;
    const char *ca_dir;
    const char *ca_file;
    char *psk_optarg_list[S2N_MAX_PSK_LIST_LENGTH];
    size_t psk_list_len;
};

static uint8_t ticket_key_name[16] = "2016.07.26.15\0";

static uint8_t default_ticket_key[32] = {0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc,
                                         0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63, 0x90, 0xb6, 0xc7, 0x3b,
                                         0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2,
                                         0xb3, 0xe5 };


struct session_cache_entry session_cache[256];

//rsa_2048_sha384_client_cert.pem - Expires: Jul 8th, 2117
static char rsa_certificate_chain[] =
        "-----BEGIN CERTIFICATE-----"
        "MIIDfTCCAmWgAwIBAgIJAPUg4P1R3ctAMA0GCSqGSIb3DQEBDAUAMF8xCzAJBgNV"
        "BAYTAlVTMQswCQYDVQQIDAJXQTEQMA4GA1UEBwwHU2VhdHRsZTEPMA0GA1UECgwG"
        "QW1hem9uMQwwCgYDVQQLDANzMm4xEjAQBgNVBAMMCWxvY2FsaG9zdDAgFw0xNzA4"
        "MDEyMjQzMzJaGA8yMTE3MDcwODIyNDMzMlowXzELMAkGA1UEBhMCVVMxCzAJBgNV"
        "BAgMAldBMRAwDgYDVQQHDAdTZWF0dGxlMQ8wDQYDVQQKDAZBbWF6b24xDDAKBgNV"
        "BAsMA3MybjESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEFAAOC"
        "AQ8AMIIBCgKCAQEA+gyp3fZTLrvWsZ8QxBIoLItRcSveQc4HavylagfNIawpnRbu"
        "39Lu2dzJSDk9so04iPm5+OLVAY8lhH9vPOSyhCL/GxikxkKgCvLWv4c4fVBeWt5Z"
        "S5xgOVsaKUR9oVfhTHLlc6M/gA5NW0Wbh34DZHAFCF9noGGoKKXpnDTyApGBYTHW"
        "XXEcL2sPKF/jU9maGPQzX7joHlHWSx1kiWTne1Gn7NJrmxrYUrn9VjM15bwi94gZ"
        "LE5TsCCoPFIzbzyKattYFJ8xNHERcf/Ss+0VCYCAT2g0GmykjK3znpKPCRSakPfx"
        "Xqfpx0MJLsh9zG1eqkQV+zc4NXursZ61ydBlLQIDAQABozowODALBgNVHQ8EBAMC"
        "BDAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwFAYDVR0RBA0wC4IJMTI3LjAuMC4xMA0G"
        "CSqGSIb3DQEBDAUAA4IBAQBVEGuaKg2pdynqZHiMr67WlbHqAE+9NvT5ouwb81VZ"
        "/UH0hawwRJAQgSa09sUNyp1tGmV7OrLIzVyp0HcpNt4RbASmk9eDwPO/woggGWXD"
        "f0go1LlKPcB/IoMvOmEX8CqqNWncYproXEaHT31hwQRtrT+bfU8MbH76eQ5vC2Fo"
        "RfUfHW6mjc8plw786BdKIg0B5r9rHMTrmFeP/HlDP5fkS4wH5y9hLGqkchBDUtAa"
        "wvXRARKV/xCvZMqcwPY6sqbpZ5surR4GEe9KrgodmtWYCq12TIfmucfkAicFcCQa"
        "fxZRly5wMFwzjqcyM01lzDCqzhxC7nVljCJie8brb2mG"
        "-----END CERTIFICATE-----";

//rsa_2048_sha384_client_key.pem
static char rsa_private_key[] =
        "-----BEGIN PRIVATE KEY-----"
        "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQD6DKnd9lMuu9ax"
        "nxDEEigsi1FxK95Bzgdq/KVqB80hrCmdFu7f0u7Z3MlIOT2yjTiI+bn44tUBjyWE"
        "f2885LKEIv8bGKTGQqAK8ta/hzh9UF5a3llLnGA5WxopRH2hV+FMcuVzoz+ADk1b"
        "RZuHfgNkcAUIX2egYagopemcNPICkYFhMdZdcRwvaw8oX+NT2ZoY9DNfuOgeUdZL"
        "HWSJZOd7Uafs0mubGthSuf1WMzXlvCL3iBksTlOwIKg8UjNvPIpq21gUnzE0cRFx"
        "/9Kz7RUJgIBPaDQabKSMrfOeko8JFJqQ9/Fep+nHQwkuyH3MbV6qRBX7Nzg1e6ux"
        "nrXJ0GUtAgMBAAECggEBAOcHnEtAtEqRsyQZ29vNCuFdN7pg1dHnEmN/WzZETvu1"
        "nh1OexbCRX11yWO5v4+he4LTeUjEDBqMsBVjyNtyUp5T13CprFSiakyzYkdEIKVo"
        "BEXg+pApw5461kkaxxizoa6I2gel5Z3jmQWjorflbiz2cy/xNkWw9TXZVabGJHTJ"
        "OD+C6afzcImpCfdNVPQ2NvZpyNGwxDwimrxbIpowormedFjG0YscdruSAY4R1D/f"
        "Z8iqoUGb22Mlu0vtGT8rb5Gz/VcnzAVjKRmExo4WBCCi7zg6vJ6QwYd9SYgObYJr"
        "JztT3HtQWEk28ip4bNmLgVjDjtAAePEp0e6FwiB8nAECgYEA/jgBHmtx2YGuH6ns"
        "PQEGnOyp2CGCi1lSAcH76pViOBDRnjr1oP1mOFjYqk9OgngF9M3sEnID5dl4FoDr"
        "C12nyV/M9ZRlhy3Vq+5armWIUITFwKNpO1NGXQB9LPYbVA6Mt2Vgntqqc2id9/vA"
        "sgZhdw4Rcjelspx+Gi3+hdlIX6ECgYEA+80uPpzyVpy4BBcYG+IDi07agn7w99LN"
        "vo4/NeFlBPFYGjywaC90Ju0o8CFt8QL0E4tPv8jhWzTqh3FupKbI4R5jLlVzyoHK"
        "cxdJr7WIK4vnXFtJu2tECudHVMGYhY2NkAILXfNyksYThB7/LJkhEK+f9Got8gZK"
        "xXasU6EfSg0CgYBcbNojSCcNUDOROYM1LrFLzlN1y8EdjqzdDLzdLdCW166OW5tA"
        "G8DVTaAAU3MUxjRMK63fiupV37nkXJyX9kXxVc47nudGvWhI6RC5BRsJQyxufDrf"
        "IcicOXhJJ3UKG3wXlVkKiC+eY/PC3BnT37QBx/CZ2Rd6F6FVPVGjMjs44QKBgBSO"
        "LWZDHa1gYc1DrV4pVyy6JTBd+IHinZUeu55EZiC/KvgJWEVJCmxbE+p2cCkqmo41"
        "4y6+0VbGvRaNdgDO9Lsb5fDUXP19Fu/KSOOlKBaV9y8c7Kn2GbniI3qRy0erxJCq"
        "+g6TXxkIPnOcrCwR3BcmnyIuwM1vIg94npy9HHbJAoGBALQa7hybvU+K9QhKJ/UA"
        "Ek0GF+8uYfJtQ27U+lXVXIq85lveXAUZ7S/d5k5WklU6iZTYhljEWnLSpsXReyYi"
        "4UlMKX+zTAsL3a5o7GtM0LbV8ZyecTt9k8xK8T/PdS0/w78KwTO/13OdItuMi0vx"
        "Q00ZFPpn7NMd+V9tAUhofrET"
        "-----END PRIVATE KEY-----";

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