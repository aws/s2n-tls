import hashlib
import hmac

# The following PEM-encoded ECC private keys were used to generate the ECC shared secrets.
# These private keys are also used in s2n/tests/unit/s2n_tls13_hybrid_shared_secret_test.c.
#
# #define CLIENT_X25519_PRIV_KEY "-----BEGIN PRIVATE KEY-----\n"\
#                                "MC4CAQAwBQYDK2VuBCIEIIgzBrAp631nCDaoA7ilx/8S/cW1lddVQOw9869sROBF\n"\
#                                "-----END PRIVATE KEY-----"
#
# #define SERVER_X25519_PRIV_KEY "-----BEGIN PRIVATE KEY-----\n"\
#                                "MC4CAQAwBQYDK2VuBCIEIIBo+KJ2Zs3vRHQ3sYgHL4zTQPlJPl1y7sW8HT9qRE96\n"\
#                                "-----END PRIVATE KEY-----"
#
# #define CLIENT_SECP256R1_PRIV_KEY "-----BEGIN EC PARAMETERS-----\n"\
#                                   "BggqhkjOPQMBBw==\n"\
#                                   "-----END EC PARAMETERS-----\n"\
#                                   "-----BEGIN EC PRIVATE KEY-----\n"\
#                                   "MHcCAQEEIFCkEmNXACRbWdizfAKP8/Qvx9aplVxLE+Sm2vmCcsY3oAoGCCqGSM49\n"\
#                                   "AwEHoUQDQgAESk526eZ9lf6xrNOiTF8qkYvJDOfc4qqShcbB7qnT67As4pyeQzVm\n"\
#                                   "xfMjmXYBOUnPVBL3FKnIk45sDSCfu++gug==\n"\
#                                   "-----END EC PRIVATE KEY-----"
#
# #define SERVER_SECP256R1_PRIV_KEY "-----BEGIN EC PARAMETERS-----\n"\
#                                   "BggqhkjOPQMBBw==\n"\
#                                   "-----END EC PARAMETERS-----\n"\
#                                   "-----BEGIN EC PRIVATE KEY-----\n"\
#                                   "MHcCAQEEINXLCaZuyYG0HrlSFcHLPFmSnyFm5RqrmyZfgdrxqprXoAoGCCqGSM49\n"\
#                                   "AwEHoUQDQgAEMDuuxEQ1yaA13ceuJP+RC0sbf5ksW6DPlL+yXJiD7cUeWUPrtxbP\n"\
#                                   "ViSR6ex8fYV69oCHgnDnElfE3xaiXiQWBw==\n"\
#                                   "-----END EC PRIVATE KEY-----"

# We aren't really concerned with the actual bytes of the transcript, only the hash.
# The transcript_hash values were calculated as:
# hashlib.sha256(b"client_hello || server_hello").hexdigest()
# hashlib.sha384(b"client_hello || server_hello").hexdigest()
# The string "client_hello || server_hello" is used in s2n/tests/unit/s2n_tls13_hybrid_shared_secret_test.c.

# The PQ shared secrets come from the first test vector in the corresponding NIST KAT.
input_vectors = [
    {
        "group_name": "x25519_sikep434r2",
        "cipher_suite": "TLS_AES_128_GCM_SHA256",
        "ec_shared_secret": "519be87fa0599077e5673d6f2d910aa150d7fef783c5e1491961fdf63b255910",
        "pq_shared_secret": "35F7F8FF388714DEDC41F139078CEDC9",
        "transcript_hash": "f5f7f7867668be4b792159d4d194a03ec5cfa238b6409b5ca2ddccfddcc92a2b",
    },
    {
        "group_name": "x25519_sikep434r2",
        "cipher_suite": "TLS_AES_256_GCM_SHA384",
        "ec_shared_secret": "519be87fa0599077e5673d6f2d910aa150d7fef783c5e1491961fdf63b255910",
        "pq_shared_secret": "35F7F8FF388714DEDC41F139078CEDC9",
        "transcript_hash": "35412cebcf35cb8a7af8f78278a486fc798f8702eaebd067c97acb27bffe13524d8426a4ed57956b4fd0ffdc4c90be52",
    },
    {
        "group_name": "secp256r1_sikep434r2",
        "cipher_suite": "TLS_AES_128_GCM_SHA256",
        "ec_shared_secret": "9348e27655539e08fffe46b35f863dd634e7437cc6bc11c7d329ef5484ec3b60",
        "pq_shared_secret": "35F7F8FF388714DEDC41F139078CEDC9",
        "transcript_hash": "f5f7f7867668be4b792159d4d194a03ec5cfa238b6409b5ca2ddccfddcc92a2b",
    },
    {
        "group_name": "secp256r1_sikep434r2",
        "cipher_suite": "TLS_AES_256_GCM_SHA384",
        "ec_shared_secret": "9348e27655539e08fffe46b35f863dd634e7437cc6bc11c7d329ef5484ec3b60",
        "pq_shared_secret": "35F7F8FF388714DEDC41F139078CEDC9",
        "transcript_hash": "35412cebcf35cb8a7af8f78278a486fc798f8702eaebd067c97acb27bffe13524d8426a4ed57956b4fd0ffdc4c90be52",
    },
    {
        "group_name": "x25519_bike1l1r2",
        "cipher_suite": "TLS_AES_128_GCM_SHA256",
        "ec_shared_secret": "519be87fa0599077e5673d6f2d910aa150d7fef783c5e1491961fdf63b255910",
        "pq_shared_secret": "C1C96E2B8B1D23E52F02AD3A766A75ADBEDF7BA1558B94412B4AB534EEDBDE36",
        "transcript_hash": "f5f7f7867668be4b792159d4d194a03ec5cfa238b6409b5ca2ddccfddcc92a2b",
    },
    {
        "group_name": "x25519_bike1l1r2",
        "cipher_suite": "TLS_AES_256_GCM_SHA384",
        "ec_shared_secret": "519be87fa0599077e5673d6f2d910aa150d7fef783c5e1491961fdf63b255910",
        "pq_shared_secret": "C1C96E2B8B1D23E52F02AD3A766A75ADBEDF7BA1558B94412B4AB534EEDBDE36",
        "transcript_hash": "35412cebcf35cb8a7af8f78278a486fc798f8702eaebd067c97acb27bffe13524d8426a4ed57956b4fd0ffdc4c90be52",
    },
    {
        "group_name": "secp256r1_bike1l1r2",
        "cipher_suite": "TLS_AES_128_GCM_SHA256",
        "ec_shared_secret": "9348e27655539e08fffe46b35f863dd634e7437cc6bc11c7d329ef5484ec3b60",
        "pq_shared_secret": "C1C96E2B8B1D23E52F02AD3A766A75ADBEDF7BA1558B94412B4AB534EEDBDE36",
        "transcript_hash": "f5f7f7867668be4b792159d4d194a03ec5cfa238b6409b5ca2ddccfddcc92a2b",
    },
    {
        "group_name": "secp256r1_bike1l1r2",
        "cipher_suite": "TLS_AES_256_GCM_SHA384",
        "ec_shared_secret": "9348e27655539e08fffe46b35f863dd634e7437cc6bc11c7d329ef5484ec3b60",
        "pq_shared_secret": "C1C96E2B8B1D23E52F02AD3A766A75ADBEDF7BA1558B94412B4AB534EEDBDE36",
        "transcript_hash": "35412cebcf35cb8a7af8f78278a486fc798f8702eaebd067c97acb27bffe13524d8426a4ed57956b4fd0ffdc4c90be52",
    },
    {
        "group_name": "x25519_kyber512r2",
        "cipher_suite": "TLS_AES_128_GCM_SHA256",
        "ec_shared_secret": "519be87fa0599077e5673d6f2d910aa150d7fef783c5e1491961fdf63b255910",
        "pq_shared_secret": "D0FF6083EE6E516C10AECB53DB05426C382A1A75F3E943C9F469A060C634EF4E",
        "transcript_hash": "f5f7f7867668be4b792159d4d194a03ec5cfa238b6409b5ca2ddccfddcc92a2b",
    },
    {
        "group_name": "x25519_kyber512r2",
        "cipher_suite": "TLS_AES_256_GCM_SHA384",
        "ec_shared_secret": "519be87fa0599077e5673d6f2d910aa150d7fef783c5e1491961fdf63b255910",
        "pq_shared_secret": "D0FF6083EE6E516C10AECB53DB05426C382A1A75F3E943C9F469A060C634EF4E",
        "transcript_hash": "35412cebcf35cb8a7af8f78278a486fc798f8702eaebd067c97acb27bffe13524d8426a4ed57956b4fd0ffdc4c90be52",
    },
    {
        "group_name": "secp256r1_kyber512r2",
        "cipher_suite": "TLS_AES_128_GCM_SHA256",
        "ec_shared_secret": "9348e27655539e08fffe46b35f863dd634e7437cc6bc11c7d329ef5484ec3b60",
        "pq_shared_secret": "D0FF6083EE6E516C10AECB53DB05426C382A1A75F3E943C9F469A060C634EF4E",
        "transcript_hash": "f5f7f7867668be4b792159d4d194a03ec5cfa238b6409b5ca2ddccfddcc92a2b",
    },
    {
        "group_name": "secp256r1_kyber512r2",
        "cipher_suite": "TLS_AES_256_GCM_SHA384",
        "ec_shared_secret": "9348e27655539e08fffe46b35f863dd634e7437cc6bc11c7d329ef5484ec3b60",
        "pq_shared_secret": "D0FF6083EE6E516C10AECB53DB05426C382A1A75F3E943C9F469A060C634EF4E",
        "transcript_hash": "35412cebcf35cb8a7af8f78278a486fc798f8702eaebd067c97acb27bffe13524d8426a4ed57956b4fd0ffdc4c90be52",
    },
    {
        "group_name": "x25519_kyber512r3",
        "cipher_suite": "TLS_AES_128_GCM_SHA256",
        "ec_shared_secret": "519be87fa0599077e5673d6f2d910aa150d7fef783c5e1491961fdf63b255910",
        "pq_shared_secret": "0A6925676F24B22C286F4C81A4224CEC506C9B257D480E02E3B49F44CAA3237F",
        "transcript_hash": "f5f7f7867668be4b792159d4d194a03ec5cfa238b6409b5ca2ddccfddcc92a2b",
    },
    {
        "group_name": "x25519_kyber512r3",
        "cipher_suite": "TLS_AES_256_GCM_SHA384",
        "ec_shared_secret": "519be87fa0599077e5673d6f2d910aa150d7fef783c5e1491961fdf63b255910",
        "pq_shared_secret": "0A6925676F24B22C286F4C81A4224CEC506C9B257D480E02E3B49F44CAA3237F",
        "transcript_hash": "35412cebcf35cb8a7af8f78278a486fc798f8702eaebd067c97acb27bffe13524d8426a4ed57956b4fd0ffdc4c90be52",
    },
    {
        "group_name": "secp256r1_kyber512r3",
        "cipher_suite": "TLS_AES_128_GCM_SHA256",
        "ec_shared_secret": "9348e27655539e08fffe46b35f863dd634e7437cc6bc11c7d329ef5484ec3b60",
        "pq_shared_secret": "0A6925676F24B22C286F4C81A4224CEC506C9B257D480E02E3B49F44CAA3237F",
        "transcript_hash": "f5f7f7867668be4b792159d4d194a03ec5cfa238b6409b5ca2ddccfddcc92a2b",
    },
    {
        "group_name": "secp256r1_kyber512r3",
        "cipher_suite": "TLS_AES_256_GCM_SHA384",
        "ec_shared_secret": "9348e27655539e08fffe46b35f863dd634e7437cc6bc11c7d329ef5484ec3b60",
        "pq_shared_secret": "0A6925676F24B22C286F4C81A4224CEC506C9B257D480E02E3B49F44CAA3237F",
        "transcript_hash": "35412cebcf35cb8a7af8f78278a486fc798f8702eaebd067c97acb27bffe13524d8426a4ed57956b4fd0ffdc4c90be52",
    },
    {
        "group_name": "x25519_bikel1r3",
        "cipher_suite": "TLS_AES_128_GCM_SHA256",
        "ec_shared_secret": "519be87fa0599077e5673d6f2d910aa150d7fef783c5e1491961fdf63b255910",
        "pq_shared_secret": "1A88B3A458EE42906A5FD423817E043532579C4F79518A81213DC91D0F2FCEA9",
        "transcript_hash": "f5f7f7867668be4b792159d4d194a03ec5cfa238b6409b5ca2ddccfddcc92a2b",
    },
    {
        "group_name": "x25519_bikel1r3",
        "cipher_suite": "TLS_AES_256_GCM_SHA384",
        "ec_shared_secret": "519be87fa0599077e5673d6f2d910aa150d7fef783c5e1491961fdf63b255910",
        "pq_shared_secret": "1A88B3A458EE42906A5FD423817E043532579C4F79518A81213DC91D0F2FCEA9",
        "transcript_hash": "35412cebcf35cb8a7af8f78278a486fc798f8702eaebd067c97acb27bffe13524d8426a4ed57956b4fd0ffdc4c90be52",
    },
    {
        "group_name": "secp256r1_bikel1r3",
        "cipher_suite": "TLS_AES_128_GCM_SHA256",
        "ec_shared_secret": "9348e27655539e08fffe46b35f863dd634e7437cc6bc11c7d329ef5484ec3b60",
        "pq_shared_secret": "1A88B3A458EE42906A5FD423817E043532579C4F79518A81213DC91D0F2FCEA9",
        "transcript_hash": "f5f7f7867668be4b792159d4d194a03ec5cfa238b6409b5ca2ddccfddcc92a2b",
    },
    {
        "group_name": "secp256r1_bikel1r3",
        "cipher_suite": "TLS_AES_256_GCM_SHA384",
        "ec_shared_secret": "9348e27655539e08fffe46b35f863dd634e7437cc6bc11c7d329ef5484ec3b60",
        "pq_shared_secret": "1A88B3A458EE42906A5FD423817E043532579C4F79518A81213DC91D0F2FCEA9",
        "transcript_hash": "35412cebcf35cb8a7af8f78278a486fc798f8702eaebd067c97acb27bffe13524d8426a4ed57956b4fd0ffdc4c90be52",
    },
]

def hkdf_extract(key: bytes, info: bytes, hash_alg: str):
    return hmac.new(key, info, hash_alg).digest()

def hkdf_expand_label(key: bytes, label: str, context: bytes, hash_alg: str):
    label_arr = [0, hashlib.new(hash_alg).digest_size, len("tls13 ") + len(label)]
    for c in "tls13 ":
        label_arr.append(ord(c))

    for c in label:
        label_arr.append(ord(c))

    label_arr.append(len(context))

    for c in context:
        label_arr.append(c)

    return hkdf_extract(key, bytearray(label_arr) + bytes([1]), hash_alg)

def compute_secrets(input_vector: dict):
    shared_secret = bytes.fromhex(input_vector["ec_shared_secret"] + input_vector["pq_shared_secret"])
    hash_alg = input_vector["cipher_suite"].split("_")[-1].lower()
    zeros = bytearray([0] * hashlib.new(hash_alg).digest_size)
    transcript_hash = bytes.fromhex(input_vector["transcript_hash"])

    h = hashlib.new(hash_alg)
    h.update(b"")
    empty_hash = h.digest()

    secrets = {"early_secret": hkdf_extract(zeros, zeros, hash_alg)}
    secrets["derived_secret"] = hkdf_expand_label(secrets["early_secret"], "derived", empty_hash, hash_alg)
    secrets["handshake_secret"] = hkdf_extract(secrets["derived_secret"], shared_secret, hash_alg)
    secrets["client_traffic_secret"] = hkdf_expand_label(secrets["handshake_secret"], "c hs traffic", transcript_hash, hash_alg)
    secrets["server_traffic_secret"] = hkdf_expand_label(secrets["handshake_secret"], "s hs traffic", transcript_hash, hash_alg)

    return secrets

def main():
    output = ""

    for input_vector in input_vectors:
        secrets = compute_secrets(input_vector)

        for input_key, input_value in input_vector.items():
            output += input_key + " = " + input_value + "\n"

        for secret_name, secret_bytes in secrets.items():
            output += secret_name + " = " + secret_bytes.hex() + "\n"

        output += "\n"

    print(output)

if __name__ == '__main__':
    main()
