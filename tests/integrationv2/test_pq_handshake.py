import pytest
import os

from common import Certificates, Ciphers, Curves, Protocols, AvailablePorts, KemGroups, Kems, SecurityPolicies
from configuration import available_ports, PROVIDERS, PROTOCOLS
from common import Ciphers, ProviderOptions, Protocols, data_bytes
from fixtures import managed_process
from providers import Provider, S2N, OpenSSL
from utils import get_expected_s2n_version
from global_flags import get_flag, S2N_NO_PQ

# Many test vectors have multiple "expected_curves" or "expected_kem_groups".
# Either secp256r1 or x25519 may be negotiated depending on how s2n was compiled.
# All "OpenSSL" providers are actually OpenQuantumSafe OpenSSL. We reuse the
# OpenSSL provider and use get_oqs_openssl_override_env_vars() to execute
# the process with oqs_openssl.
pq_test_vectors = [
    # s2nc <-> oqs_openssl server; expect to negotiate PQ 1.3.
    {"client_provider": S2N, "client_prefs": SecurityPolicies.PQ_KYBERBIKESIKE_TEST_TLS_1_0_2020_09,
     "server_provider": OpenSSL, "server_prefs": KemGroups.P256_KYBER512R2,
     "expected_cipher": Ciphers.AES256_GCM_SHA384, "expected_protocol": Protocols.TLS13,
     "expected_kem_groups": [KemGroups.P256_KYBER512R2], "expected_curves": None, "expected_kem": None},
    {"client_provider": S2N, "client_prefs": SecurityPolicies.PQ_KYBER_TEST_TLS_1_0_2020_09, "server_provider": OpenSSL,
     "server_prefs": KemGroups.P256_KYBER512R2,
     "expected_cipher": Ciphers.AES256_GCM_SHA384, "expected_protocol": Protocols.TLS13,
     "expected_kem_groups": [KemGroups.P256_KYBER512R2], "expected_curves": None, "expected_kem": None},
    {"client_provider": S2N, "client_prefs": SecurityPolicies.PQ_BIKE_TEST_TLS_1_0_2020_09, "server_provider": OpenSSL,
     "server_prefs": KemGroups.P256_BIKE1L1FOR2,
     "expected_cipher": Ciphers.AES256_GCM_SHA384, "expected_protocol": Protocols.TLS13,
     "expected_kem_groups": [KemGroups.P256_BIKE1L1FOR2], "expected_curves": None, "expected_kem": None},
    {"client_provider": S2N, "client_prefs": SecurityPolicies.PQ_SIKE_TEST_TLS_1_0_2020_09, "server_provider": OpenSSL,
     "server_prefs": KemGroups.P256_SIKEP434R2,
     "expected_cipher": Ciphers.AES256_GCM_SHA384, "expected_protocol": Protocols.TLS13,
     "expected_kem_groups": [KemGroups.P256_SIKEP434R2], "expected_curves": None, "expected_kem": None},
    {"client_provider": S2N, "client_prefs": SecurityPolicies.PQ_KYBERBIKESIKE_TEST_TLS_1_0_2020_09,
     "server_provider": OpenSSL, "server_prefs": KemGroups.P256_BIKE1L1FOR2,
     "expected_cipher": Ciphers.AES256_GCM_SHA384, "expected_protocol": Protocols.TLS13,
     "expected_kem_groups": [KemGroups.P256_BIKE1L1FOR2], "expected_curves": None, "expected_kem": None},
    {"client_provider": S2N, "client_prefs": SecurityPolicies.PQ_KYBERBIKESIKE_TEST_TLS_1_0_2020_09,
     "server_provider": OpenSSL, "server_prefs": KemGroups.P256_SIKEP434R2,
     "expected_cipher": Ciphers.AES256_GCM_SHA384, "expected_protocol": Protocols.TLS13,
     "expected_kem_groups": [KemGroups.P256_SIKEP434R2], "expected_curves": None, "expected_kem": None},

    # oqs_openssl client <-> s2nd; expect to negotiate PQ 1.3.
    {"client_provider": OpenSSL, "client_prefs": KemGroups.P256_KYBER512R2, "server_provider": S2N,
     "server_prefs": SecurityPolicies.PQ_KYBERBIKESIKE_TEST_TLS_1_0_2020_09,
     "expected_cipher": Ciphers.AES256_GCM_SHA384, "expected_protocol": Protocols.TLS13,
     "expected_kem_groups": [KemGroups.P256_KYBER512R2], "expected_curves": None, "expected_kem": None},
    {"client_provider": OpenSSL, "client_prefs": KemGroups.P256_KYBER512R2, "server_provider": S2N,
     "server_prefs": SecurityPolicies.PQ_KYBER_TEST_TLS_1_0_2020_09,
     "expected_cipher": Ciphers.AES256_GCM_SHA384, "expected_protocol": Protocols.TLS13,
     "expected_kem_groups": [KemGroups.P256_KYBER512R2], "expected_curves": None, "expected_kem": None},
    {"client_provider": OpenSSL, "client_prefs": KemGroups.P256_BIKE1L1FOR2, "server_provider": S2N,
     "server_prefs": SecurityPolicies.PQ_BIKE_TEST_TLS_1_0_2020_09,
     "expected_cipher": Ciphers.AES256_GCM_SHA384, "expected_protocol": Protocols.TLS13,
     "expected_kem_groups": [KemGroups.P256_BIKE1L1FOR2], "expected_curves": None, "expected_kem": None},
    {"client_provider": OpenSSL, "client_prefs": KemGroups.P256_SIKEP434R2, "server_provider": S2N,
     "server_prefs": SecurityPolicies.PQ_SIKE_TEST_TLS_1_0_2020_09,
     "expected_cipher": Ciphers.AES256_GCM_SHA384, "expected_protocol": Protocols.TLS13,
     "expected_kem_groups": [KemGroups.P256_SIKEP434R2], "expected_curves": None, "expected_kem": None},
    {"client_provider": OpenSSL, "client_prefs": KemGroups.P256_BIKE1L1FOR2, "server_provider": S2N,
     "server_prefs": SecurityPolicies.PQ_KYBERBIKESIKE_TEST_TLS_1_0_2020_09,
     "expected_cipher": Ciphers.AES256_GCM_SHA384, "expected_protocol": Protocols.TLS13,
     "expected_kem_groups": [KemGroups.P256_BIKE1L1FOR2], "expected_curves": None, "expected_kem": None},
    {"client_provider": OpenSSL, "client_prefs": KemGroups.P256_SIKEP434R2, "server_provider": S2N,
     "server_prefs": SecurityPolicies.PQ_KYBERBIKESIKE_TEST_TLS_1_0_2020_09,
     "expected_cipher": Ciphers.AES256_GCM_SHA384, "expected_protocol": Protocols.TLS13,
     "expected_kem_groups": [KemGroups.P256_SIKEP434R2], "expected_curves": None, "expected_kem": None},

    # s2nc <-> s2nd; expect to negotiate PQ 1.3.
    {"client_provider": S2N, "client_prefs": SecurityPolicies.PQ_KYBERBIKESIKE_TEST_TLS_1_0_2020_09,
     "server_provider": S2N, "server_prefs": SecurityPolicies.PQ_KYBERBIKESIKE_TEST_TLS_1_0_2020_09,
     "expected_cipher": Ciphers.AES256_GCM_SHA384, "expected_protocol": Protocols.TLS13,
     "expected_kem_groups": [KemGroups.P256_KYBER512R2, KemGroups.X25519_KYBER512R2], "expected_curves": None,
     "expected_kem": None},
    {"client_provider": S2N, "client_prefs": SecurityPolicies.PQ_KYBERBIKESIKE_TEST_TLS_1_0_2020_09,
     "server_provider": S2N, "server_prefs": SecurityPolicies.PQ_KYBER_TEST_TLS_1_0_2020_09,
     "expected_cipher": Ciphers.AES256_GCM_SHA384, "expected_protocol": Protocols.TLS13,
     "expected_kem_groups": [KemGroups.P256_KYBER512R2, KemGroups.X25519_KYBER512R2], "expected_curves": None,
     "expected_kem": None},
    {"client_provider": S2N, "client_prefs": SecurityPolicies.PQ_KYBER_TEST_TLS_1_0_2020_09, "server_provider": S2N,
     "server_prefs": SecurityPolicies.PQ_KYBERBIKESIKE_TEST_TLS_1_0_2020_09,
     "expected_cipher": Ciphers.AES256_GCM_SHA384, "expected_protocol": Protocols.TLS13,
     "expected_kem_groups": [KemGroups.P256_KYBER512R2, KemGroups.X25519_KYBER512R2], "expected_curves": None,
     "expected_kem": None},
    {"client_provider": S2N, "client_prefs": SecurityPolicies.PQ_BIKE_TEST_TLS_1_0_2020_09, "server_provider": S2N,
     "server_prefs": SecurityPolicies.PQ_KYBERBIKESIKE_TEST_TLS_1_0_2020_09,
     "expected_cipher": Ciphers.AES256_GCM_SHA384, "expected_protocol": Protocols.TLS13,
     "expected_kem_groups": [KemGroups.P256_BIKE1L1FOR2, KemGroups.X25519_BIKE1L1FOR2], "expected_curves": None,
     "expected_kem": None},
    {"client_provider": S2N, "client_prefs": SecurityPolicies.PQ_SIKE_TEST_TLS_1_0_2020_09, "server_provider": S2N,
     "server_prefs": SecurityPolicies.PQ_KYBERBIKESIKE_TEST_TLS_1_0_2020_09,
     "expected_cipher": Ciphers.AES256_GCM_SHA384, "expected_protocol": Protocols.TLS13,
     "expected_kem_groups": [KemGroups.P256_SIKEP434R2, KemGroups.X25519_SIKEP434R2], "expected_curves": None,
     "expected_kem": None},
    {"client_provider": S2N, "client_prefs": SecurityPolicies.PQ_KYBER_TEST_TLS_1_0_2020_09, "server_provider": S2N,
     "server_prefs": SecurityPolicies.PQ_KYBER_TEST_TLS_1_0_2020_09,
     "expected_cipher": Ciphers.AES256_GCM_SHA384, "expected_protocol": Protocols.TLS13,
     "expected_kem_groups": [KemGroups.P256_KYBER512R2, KemGroups.X25519_KYBER512R2], "expected_curves": None,
     "expected_kem": None},
    {"client_provider": S2N, "client_prefs": SecurityPolicies.PQ_BIKE_TEST_TLS_1_0_2020_09, "server_provider": S2N,
     "server_prefs": SecurityPolicies.PQ_BIKE_TEST_TLS_1_0_2020_09,
     "expected_cipher": Ciphers.AES256_GCM_SHA384, "expected_protocol": Protocols.TLS13,
     "expected_kem_groups": [KemGroups.P256_BIKE1L1FOR2, KemGroups.X25519_BIKE1L1FOR2], "expected_curves": None,
     "expected_kem": None},
    {"client_provider": S2N, "client_prefs": SecurityPolicies.PQ_SIKE_TEST_TLS_1_0_2020_09, "server_provider": S2N,
     "server_prefs": SecurityPolicies.PQ_SIKE_TEST_TLS_1_0_2020_09,
     "expected_cipher": Ciphers.AES256_GCM_SHA384, "expected_protocol": Protocols.TLS13,
     "expected_kem_groups": [KemGroups.P256_SIKEP434R2, KemGroups.X25519_SIKEP434R2], "expected_curves": None,
     "expected_kem": None},

    # s2nc <-> s2nd; client and server both support PQ 1.3, but have no KEM groups in common; expect to negotiate ECDHE 1.3.
    {"client_provider": S2N, "client_prefs": SecurityPolicies.PQ_KYBER_TEST_TLS_1_0_2020_09, "server_provider": S2N,
     "server_prefs": SecurityPolicies.PQ_BIKE_TEST_TLS_1_0_2020_09,
     "expected_cipher": Ciphers.AES256_GCM_SHA384, "expected_protocol": Protocols.TLS13, "expected_kem_groups": None,
     "expected_curves": [Curves.X25519, Curves.P256], "expected_kem": None},
    {"client_provider": S2N, "client_prefs": SecurityPolicies.PQ_BIKE_TEST_TLS_1_0_2020_09, "server_provider": S2N,
     "server_prefs": SecurityPolicies.PQ_SIKE_TEST_TLS_1_0_2020_09,
     "expected_cipher": Ciphers.AES256_GCM_SHA384, "expected_protocol": Protocols.TLS13, "expected_kem_groups": None,
     "expected_curves": [Curves.X25519, Curves.P256], "expected_kem": None},
    {"client_provider": S2N, "client_prefs": SecurityPolicies.PQ_SIKE_TEST_TLS_1_0_2020_09, "server_provider": S2N,
     "server_prefs": SecurityPolicies.PQ_KYBER_TEST_TLS_1_0_2020_09,
     "expected_cipher": Ciphers.AES256_GCM_SHA384, "expected_protocol": Protocols.TLS13, "expected_kem_groups": None,
     "expected_curves": [Curves.X25519, Curves.P256], "expected_kem": None},

    # s2nc <-> s2nd; given {client, server}_prefs == None, s2n will default to non-pq; expect to negotiate ECDHE 1.3.
    {"client_provider": S2N, "client_prefs": SecurityPolicies.PQ_KYBERBIKESIKE_TEST_TLS_1_0_2020_09,
     "server_provider": S2N, "server_prefs": None,
     "expected_cipher": Ciphers.AES128_GCM_SHA256, "expected_protocol": Protocols.TLS13, "expected_kem_groups": None,
     "expected_curves": [Curves.X25519, Curves.P256], "expected_kem": None},
    {"client_provider": S2N, "client_prefs": None, "server_provider": S2N,
     "server_prefs": SecurityPolicies.PQ_KYBERBIKESIKE_TEST_TLS_1_0_2020_09,
     "expected_cipher": Ciphers.AES256_GCM_SHA384, "expected_protocol": Protocols.TLS13, "expected_kem_groups": None,
     "expected_curves": [Curves.X25519, Curves.P256], "expected_kem": None},

    # s2nc <-> s2nd; client and server share a 1.3 KEM group, but client did not send a keyshare for it.
    # Rather than send HRR, s2n server prefers to negotiate a group for which it has already received
    # a share; expect to negotiate ECDHE 1.3.
    {"client_provider": S2N, "client_prefs": SecurityPolicies.PQ_KYBERBIKESIKE_TEST_TLS_1_0_2020_09,
     "server_provider": S2N, "server_prefs": SecurityPolicies.PQ_BIKE_TEST_TLS_1_0_2020_09,
     "expected_cipher": Ciphers.AES256_GCM_SHA384,
     "expected_protocol": Protocols.TLS13, "expected_kem_groups": None, "expected_curves": [Curves.X25519, Curves.P256],
     "expected_kem": None},
    {"client_provider": S2N, "client_prefs": SecurityPolicies.PQ_KYBERBIKESIKE_TEST_TLS_1_0_2020_09,
     "server_provider": S2N, "server_prefs": SecurityPolicies.PQ_SIKE_TEST_TLS_1_0_2020_09,
     "expected_cipher": Ciphers.AES256_GCM_SHA384, "expected_protocol": Protocols.TLS13, "expected_kem_groups": None,
     "expected_curves": [Curves.X25519, Curves.P256], "expected_kem": None},

    # s2nc <-> s2nd; client supports PQ 1.2 and 1.3, server only supports PQ 1.2; expect to negotiate PQ 1.2.
    {"client_provider": S2N, "client_prefs": SecurityPolicies.PQ_KYBERBIKESIKE_TEST_TLS_1_0_2020_09,
     "server_provider": S2N, "server_prefs": SecurityPolicies.KMS_PQ_TLS_1_0_2020_07,
     "expected_cipher": Ciphers.ECDHE_KYBER_RSA_AES256_GCM_SHA384, "expected_protocol": Protocols.TLS12,
     "expected_kem_groups": None, "expected_curves": [Curves.P256], "expected_kem": Kems.KYBER512R2},

    # s2nc <-> s2nd; client supports only PQ 1.2, server supports PQ 1.2 and 1.3; expect to negotiate PQ 1.2.
    {"client_provider": S2N, "client_prefs": SecurityPolicies.KMS_PQ_TLS_1_0_2020_07, "server_provider": S2N,
     "server_prefs": SecurityPolicies.PQ_KYBERBIKESIKE_TEST_TLS_1_0_2020_09,
     "expected_cipher": Ciphers.ECDHE_KYBER_RSA_AES256_GCM_SHA384, "expected_protocol": Protocols.TLS12,
     "expected_kem_groups": None, "expected_curves": [Curves.P256], "expected_kem": Kems.KYBER512R2},

    # s2nc <-> s2nd; client and server both support PQ 1.2; expect to negotiate PQ 1.2.
    {"client_provider": S2N, "client_prefs": SecurityPolicies.KMS_PQ_TLS_1_0_2019_06, "server_provider": S2N,
     "server_prefs": SecurityPolicies.KMS_PQ_TLS_1_0_2019_06,
     "expected_cipher": Ciphers.ECDHE_BIKE_RSA_AES256_GCM_SHA384, "expected_protocol": Protocols.TLS12,
     "expected_kem_groups": None, "expected_curves": [Curves.P256], "expected_kem": Kems.BIKE1L1R1},
    {"client_provider": S2N, "client_prefs": SecurityPolicies.KMS_PQ_TLS_1_0_2019_06, "server_provider": S2N,
     "server_prefs": SecurityPolicies.KMS_PQ_TLS_1_0_2020_02,
     "expected_cipher": Ciphers.ECDHE_BIKE_RSA_AES256_GCM_SHA384, "expected_protocol": Protocols.TLS12,
     "expected_kem_groups": None, "expected_curves": [Curves.P256], "expected_kem": Kems.BIKE1L1R1},
    {"client_provider": S2N, "client_prefs": SecurityPolicies.KMS_PQ_TLS_1_0_2019_06, "server_provider": S2N,
     "server_prefs": SecurityPolicies.KMS_PQ_TLS_1_0_2020_07,
     "expected_cipher": Ciphers.ECDHE_BIKE_RSA_AES256_GCM_SHA384, "expected_protocol": Protocols.TLS12,
     "expected_kem_groups": None, "expected_curves": [Curves.P256], "expected_kem": Kems.BIKE1L1R1},
    {"client_provider": S2N, "client_prefs": SecurityPolicies.KMS_PQ_TLS_1_0_2020_02, "server_provider": S2N,
     "server_prefs": SecurityPolicies.KMS_PQ_TLS_1_0_2019_06,
     "expected_cipher": Ciphers.ECDHE_BIKE_RSA_AES256_GCM_SHA384, "expected_protocol": Protocols.TLS12,
     "expected_kem_groups": None, "expected_curves": [Curves.P256], "expected_kem": Kems.BIKE1L1R1},
    {"client_provider": S2N, "client_prefs": SecurityPolicies.KMS_PQ_TLS_1_0_2020_02, "server_provider": S2N,
     "server_prefs": SecurityPolicies.KMS_PQ_TLS_1_0_2020_02,
     "expected_cipher": Ciphers.ECDHE_BIKE_RSA_AES256_GCM_SHA384, "expected_protocol": Protocols.TLS12,
     "expected_kem_groups": None, "expected_curves": [Curves.P256], "expected_kem": Kems.BIKE1L1FOR2},
    {"client_provider": S2N, "client_prefs": SecurityPolicies.KMS_PQ_TLS_1_0_2020_02, "server_provider": S2N,
     "server_prefs": SecurityPolicies.KMS_PQ_TLS_1_0_2020_07,
     "expected_cipher": Ciphers.ECDHE_BIKE_RSA_AES256_GCM_SHA384, "expected_protocol": Protocols.TLS12,
     "expected_kem_groups": None, "expected_curves": [Curves.P256], "expected_kem": Kems.BIKE1L1FOR2},
    {"client_provider": S2N, "client_prefs": SecurityPolicies.KMS_PQ_TLS_1_0_2020_07, "server_provider": S2N,
     "server_prefs": SecurityPolicies.KMS_PQ_TLS_1_0_2019_06,
     "expected_cipher": Ciphers.ECDHE_BIKE_RSA_AES256_GCM_SHA384, "expected_protocol": Protocols.TLS12,
     "expected_kem_groups": None, "expected_curves": [Curves.P256], "expected_kem": Kems.BIKE1L1R1},
    {"client_provider": S2N, "client_prefs": SecurityPolicies.KMS_PQ_TLS_1_0_2020_07, "server_provider": S2N,
     "server_prefs": SecurityPolicies.KMS_PQ_TLS_1_0_2020_02,
     "expected_cipher": Ciphers.ECDHE_BIKE_RSA_AES256_GCM_SHA384, "expected_protocol": Protocols.TLS12,
     "expected_kem_groups": None, "expected_curves": [Curves.P256], "expected_kem": Kems.BIKE1L1FOR2},
    {"client_provider": S2N, "client_prefs": SecurityPolicies.KMS_PQ_TLS_1_0_2020_07, "server_provider": S2N,
     "server_prefs": SecurityPolicies.KMS_PQ_TLS_1_0_2020_07,
     "expected_cipher": Ciphers.ECDHE_KYBER_RSA_AES256_GCM_SHA384, "expected_protocol": Protocols.TLS12,
     "expected_kem_groups": None, "expected_curves": [Curves.P256], "expected_kem": Kems.KYBER512R2},
    {"client_provider": S2N, "client_prefs": SecurityPolicies.PQ_SIKE_TEST_TLS_1_0_2019_11, "server_provider": S2N,
     "server_prefs": SecurityPolicies.KMS_PQ_TLS_1_0_2019_06,
     "expected_cipher": Ciphers.ECDHE_SIKE_RSA_AES256_GCM_SHA384, "expected_protocol": Protocols.TLS12,
     "expected_kem_groups": None, "expected_curves": [Curves.P256], "expected_kem": Kems.SIKEP503R2},
    {"client_provider": S2N, "client_prefs": SecurityPolicies.PQ_SIKE_TEST_TLS_1_0_2019_11, "server_provider": S2N,
     "server_prefs": SecurityPolicies.KMS_PQ_TLS_1_0_2020_02,
     "expected_cipher": Ciphers.ECDHE_SIKE_RSA_AES256_GCM_SHA384, "expected_protocol": Protocols.TLS12,
     "expected_kem_groups": None, "expected_curves": [Curves.P256], "expected_kem": Kems.SIKEP503R2},
    {"client_provider": S2N, "client_prefs": SecurityPolicies.PQ_SIKE_TEST_TLS_1_0_2019_11, "server_provider": S2N,
     "server_prefs": SecurityPolicies.KMS_PQ_TLS_1_0_2020_07,
     "expected_cipher": Ciphers.ECDHE_SIKE_RSA_AES256_GCM_SHA384, "expected_protocol": Protocols.TLS12,
     "expected_kem_groups": None, "expected_curves": [Curves.P256], "expected_kem": Kems.SIKEP503R2},
    {"client_provider": S2N, "client_prefs": SecurityPolicies.PQ_SIKE_TEST_TLS_1_0_2020_02, "server_provider": S2N,
     "server_prefs": SecurityPolicies.KMS_PQ_TLS_1_0_2019_06,
     "expected_cipher": Ciphers.ECDHE_SIKE_RSA_AES256_GCM_SHA384, "expected_protocol": Protocols.TLS12,
     "expected_kem_groups": None, "expected_curves": [Curves.P256], "expected_kem": Kems.SIKEP503R2},
    {"client_provider": S2N, "client_prefs": SecurityPolicies.PQ_SIKE_TEST_TLS_1_0_2020_02, "server_provider": S2N,
     "server_prefs": SecurityPolicies.KMS_PQ_TLS_1_0_2020_02,
     "expected_cipher": Ciphers.ECDHE_SIKE_RSA_AES256_GCM_SHA384, "expected_protocol": Protocols.TLS12,
     "expected_kem_groups": None, "expected_curves": [Curves.P256], "expected_kem": Kems.SIKEP434R2},
    {"client_provider": S2N, "client_prefs": SecurityPolicies.PQ_SIKE_TEST_TLS_1_0_2020_02, "server_provider": S2N,
     "server_prefs": SecurityPolicies.KMS_PQ_TLS_1_0_2020_07,
     "expected_cipher": Ciphers.ECDHE_SIKE_RSA_AES256_GCM_SHA384, "expected_protocol": Protocols.TLS12,
     "expected_kem_groups": None, "expected_curves": [Curves.P256], "expected_kem": Kems.SIKEP434R2},

    # s2nc <-> s2nd. Client supports PQ 1.2, server supports does not support PQ; expect to negotiate ECDHE 1.2.
    {"client_provider": S2N, "client_prefs": SecurityPolicies.KMS_PQ_TLS_1_0_2019_06, "server_provider": S2N,
     "server_prefs": SecurityPolicies.KMS_TLS_1_0_2018_10,
     "expected_cipher": Ciphers.ECDHE_RSA_AES256_GCM_SHA384, "expected_protocol": Protocols.TLS12,
     "expected_kem_groups": None, "expected_curves": [Curves.P256], "expected_kem": None},
    {"client_provider": S2N, "client_prefs": SecurityPolicies.KMS_PQ_TLS_1_0_2020_02, "server_provider": S2N,
     "server_prefs": SecurityPolicies.KMS_TLS_1_0_2018_10,
     "expected_cipher": Ciphers.ECDHE_RSA_AES256_GCM_SHA384, "expected_protocol": Protocols.TLS12,
     "expected_kem_groups": None, "expected_curves": [Curves.P256], "expected_kem": None},
    {"client_provider": S2N, "client_prefs": SecurityPolicies.KMS_PQ_TLS_1_0_2020_07, "server_provider": S2N,
     "server_prefs": SecurityPolicies.KMS_TLS_1_0_2018_10,
     "expected_cipher": Ciphers.ECDHE_RSA_AES256_GCM_SHA384, "expected_protocol": Protocols.TLS12,
     "expected_kem_groups": None, "expected_curves": [Curves.P256], "expected_kem": None},

    # s2nc <-> s2nd. Client does not support PQ, server supports PQ 1.2; expect to negotiate ECDHE 1.2.
    {"client_provider": S2N, "client_prefs": SecurityPolicies.KMS_TLS_1_0_2018_10, "server_provider": S2N,
     "server_prefs": SecurityPolicies.KMS_PQ_TLS_1_0_2019_06,
     "expected_cipher": Ciphers.ECDHE_RSA_AES256_GCM_SHA384, "expected_protocol": Protocols.TLS12,
     "expected_kem_groups": None, "expected_curves": [Curves.P256], "expected_kem": None},
    {"client_provider": S2N, "client_prefs": SecurityPolicies.KMS_TLS_1_0_2018_10, "server_provider": S2N,
     "server_prefs": SecurityPolicies.KMS_PQ_TLS_1_0_2020_02,
     "expected_cipher": Ciphers.ECDHE_RSA_AES256_GCM_SHA384, "expected_protocol": Protocols.TLS12,
     "expected_kem_groups": None, "expected_curves": [Curves.P256], "expected_kem": None},
    {"client_provider": S2N, "client_prefs": SecurityPolicies.KMS_TLS_1_0_2018_10, "server_provider": S2N,
     "server_prefs": SecurityPolicies.KMS_PQ_TLS_1_0_2020_07,
     "expected_cipher": Ciphers.ECDHE_RSA_AES256_GCM_SHA384, "expected_protocol": Protocols.TLS12,
     "expected_kem_groups": None, "expected_curves": [Curves.P256], "expected_kem": None},
]


def get_oqs_openssl_override_env_vars():
    oqs_openssl_install_dir = os.environ["OQS_OPENSSL_1_1_1_INSTALL_DIR"]

    override_env_vars = dict()
    override_env_vars["PATH"] = oqs_openssl_install_dir + "/bin"
    override_env_vars["LD_LIBRARY_PATH"] = oqs_openssl_install_dir + "/lib"

    return override_env_vars


def assert_s2n_results(results, peer, vector):
    expected_protocol = vector["expected_protocol"]
    expected_curves = vector["expected_curves"]
    expected_kem = vector["expected_kem"]
    expected_kem_groups = vector["expected_kem_groups"]
    expected_cipher = vector["expected_cipher"]

    if expected_curves is None:
        possible_curve_output = []
        curve_found = True
    else:
        possible_curve_output = [bytes("Curve: {}".format(curve.s2n_name).encode('utf-8')) for curve in expected_curves]
        curve_found = False

    if expected_kem_groups is None:
        possible_kem_group_output = []
        kem_group_found = True
    else:
        possible_kem_group_output = [bytes("KEM Group: {}".format(kem_group.s2n_name).encode('utf-8')) for kem_group in
                                     expected_kem_groups]
        kem_group_found = False

    expected_version = get_expected_s2n_version(expected_protocol, peer)

    for result in results:
        assert result.exception is None
        assert result.exit_code == 0
        assert bytes("Actual protocol version: {}".format(expected_version).encode('utf-8')) in result.stdout

        for curve_output in possible_curve_output:
            if curve_output in result.stdout:
                curve_found = True

        if expected_kem is not None:
            assert bytes("KEM: {}".format(expected_kem.name).encode('utf-8')) in result.stdout

        for kem_group_output in possible_kem_group_output:
            if kem_group_output in result.stdout:
                kem_group_found = True

        assert bytes("Cipher negotiated: {}".format(expected_cipher).encode('utf-8')) in result.stdout

    assert curve_found
    assert kem_group_found


@pytest.mark.parametrize("vector", pq_test_vectors)
def test_pq_handshake(managed_process, vector):
    if get_flag(S2N_NO_PQ, False) is True:
        # Skip this test if PQ was disabled
        return

    host = "localhost"
    port = next(available_ports)
    client_provider = vector["client_provider"]
    server_provider = vector["server_provider"]

    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        host=host,
        port=port,
        insecure=True,
        protocol=Protocols.TLS13)

    if client_provider is S2N:
        client_options.security_policy = vector["client_prefs"]
    elif client_provider is OpenSSL:
        client_options.kem_group = vector["client_prefs"]
        client_options.env_overrides = get_oqs_openssl_override_env_vars()

    server_options = ProviderOptions(
        mode=Provider.ServerMode,
        host=host,
        port=port,
        protocol=Protocols.TLS13,
        cert=Certificates.RSA_4096_SHA512.cert,
        key=Certificates.RSA_4096_SHA512.key)

    if server_provider is S2N:
        server_options.security_policy = vector["server_prefs"]
    elif server_provider is OpenSSL:
        server_options.kem_group = vector["server_prefs"]
        server_options.env_overrides = get_oqs_openssl_override_env_vars()

    server = managed_process(server_provider, server_options, timeout=5)
    client = managed_process(client_provider, client_options, timeout=5)

    server_results = server.get_results()
    client_results = client.get_results()

    if server_provider is S2N:
        assert_s2n_results(server_results, client_provider, vector)
    elif server_provider is OpenSSL:
        for results in server_results:
            assert results.exception is None
            assert results.exit_code == 0

    if client_provider is S2N:
        assert_s2n_results(client_results, server_provider, vector)
    elif client_provider is OpenSSL:
        for results in client_results:
            assert results.exception is None
            assert results.exit_code == 0
