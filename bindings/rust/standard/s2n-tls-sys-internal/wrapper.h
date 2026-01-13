// This is a wrapper header file that includes all the necessary s2n-tls headers
// for generating Rust bindings with bindgen

// Core s2n header - ensures other headers can find it
#include "api/s2n.h"

// Include security policies
#include "tls/s2n_security_policies.h"
#include "tls/s2n_security_rules.h"

// Include cipher suites and preferences
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_cipher_preferences.h"

// Include ECC preferences
#include "tls/s2n_ecc_preferences.h"

// Include KEM preferences
#include "tls/s2n_kem.h"
#include "tls/s2n_kem_preferences.h"
