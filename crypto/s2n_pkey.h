#pragma once

#include "crypto/s2n_ecdsa.h"
#include "crypto/s2n_hash.h"
#include "crypto/s2n_rsa.h"

#include "utils/s2n_blob.h"

/* Structure that models a public or private key and type-specific operations */
struct s2n_pkey {
    union {
        struct s2n_rsa_key rsa_key;
        struct s2n_ecdsa_key ecdsa_key;
    } key;

    const struct s2n_pkey_ctx *ctx;
};

struct s2n_pkey_ctx {
    int (*sign)(const struct s2n_pkey *priv_key, struct s2n_hash_state *digest, struct s2n_blob *signature);
    
    int (*verify)(const struct s2n_pkey *pub_key, struct s2n_hash_state *digest, struct s2n_blob *signature);

    int (*encrypt)(const struct s2n_pkey *key, struct s2n_blob *in, struct s2n_blob *out);
    
    int (*decrypt)(const struct s2n_pkey *key, struct s2n_blob *in, struct s2n_blob *out);

    int (*match)(const struct s2n_pkey *pub_key, const struct s2n_pkey *priv_key); 
   
    int (*free)(struct s2n_pkey *key);
};

extern int s2n_asn1der_to_private_key(struct s2n_pkey *priv_key, struct s2n_blob *asn1der);
extern int s2n_asn1der_to_public_key(struct s2n_pkey *pub_key, struct s2n_blob *asn1der);
extern int s2n_pkey_sign(const struct s2n_pkey *pkey, struct s2n_hash_state *digest, struct s2n_blob *signature);
extern int s2n_pkey_verify(const struct s2n_pkey *pkey, struct s2n_hash_state *digest, struct s2n_blob *signature);
extern int s2n_pkey_encrypt(const struct s2n_pkey *pkey, struct s2n_blob *in, struct s2n_blob *out);
extern int s2n_pkey_decrypt(const struct s2n_pkey *pkey, struct s2n_blob *in, struct s2n_blob *out);
extern int s2n_pkey_match(const struct s2n_pkey *pub_key, const struct s2n_pkey *priv_key);
extern int s2n_pkey_free(struct s2n_pkey *pkey);

extern const struct s2n_pkey_ctx rsa_key_ctx;
extern const struct s2n_pkey_ctx ecdsa_key_ctx;
