#! /bin/bash

USER_TYPES="server client"
RSA_KEY_SIZES="1024 2048 3072 4096"
HASH_ALGS="sha1 sha224 sha256 sha384 sha512"

for user in $USER_TYPES
do
  for rsa_size in $RSA_KEY_SIZES
  do
    for hash_alg in $HASH_ALGS
    do
      PREFIX="rsa_${rsa_size}_${hash_alg}_${user}"
      openssl req -x509 -config cert_config.cfg -newkey rsa:${rsa_size} -${hash_alg} -nodes -keyout ${PREFIX}_key.pem -out ${PREFIX}_cert.pem -days 36500
    done;
  done; 
done;
