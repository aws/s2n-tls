#!/bin/bash

get_subj() {
  common_name="$1"
  echo "/C=US/ST=Massachusetts/L=Boston/CN=${common_name}"
}

init_ca_dir() {
  ca_dir="$1"
  mkdir -p "${ca_dir}"
  touch "${ca_dir}/certindex"
  echo 01 > "${ca_dir}/certserial"
  echo 01 > "${ca_dir}/crlnumber"
}

generate_key_cert() {
  path="$1"
  name=$(basename "${path}")
  openssl genrsa -out "${path}.key" 4096 || exit
  openssl req -new \
    -key "${path}.key" \
    -out "${path}.csr" \
    -subj "$(get_subj ${name})" \
    || exit
}

generate_key_cert_self_signed() {
  path="$1"
  name=$(basename "${path}")
  openssl genrsa -out "${path}.key" 4096
  openssl req -new -x509 -days 36500 \
    -key "${path}.key" \
    -out "${path}.crt" \
    -subj "$(get_subj ${name})" \
    || exit
}

OPENSSL_CONF_FILE="$(pwd)/openssl.conf"

sign_cert() {
  path="$1"
  ca_name="$2" openssl ca -batch -config "${OPENSSL_CONF_FILE}" -notext \
    -in "${path}.csr" \
    -out "${path}.crt" \
    || exit
}

generate_crl() {
  ca="$1"
  ca_name="${ca}" openssl ca -config "${OPENSSL_CONF_FILE}" -gencrl \
    -keyfile "${ca}.key" \
    -cert "${ca}.crt" \
    -out "${ca}.crl.pem" \
    || exit
  openssl crl -inform PEM \
    -in "${ca}.crl.pem" \
    -outform DER -out "${ca}.crl" \
    || exit
  rm "${ca}.crl.pem"
}

revoke_certificate() {
  cert_path="$1"
  ca="$2"
  ca_name="${ca}" openssl ca -config "${OPENSSL_CONF_FILE}" \
    -revoke "${cert_path}" \
    -keyfile "${ca}.key" \
    -cert "${ca}.crt" \
    || exit
  generate_crl "${ca}"
}

#
# Generate certificate chains of valid and revoked certificates with 1 intermediate CA.
#
# root -> valid intermediate   -> valid leaf
#                              -> revoked leaf
#      -> revoked intermediate -> valid leaf
#                              -> revoked leaf
#

# Generate root certificate
init_ca_dir ./root
generate_key_cert_self_signed ./root/root

# Generate intermediate certificates
init_ca_dir ./root/intermediate
generate_key_cert ./root/intermediate/intermediate

init_ca_dir ./root/intermediate_revoked
generate_key_cert ./root/intermediate_revoked/intermediate_revoked

# Generate leaf certificates
mkdir ./root/intermediate/leaf
generate_key_cert ./root/intermediate/leaf/leaf
generate_key_cert ./root/intermediate/leaf/leaf_revoked

mkdir ./root/intermediate_revoked/leaf
generate_key_cert ./root/intermediate_revoked/leaf/leaf
generate_key_cert ./root/intermediate_revoked/leaf/leaf_revoked

# Sign intermediates with root
pushd ./root 1> /dev/null || exit
sign_cert ./intermediate/intermediate root
sign_cert ./intermediate_revoked/intermediate_revoked root
popd 1> /dev/null || exit

# Sign leaves with intermediates
pushd ./root/intermediate 1> /dev/null || exit
sign_cert ./leaf/leaf intermediate
sign_cert ./leaf/leaf_revoked intermediate
popd 1> /dev/null || exit

pushd ./root/intermediate_revoked 1> /dev/null || exit
sign_cert ./leaf/leaf intermediate_revoked
sign_cert ./leaf/leaf_revoked intermediate_revoked
popd 1> /dev/null || exit

# Generate CRLs and revoke the revoked certificates
pushd ./root 1> /dev/null || exit
generate_crl root
revoke_certificate ./intermediate_revoked/intermediate_revoked.crt root
popd 1> /dev/null || exit

pushd ./root/intermediate 1> /dev/null || exit
generate_crl intermediate
revoke_certificate ./leaf/leaf_revoked.crt intermediate
popd 1> /dev/null || exit

pushd ./root/intermediate_revoked 1> /dev/null || exit
generate_crl intermediate_revoked
revoke_certificate ./leaf/leaf_revoked.crt intermediate_revoked
popd 1> /dev/null || exit

#
# Generate invalid CRLs
#

pushd ./root/intermediate 1> /dev/null || exit

# CRL with invalid thisUpdate field
# - requires openssl 3.0 to generate
ca_name=intermediate openssl ca -config "${OPENSSL_CONF_FILE}" -gencrl \
  -crl_lastupdate 21220101000000Z \
  -keyfile intermediate.key \
  -cert intermediate.crt \
  -out intermediate_invalid_thisUpdate.crl.pem \
  || exit
openssl crl -inform PEM \
  -in intermediate_invalid_thisUpdate.crl.pem \
  -outform DER -out intermediate_invalid_thisUpdate.crl \
  || exit
rm intermediate_invalid_thisUpdate.crl.pem

# CRL with invalid nextUpdate field
# - requires openssl 3.0 to generate
ca_name=intermediate openssl ca -config "${OPENSSL_CONF_FILE}" -gencrl \
  -crl_nextupdate 19220101000000Z \
  -keyfile intermediate.key \
  -cert intermediate.crt \
  -out intermediate_invalid_nextUpdate.crl.pem \
  || exit
openssl crl -inform PEM \
  -in intermediate_invalid_nextUpdate.crl.pem \
  -outform DER -out intermediate_invalid_nextUpdate.crl \
  || exit
rm intermediate_invalid_nextUpdate.crl.pem

popd 1> /dev/null || exit

#
# Create certificate chain pems and copy CRLs
#

cat ./root/intermediate/leaf/leaf.crt \
  ./root/intermediate/intermediate.crt \
  ./root/root.crt \
  > chain_root_valid_valid.pem

cat ./root/intermediate/leaf/leaf_revoked.crt \
  ./root/intermediate/intermediate.crt \
  ./root/root.crt \
  > chain_root_valid_revoked.pem

cat ./root/intermediate_revoked/leaf/leaf.crt \
  ./root/intermediate_revoked/intermediate_revoked.crt \
  ./root/root.crt \
  > chain_root_revoked_valid.pem

cat ./root/intermediate_revoked/leaf/leaf_revoked.crt \
  ./root/intermediate_revoked/intermediate_revoked.crt \
  ./root/root.crt \
  > chain_root_revoked_revoked.pem

cp ./root/root.crl ./root.crl
cp ./root/intermediate/intermediate.crl ./intermediate.crl
cp ./root/intermediate_revoked/intermediate_revoked.crl ./intermediate_revoked.crl

cp ./root/intermediate/intermediate_invalid_thisUpdate.crl ./intermediate_invalid_thisUpdate.crl
cp ./root/intermediate/intermediate_invalid_nextUpdate.crl ./intermediate_invalid_nextUpdate.crl

# Cleanup
rm -r ./root
