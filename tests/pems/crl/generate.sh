#!/bin/bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at
#
#  http://aws.amazon.com/apache2.0
#
# or in the "license" file accompanying this file. This file is distributed
# on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.
#

install_dir="$(pwd)"
openssl_conf_path="$(pwd)/openssl.conf"

get_subj() {
  common_name="$1"
  echo "/C=US/ST=Massachusetts/L=Boston/O=Amazon/OU=s2n/CN=${common_name}"
}

init_ca_dir() {
  ca_dir="$1"
  mkdir -p "${ca_dir}"
  touch "${ca_dir}/index.txt"
  echo 01 > "${ca_dir}/serial"
  echo 01 > "${ca_dir}/crlnumber"
}

generate_key_cert() {
  path="$1"
  type="$2"

  common_name=$(basename "${path}")
  out="csr.pem"
  opts=()

  case "${type}" in
    ca)
      opts=("-x509" "-days" "36500" "-extensions" "v3_ca")
      out="cert.pem"
      ;;
    intermediate)
      ;;
    leaf)
      # Common name must be localhost for s2n-tls default verify host callback
      common_name="localhost"
      ;;
    *)
      echo "invalid type"
      exit
  esac

  pushd "${path}" || exit

  openssl genrsa -out key.pem 4096 || exit
  chmod 400 key.pem

  ca_dir="." \
  openssl req -config "${openssl_conf_path}" \
      -key key.pem \
      -new -sha256 \
      "${opts[@]}" \
      -out "${out}" \
      -subj "$(get_subj ${common_name})" \
      || exit

  # Create a chain with just the root certificate for validating child certificates
  if [ "${type}" = "ca" ]; then
    cp cert.pem chain.pem
  fi

  popd || exit
}

verify_cert() {
  ca_file_path="$1"
  cert_file_path="$2"
  crl_file_path="$3"

  opts=()
  if [ -n "${crl_file_path}" ]; then
      is_revoked=$4
      if [ -z "${is_revoked}" ]; then
        exit
      fi

      opts=("-CRLfile" "${crl_file_path}" "-crl_check")
  fi

  verify_stderr=$(
    openssl verify \
        -CAfile "${ca_file_path}" \
        "${opts[@]}" \
        "${cert_file_path}" \
        2>&1
  )
  verify_ret=$?

  if [ -n "${crl_file_path}" ] && [ ${is_revoked} -eq 1 ]; then
    # Ensure openssl verify failed due to certificate revocation
    if ! [[ "${verify_stderr}" =~ .*"certificate revoked".* ]]; then
      exit
    fi
  else
    # Ensure openssl verify succeeded
    if [ ${verify_ret} -ne 0 ]; then
      exit
    fi
  fi
}

sign_cert() {
  signer_path="$1"
  to_sign_path="$2"
  signer_type="$3"

  opts=()
  case "${signer_type}" in
    ca)
      opts=("-extensions" "v3_intermediate_ca")
      ;;
    intermediate)
      opts=("-extensions" "usr_cert")
      ;;
    *)
      echo "invalid type"
      exit
  esac

  ca_dir="${signer_path}" \
  openssl ca -config "${openssl_conf_path}" -batch \
      -days 36500 -notext -md sha256 \
      "${opts[@]}" \
      -in "${to_sign_path}/csr.pem" \
      -out "${to_sign_path}/cert.pem" \
      || exit

  # Ensure openssl can validate the signed certificate
  verify_cert "${signer_path}/chain.pem" "${to_sign_path}/cert.pem"

  # Create a chain that includes the newly signed certificate and all parent certificates
  # for validating future child certificates
  if [ "${signer_type}" = "ca" ]; then
    cat "${to_sign_path}/cert.pem" "${signer_path}/chain.pem" > "${to_sign_path}/chain.pem"
  fi
}

generate_crl() {
  path="$1"

  pushd "${path}" || exit
  ca_dir="." \
  openssl ca -config "${openssl_conf_path}" -gencrl \
    -out crl.pem \
      || exit
  popd || exit
}

revoke_cert() {
  ca_path="$1"
  cert_path="$2"

  ca_dir="${ca_path}" \
  openssl ca -config "${openssl_conf_path}" \
      -revoke "${cert_path}/cert.pem" \
      || exit
  generate_crl "${ca_path}"
}

base_dir=$(mktemp -d)
pushd "${base_dir}" || exit

#
# Generate certificate chains of valid and revoked certificates with 1 intermediate CA.
#
# root -> valid intermediate   -> valid leaf
#                              -> revoked leaf
#      -> revoked intermediate -> valid leaf
#                              -> revoked leaf
#

# Generate root certificate
init_ca_dir root
generate_key_cert root ca

# Generate intermediate certificates
init_ca_dir root/intermediate
generate_key_cert root/intermediate intermediate
sign_cert root root/intermediate ca

init_ca_dir root/intermediate_revoked
generate_key_cert root/intermediate_revoked intermediate
sign_cert root root/intermediate_revoked ca

# Generate leaf certificates
mkdir root/intermediate/leaf
generate_key_cert root/intermediate/leaf leaf
sign_cert root/intermediate root/intermediate/leaf intermediate

mkdir root/intermediate/leaf_revoked
generate_key_cert root/intermediate/leaf_revoked leaf
sign_cert root/intermediate root/intermediate/leaf_revoked intermediate

mkdir root/intermediate_revoked/leaf
generate_key_cert root/intermediate_revoked/leaf leaf
sign_cert root/intermediate_revoked root/intermediate_revoked/leaf intermediate

mkdir root/intermediate_revoked/leaf_revoked
generate_key_cert root/intermediate_revoked/leaf_revoked leaf
sign_cert root/intermediate_revoked root/intermediate_revoked/leaf_revoked intermediate

# Generate CRLs and revoke the revoked certificates
generate_crl root
revoke_cert root root/intermediate_revoked

generate_crl root/intermediate
revoke_cert root/intermediate root/intermediate/leaf_revoked

generate_crl root/intermediate_revoked
revoke_cert root/intermediate_revoked root/intermediate/leaf_revoked

# Ensure openssl verify reads generated CRLs and properly rejects certificates
verify_cert root/chain.pem root/intermediate/cert.pem root/crl.pem 0
verify_cert root/chain.pem root/intermediate_revoked/cert.pem root/crl.pem 1

verify_cert root/intermediate/chain.pem root/intermediate/leaf/cert.pem root/intermediate/crl.pem 0
verify_cert root/intermediate/chain.pem root/intermediate/leaf_revoked/cert.pem root/intermediate/crl.pem 1

verify_cert root/intermediate_revoked/chain.pem root/intermediate_revoked/leaf/cert.pem root/intermediate_revoked/crl.pem 0
verify_cert root/intermediate_revoked/chain.pem root/intermediate_revoked/leaf_revoked/cert.pem root/intermediate_revoked/crl.pem 1

# Generate CRLs with invalid timestamps. Requires Openssl 3.0.
ca_dir="root/intermediate" \
openssl ca -config "${openssl_conf_path}" -gencrl \
    -crl_lastupdate 21220101000000Z \
    -out "${install_dir}/intermediate_invalid_this_update_crl.pem" \
    || exit

ca_dir="root/intermediate" \
openssl ca -config "${openssl_conf_path}" -gencrl \
    -crl_nextupdate 500101000000Z \
    -out "${install_dir}/intermediate_invalid_next_update_crl.pem" \
    || exit

#
# Create certificate chain pems and copy CRLs and keys
#

cp root/cert.pem "${install_dir}/root_cert.pem"

cat root/intermediate/leaf/cert.pem \
    root/intermediate/cert.pem \
    > "${install_dir}/none_revoked_cert_chain.pem"
cp root/intermediate/leaf/key.pem "${install_dir}/none_revoked_key.pem"

cat root/intermediate/leaf_revoked/cert.pem \
    root/intermediate/cert.pem \
    > "${install_dir}/leaf_revoked_cert_chain.pem"
cp root/intermediate/leaf_revoked/key.pem "${install_dir}/leaf_revoked_key.pem"

cat root/intermediate_revoked/leaf/cert.pem \
    root/intermediate_revoked/cert.pem \
    > "${install_dir}/intermediate_revoked_cert_chain.pem"
cp root/intermediate_revoked/leaf/key.pem "${install_dir}/intermediate_revoked_key.pem"

cat root/intermediate_revoked/leaf_revoked/cert.pem \
    root/intermediate_revoked/cert.pem \
    > "${install_dir}/all_revoked_cert_chain.pem"
cp root/intermediate_revoked/leaf_revoked/key.pem "${install_dir}/all_revoked_key.pem"

cp root/crl.pem "${install_dir}/root_crl.pem"
cp root/intermediate/crl.pem "${install_dir}/intermediate_crl.pem"
cp root/intermediate_revoked/crl.pem "${install_dir}/intermediate_revoked_crl.pem"

popd || exit

# Cleanup
rm -rf "${base_dir}"

# Ensure that s2nc accepts all generated certificates
./test_s2nc.sh || exit

echo "Generation successful."
