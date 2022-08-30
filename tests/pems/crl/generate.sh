#!/bin/bash

set -o xtrace

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
  openssl verify -CAfile "${signer_path}"/chain.pem "${to_sign_path}"/cert.pem || exit

  # Create a chain that includes the newly signed certificate and all parent certificates
  # for validating future child certificates
  if [ "${signer_type}" = "ca" ]; then
    cat "${to_sign_path}/cert.pem" "${signer_path}/chain.pem" > "${to_sign_path}/chain.pem"
  fi
}

#base_dir=$(mktemp -d)
mkdir test_dir
base_dir="test_dir"
pushd "${base_dir}" || exit

init_ca_dir root
generate_key_cert root ca

init_ca_dir root/intermediate
generate_key_cert root/intermediate intermediate
sign_cert root root/intermediate ca

mkdir root/intermediate/leaf
generate_key_cert root/intermediate/leaf leaf
sign_cert root/intermediate root/intermediate/leaf intermediate

cat root/intermediate/leaf/cert.pem root/intermediate/cert.pem > test_cert_chain.pem
cp root/cert.pem test_root.pem
cp root/intermediate/leaf/key.pem test_key.pem

popd || exit

