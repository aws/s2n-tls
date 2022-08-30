
s2nc_path="../../../bin/s2nc"
s2nd_path="../../../bin/s2nd"

cert_chains=("valid_valid" "valid_revoked" "revoked_valid" "revoked_revoked")

for cert_chain in "${cert_chains[@]}"; do
  "${s2nd_path}" \
      --self-service-blinding \
      --negotiate \
      --cert "${cert_chain}_cert_chain.pem" \
      --key "${cert_chain}_key.pem" \
      localhost 8888 &
  s2nd_pid=$!

  "${s2nc_path}" \
      --ca-file "root_cert.pem" \
      localhost 8888
  s2nc_success=$?

  kill ${s2nd_pid}

  if [ ${s2nc_success} -ne 0 ]; then
    exit
  fi
done
