set -e

# make root private key
# openssl genrsa -out ca.key.pem 2048

pushd "$(dirname "$0")"

# make self-signed root cert and private key
openssl req -new -x509 -noenc -days 65536 -sha256 -keyout ../ca.key.pem -out ../ca.cert.pem -config config.cnf

# make intermediate key
# openssl genrsa -out intermediate.key.pem 2048

# make intermediate csr and key
openssl req -new -noenc -sha256 -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -keyout ../intermediate.key.pem -out intermediate.csr.pem -config config.cnf

# make server csr and key
openssl req -new -noenc -sha256 -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -keyout ../server.key.pem -out server.csr.pem -config config.cnf

# sign intermediate cert with ca
openssl x509 -req -extensions req_ext -in intermediate.csr.pem -CAcreateserial -CA ../ca.cert.pem -CAkey ../ca.key.pem -out ../intermediate.cert.pem -extfile config.cnf

# sign server cert with ca
openssl x509 -req -extensions req_ext -in server.csr.pem -CAcreateserial -CA ../intermediate.cert.pem -CAkey ../intermediate.key.pem -out ../server.cert.pem -extfile config.cnf

# combine certs
cat ../server.cert.pem ../intermediate.cert.pem ../ca.cert.pem > ../fullchain.pem

# look at quic mtls generate.sh

popd