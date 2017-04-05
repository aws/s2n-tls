#export LIBCRYPTO_ROOT=/usr/local/Cellar/openssl/1.0.2k
export BITCODE_DIR=$(pwd)/bitcode/
#export CLANG=/usr/local/Cellar/llvm/3.9.1/bin/clang
export CLANG=clang-3.8
LINKER=llvm-link-3.8

make -C stuffer  $(pwd)/bitcode/s2n_stuffer.bc
make -C crypto   $(pwd)/bitcode/s2n_stream_cipher_null.bc
make -C crypto   $(pwd)/bitcode/s2n_stream_cipher_rc4.bc
make -C crypto   $(pwd)/bitcode/s2n_aead_cipher_chacha20_poly1305.bc
make -C crypto   $(pwd)/bitcode/s2n_composite_cipher_aes_sha.bc
make -C crypto   $(pwd)/bitcode/s2n_cbc_cipher_aes.bc
make -C crypto   $(pwd)/bitcode/s2n_aead_cipher_aes_gcm.bc
make -C crypto   $(pwd)/bitcode/s2n_cbc_cipher_3des.bc
make -C tls      $(pwd)/bitcode/s2n_aead.bc
make -C tls      $(pwd)/bitcode/s2n_alerts.bc
make -C tls      $(pwd)/bitcode/s2n_cbc.bc
make -C tls      $(pwd)/bitcode/s2n_cipher_suites.bc
make -C tls      $(pwd)/bitcode/s2n_client_ccs.bc
make -C tls      $(pwd)/bitcode/s2n_client_extensions.bc
make -C tls      $(pwd)/bitcode/s2n_client_finished.bc
make -C tls      $(pwd)/bitcode/s2n_client_hello.bc
make -C tls      $(pwd)/bitcode/s2n_client_key_exchange.bc
make -C tls      $(pwd)/bitcode/s2n_config.bc
make -C tls      $(pwd)/bitcode/s2n_connection.bc
make -C tls      $(pwd)/bitcode/s2n_handshake.bc
make -C tls      $(pwd)/bitcode/s2n_handshake_io.bc
make -C tls      $(pwd)/bitcode/s2n_ocsp_stapling.bc
make -C tls      $(pwd)/bitcode/s2n_record_read.bc
make -C tls      $(pwd)/bitcode/s2n_record_write.bc
make -C tls      $(pwd)/bitcode/s2n_recv.bc
make -C tls      $(pwd)/bitcode/s2n_resume.bc
make -C tls      $(pwd)/bitcode/s2n_send.bc
make -C tls      $(pwd)/bitcode/s2n_server_ccs.bc
make -C tls      $(pwd)/bitcode/s2n_server_cert.bc
make -C tls      $(pwd)/bitcode/s2n_server_done.bc
make -C tls      $(pwd)/bitcode/s2n_server_extensions.bc
make -C tls      $(pwd)/bitcode/s2n_server_finished.bc
make -C tls      $(pwd)/bitcode/s2n_server_hello.bc
make -C tls      $(pwd)/bitcode/s2n_server_key_exchange.bc
make -C tls      $(pwd)/bitcode/s2n_shutdown.bc
make -C tls      $(pwd)/bitcode/s2n_tls.bc
make -C tls      $(pwd)/bitcode/s2n_cipher_preferences.bc
make -C utils    $(pwd)/bitcode/s2n_socket.bc

$LINKER -o $(pwd)/s2n.bc $BITCODE_DIR/*.bc

#cp s2n.bc ~/Source/s2n-handshake-verification/experiments/

saw cork-uncork.saw
