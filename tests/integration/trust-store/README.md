## Overview
The files in this directory are the CA files from an Amazon Linux 2012 Image. They are copied from /etc/pki/tls/certs.

## CA
- ca-bundle.crt
- ca-bundle.trust.crt

refreshing the trust store

```
cp /etc/pki/tls/certs/ca-bundle.crt  $S2N_DIR/tests/integration/trust-store
cp /etc/pki/tls/certs/ca-bundle.trust.crt $S2N_DIR/tests/integration/trust-store
```

### Updating the OS CA files

#### AL2

```
sudo yum update && sudo yum upgrade -y ca-certificates
```

#### Ubuntu

```
sudo apt update && sudo apt upgrade -y ca-certificates
```
