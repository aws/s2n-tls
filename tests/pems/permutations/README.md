All of the certs in this directory are generated using the `generate-certs.sh` script included in this directory.

### PKI Structure
```
   ┌────root──────┐
   │              │
   │              │
   ▼              │
 branch           │
   │              │
   │              │
   │              │
   ▼              ▼
 leaf            client
```
`generate-certs.sh` will generate 4 certificates for each key/length/digest selection, with the signing relationships that are indicated in the diagram above. This cert chain length was chosen because it matches the cert chain length used by public AWS services.