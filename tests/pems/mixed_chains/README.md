This folder contains "mixed key" cert chains.

The `ecdsa` cert chain contains intermediate and leaf certs that are issued from a CA with a smaller key.
```
 leaf: P-384 key
 ▲
 │ signature: ECDSA with SHA384
 │
 intermediate: P-384 key
 ▲
 │ signature: ECDSA with SHA384
 │
 root: P-256 key
 ▲
   signature:ECDSA with SHA384
```
