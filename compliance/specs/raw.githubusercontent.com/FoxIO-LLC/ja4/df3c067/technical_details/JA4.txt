# JA4: TLS Client Fingerprinting

![JA4](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.png)

JA4 looks at the TLS Client Hello packet and builds a fingerprint of the client based on attributes within the packet.

### JA4 Algorithm:
(QUIC=”q”, DTLS="d", or Normal TLS=”t”)  
(2 character TLS version)  
(SNI=”d” or no SNI=”i”)  
(2 character count of ciphers)  
(2 character count of extensions)  
(first and last characters of first ALPN extension value)  
_  
(sha256 hash of the list of cipher hex codes sorted in hex order, truncated to 12 characters)  
_  
(sha256 hash of (the list of extension hex codes sorted in hex order)_(the list of signature algorithms), truncated to 12 characters)  
  
The end result is a fingerprint that looks like:  
t13d1516h2_8daaf6152771_b186095e22b6  
  
## Details:
The program needs to ignore GREASE values anywhere it sees them: (https://datatracker.ietf.org/doc/html/draft-davidben-tls-grease-01#page-5)

### QUIC and DTLS:
“q”, "d" or “t”, denotes whether the hello packet is for QUIC, DTLS, or normal TLS.

https://en.wikipedia.org/wiki/QUIC  
QUIC is the protocol which the new HTTP/3 standard utilizes, encapsulating TLS 1.3 into UDP packets. As QUIC was developed by Google, if an organization heavily utilizes Google products, QUIC could make up half of their network traffic, so this is important to capture.  

https://en.wikipedia.org/wiki/Datagram_Transport_Layer_Security
DTLS is a version of TLS that can operate over UDP or SCTP.

If the protocol is QUIC then the first character of the fingerprint is “q”, if DTLS it is "d", else it is “t”.  

### TLS and DTLS Version:
The TLS version is shown in 3 different places. If extension 0x002b exists (supported_versions), then the version is the highest value in the extension. Remember to ignore GREASE values. If the extension doesn’t exist, then the TLS version is the value of the Protocol Version. Handshake version (located at the top of the packet) should be ignored.

0x0304 = TLS 1.3 = “13”  
0x0303 = TLS 1.2 = “12”  
0x0302 = TLS 1.1 = “11”  
0x0301 = TLS 1.0 = “10”  
0x0300 = SSL 3.0 = “s3”  
0x0002 = SSL 2.0 = “s2”  
0xfeff = DTLS 1.0 = "d1"  
0xfefd = DTLS 1.2 = "d2"  
0xfefc = DTLS 1.3 = "d3"  
  
Unknown = “00”

### SNI:
If the SNI extension (0x0000) exists, then the destination of the connection is a domain, or “d” in the fingerprint. If the SNI does not exist, then the destination is an IP address, or “i”.

### Number of Ciphers:
2 character number of cipher suites, so if there’s 6 cipher suites in the hello packet, then the value should be “06”. If there’s > 99, which there should never be, then output “99”. Remember, ignore GREASE values. They don’t count.

### Number of Extensions:
Same as counting ciphers. Ignore GREASE. Include SNI and ALPN.

### ALPN Extension Value:
The first and last alphanumeric characters of the ALPN (Application-Layer Protocol Negotiation) first value.  
List of possible ALPN Values (scroll down): https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml

In the above example, the first ALPN value is h2 so the first and last characters to use in the fingerprint are “h2”. If the first ALPN listed was http/1.1 then the first and last characters to use in the fingerprint would be “h1”.

In Wireshark this field is located under tls.handshake.extensions_alpn_str

If there is no ALPN extension, no ALPN values, or the first ALPN value is empty, then we print "00" as the value in the fingerprint. If the first ALPN value is only a single character, then that character is treated as both the first and last character.

If the first or last byte of the first ALPN is non-alphanumeric (meaning not `0x30-0x39`, `0x41-0x5A`, or `0x61-0x7A`), then we print the first and last characters of the hex representation of the first ALPN instead. For example:
* `0xAB` would be printed as "ab"
* `0xAB 0xCD` would be printed as "ad"
* `0x30 0xAB` would be printed as "3b"
* `0x30 0x31 0xAB 0xCD` would be printed as "3d"
* `0x30 0xAB 0xCD 0x31` would be printed as "01"

### Cipher hash:
A 12 character truncated sha256 hash of the list of ciphers sorted in hex order, first 12 characters. The list is created using the 4 character hex values of the ciphers, lower case, comma delimited, ignoring GREASE.  
Example:
```
1301,1302,1303,c02b,c02f,c02c,c030,cca9,cca8,c013,c014,009c,009d,002f,0035
```
Is sorted to:
```
002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9 = 8daaf6152771
```

If there are no ciphers in the sorted cipher list, then the value of JA4_b is set to `000000000000`  
We do this rather than running a sha256 hash of nothing as this makes it clear to the user when a field has no values.

### Extension hash:
A 12 character truncated sha256 hash of the list of extensions, sorted by hex value, followed by the list of signature algorithms, in the order that they appear (not sorted).

The extension list is created using the 4 character hex values of the extensions, lower case, comma delimited, sorted (not in the order they appear). Ignore the SNI extension (0000) and the ALPN extension (0010) as we’ve already captured them in the _a_ section of the fingerprint. These values are omitted so that the same application would have the same _c_ section of the fingerprint regardless of if it were going to a domain, IP, or changing ALPNs.

For example:
```
001b,0000,0033,0010,4469,0017,002d,000d,0005,0023,0012,002b,ff01,000b,000a,0015
```
Is sorted to:
```
0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01
```
(notice 0000 and 0010 is removed)

The signature algorithm hex values are then added to the end of the list in the order that they appear (not sorted) with an underscore delimiting the two lists.  
For example the signature algorithms:  
```
0403,0804,0401,0503,0805,0501,0806,0601
```
Are added to the end of the previous string to create:
```
0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_0403,0804,0401,0503,0805,0501,0806,0601
```
Hashed to:
```
e5627efa2ab19723084c1033a96c694a45826ab5a460d2d3fd5ffcfe97161c95
```
Truncated to first 12 characters:
```
e5627efa2ab1
```

If there are no signature algorithms in the hello packet, then the string ends without an underscore and is hashed.   
For example:
```
0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01 = 6d807ffa2a79
```

If there are no extensions in the sorted extensions list, then the value of JA4_c is set to `000000000000`  
We do this rather than running a sha256 hash of nothing as this makes it clear to the user when a field has no values.

### Example

JA4 fingerprint:  
t (TLS over TCP)  
13 (TLS version 1.3)  
d (SNI exists so it’s going to a domain)  
15 (15 cipher suites ignoring grease)  
16 (16 extensions ignoring grease)  
h2 (first and last characters of the first ALPN extension value)  
_  
8daaf6152771 (truncated sha256 hash of the list of ciphers sorted)
_  
e5627efa2ab1 (truncated sha256 hash of the list of extensions sorted, SNI and ALPN removed, followed by the list of signature algorithms)
```
JA4 = t13d1516h2_8daaf6152771_e5627efa2ab1  
```
### Raw Output  
The program should allow for raw outputs either sorted or original.  
-r (raw fingerprint) -o (original) 

The raw fingerprint for JA4 would look like this:
```
JA4_r = t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_0403,0804,0401,0503,0805,0501,0806,0601
```

The "o" option includes the original values in the original order, less GREASE values. This means SNI (0000) and ALPN (0010) are included. 

The raw fingerprint with the original ordering (-o) would look like this:
```
JA4_ro = t13d1516h2_1301,1302,1303,c02b,c02f,c02c,c030,cca9,cca8,c013,c014,009c,009d,002f,0035_001b,0000,0033,0010,4469,0017,002d,000d,0005,0023,0012,002b,ff01,000b,000a,0015_0403,0804,0401,0503,0805,0501,0806,0601
```
When ‘-o’ flag is specified, ‘ja4’ field must be renamed to ‘ja4_o’:
```
JA4_o = t13d1516h2_acb858a92679_18f69afefd3d
```

