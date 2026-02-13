# Security Policy

## Reporting Security Issues

Amazon Web Services (AWS) is dedicated to the responsible disclosure of security vulnerabilities.  
  
We kindly ask that you **do not** open a public GitHub issue to report security concerns.  
  
Instead, please submit the issue to the AWS Vulnerability Disclosure Program via [HackerOne](https://hackerone.com/aws_vdp) or send your report via [email](mailto:aws-security@amazon.com).  
  
For more details, visit the [AWS Vulnerability Reporting Page](http://aws.amazon.com/security/vulnerability-reporting/).  

Thank you in advance for collaborating with us to help protect our customers.

## Threat Model

### Out of Scope Attacks

Applications integrating with s2n-tls are responsible for the security of the host on which the process loading the s2n-tls library runs. This means the following attacks are considered out of scope:
* On-host side-channel attacks via CPU/hardware flaws such as Meltdown/Spectre
* Attacks requiring on-host root access to processes, memory, sockets or files 
* Attacks involving physical fault injection, such as high voltage and temperatures or electromagnetic pulses
* Side-channel attacks requiring physical observation to detect

### Adversarial Models

s2n-tls considers the following adversarial models to be in scope:

#### Network Adversary

An active network attacker with complete control over the network used to communicate between a client and server. This attacker can:

* Intercept, modify, and send all messages sent on public network channels
* Attempt to downgrade the protocol version or cryptographic parameters negotiated between a client and server
* Obtain long-term secrets (e.g. private keys) of any client or server after a session is complete
* Exploit weak long-term keys given sufficient computation
* Exploit weak hash functions used in key derivation, HMAC, or signatures
* Exploit timing differences practically measurable over a network (e.g. remote timing side-channel attacks)
* Record encrypted traffic now for future decryption once a cryptographically relevant quantum computer is available (harvest now, decrypt later)

#### Malicious Client

In addition to the network adversary capabilities above, a malicious client may:

* Attempt to bypass client certificate-based authentication
* Send crafted payloads (e.g. client certificates) to exploit flaws in parsers
* Offer only weak cryptographic parameters (e.g. ciphersuites, key exchange groups) to influence the server's negotiation choices
* Attempt to spoof other trusted clients by manipulating session identifiers
* Cause denial of service through resource exhaustion

#### Malicious Server

In addition to the network adversary capabilities above, a malicious server may:

* Attempt to downgrade the connection by offering only weak ciphersuites, keys, DH groups, or hash functions
* Send crafted payloads (e.g. server certificates, extensions, handshake messages) to exploit flaws in parsers
* Present certificates that have been revoked or flagged via Certificate Transparency

### Vulnerability Scope

Given the adversarial models above, the following are examples of issues considered security-relevant and should be reported in accordance with [Reporting Security Issues](#reporting-security-issues):

* Implementation defects that compromise confidentiality, integrity, or availability (e.g. memory safety bugs, undefined behavior)
* Logic bugs that lead to incorrect TLS negotiation, handshake errors, or authentication bypass
* Negotiation of weak or non-policy-approved cryptographic algorithms
* Flaws in default configurations that could lead to insecure operation

The following are generally not considered vulnerabilities in this project's context:

* Application misuse of APIs that behave as documented
* Issues in the operating environment (e.g. OS, networking stack, hardware)
* Usage patterns documented as warnings in the [usage guide](https://aws.github.io/s2n-tls/usage-guide/)

If you are unsure whether an issue is security-relevant, please err on the side of caution and report it through the [Reporting Security Issues](#reporting-security-issues) process.

## Prenotification Policy

If you package or distribute s2n-tls, or use s2n-tls as part of a large multi-user service, you may be eligible for pre-notification of future s2n-tls releases. Please contact s2n-pre-notification@amazon.com.