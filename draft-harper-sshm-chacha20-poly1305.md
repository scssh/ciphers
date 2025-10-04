---
title: "A New Encryption Suite for SSH Using ChaCha20-Poly1305"
abbrev: "SSH ChaCha20-Poly1305"
category: exp

docname: draft-harper-sshm-chacha20-poly1305-latest
submissiontype: independent
v: 3
area: SEC
keyword: SSH

author:
 -
    fullname: Sophie Harper
    organization: Independent
    email: sphpr@proton.me

normative:
  RFC7539:

informative:

...

--- abstract

This document presents a new encryption suite for the SSH (Secure Shell) protocol which utilizes ChaCha20 as the stream cipher and Poly1305 as the message authentication code. By incorporating the AEAD (Authenticated Encryption with Associated Data) construction from RFC 7539, this design replaces the existing dependency on sequence numbers for Nonce generation, thus enhancing both security and operational efficiency.

--- middle

TODO

--- back

Acknowledgments

The author acknowledges the contributions of the cryptographic community, particularly those involved in the development of the SSH protocol and the advances in AEAD constructions. Special thanks are also extended to the individuals whose feedback has helped refine this design.

