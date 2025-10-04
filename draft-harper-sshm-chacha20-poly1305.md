---
title: "Private Encryption Suite for SSH Using ChaCha20-Poly1305 Version 00"
abbrev: "SSH SSH ChaCha20-Poly1305"
category: exp

docname: draft-harper-sshm-chacha20-poly1305-latest
submissiontype: independent  # also: "independent", "editorial", "IAB", or "IRTF"
v: 3
area: "Security"
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

This document presents a new encryption suite, chacha20-poly1305-00@scssh.github.io, for the SSH protocol which utilizes ChaCha20 as the stream cipher and Poly1305 as the message authentication code. By incorporating the Authenticated Encryption with Associated Data construction from RFC 7539, this design replaces the existing dependency on sequence numbers for Nonce generation, thus enhancing both security and operational efficiency.


--- middle

# Introduction

TODO Introduction


# Conventions and Definitions

{::boilerplate bcp14-tagged}


# Security Considerations

TODO Security


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
