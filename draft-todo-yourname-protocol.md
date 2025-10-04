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
 - RFC7539

informative:

...

--- abstract

This document presents a new encryption suite for the SSH (Secure Shell) protocol which utilizes ChaCha20 as the stream cipher and Poly1305 as the message authentication code. By incorporating the AEAD (Authenticated Encryption with Associated Data) construction from RFC 7539, this design replaces the existing dependency on sequence numbers for Nonce generation, thus enhancing both security and operational efficiency.

--- middle

# Introduction

The SSH protocol is integral to securing network communications, providing authentication, confidentiality, and integrity. While previous encryption methods have served their purpose, they are susceptible to certain vulnerabilities, particularly stemming from the reuse or manipulation of Nonce values. This document introduces a new encryption suite based on ChaCha20 and Poly1305, addressing these concerns by ensuring that Nonce generation is not solely reliant on sequence numbers.

The proposed design utilizes a fixed Nonce prefix derived from the Key Exchange (KEX) process and an internal block counter to facilitate secure and efficient encryption and authentication.

# Conventions and Definitions

This document utilizes terms defined in RFC 2119 to indicate requirements. In this context, "Nonce" refers to a unique value that is used only once for cryptographic operations, while "Key Exchange" (KEX) designates the process by which cryptographic keys are generated and distributed between communicating parties.

# Core Cryptographic Primitives

The encryption suite incorporates the following core cryptographic primitives:

| Primitive           | Description                                          |
|---------------------|------------------------------------------------------|
| **Stream Cipher**   | ChaCha20, employing a 256-bit key and 20 rounds     |
| **Message Authentication Code (MAC)** | Poly1305, used for integrity verification |

# Key and Nonce Management

In the proposed design, the traditional practice of using the sequence number as the Nonce is eliminated. Instead, a 96-bit (12-byte) Nonce structure, consistent with RFC 7539, is implemented. 

The key derivation process post-Key Exchange yields a 64-byte key, of which 48 bytes are utilized. The specific segments are outlined in the table below:

| Key Segment         | Length        | Purpose                                        |
|---------------------|---------------|------------------------------------------------|
| **K_E (Encryption Key)** | 32 bytes (256 bits) | Utilized for ChaCha20 to encrypt data       |
| **K_MAC (MAC Key Seed)** | 16 bytes (128 bits) | Serves as the seed for Poly1305 keys         |
| **Total Length**    | **48 bytes**  | Reduced from the original 64 bytes            |

It is notable that K_E is the sole encryption key, simplifying the key management process by eliminating the need for a secondary encryption key.

# Nonce Construction

The Nonce utilized by ChaCha20 is crafted as follows:

N = Fixed_Nonce_Prefix || Block_Counter

The "Fixed_Nonce_Prefix" is a 96-bit (12-byte) value derived from the hash output of the Key Exchange handshake. This prefix is meant to be fixed and immutable throughout the session, decoupling the Nonce from any attacker-manipulable variables such as sequence numbers.

The "Block_Counter" is a 32-bit (4-byte) segment that uses the 32-bit sequence number as an internal counter for ChaCha20. This ensures compliance with RFC 7539 while maintaining the integrity of the Nonce construction.

# MAC Key Stream Generation

Poly1305 requires a 256-bit key consisting of values r and s. The process to derive this key employs K_E and a zero Nonce. The steps are outlined as follows:

1. K_MAC (16 bytes) is zero-padded to 32 bytes, forming the seed for both Poly1305 keys r and s.
2. The ChaCha20 transformation is applied as follows:
   - **Key:** K_E
   - **Nonce:** Fixed_Nonce_Prefix || 0
   - **Internal Block Counter:** 0
3. The first 32 bytes produced by the ChaCha20 transformation are extracted and assigned as the final r and s values for Poly1305.
4. The required bit-clearing operation for r is performed in accordance with Poly1305 specifications.

# Packet Processing Flow

When sending an SSH packet P, which contains Length, Padding, and Payload, the processing flow is as follows:

1. Generate the Poly1305 key using K_E and the constructed Nonce where the block counter is set to 0.
2. Construct a 12-byte Nonce formed by concatenating the Fixed_Nonce_Prefix with the current Sequence_Number.
3. Encrypt the packet P using K_E along with the constructed Nonce, resulting in the ciphertext C.
4. Authenticate the ciphertext C using the Poly1305 MAC with the derived MAC_Key. The authenticated data (A) is required to be an empty string to maintain simplicity as permitted by RFC 7539. The authentication tag is generated based on the ciphertext C.
5. Finally, concatenate the ciphertext C and the authentication tag to form the complete output packet that is sent.

The recipient will reverse these steps to authenticate and decrypt the incoming packet, ensuring the integrity and confidentiality of the transmitted data.

# Security Considerations

The design outlined in this document aims to significantly enhance the security of SSH communications by addressing specific vulnerabilities. The fixed Nonce prefix effectively limits the potential for Nonce reuse attacks, particularly in scenarios involving manipulated sequence numbers. Any discrepancies in Nonce values between sender and receiver will result in decryption failure, thereby offering immediate detection of tampering.

Moreover, by decoupling the Nonce from sequence numbers, the possibility of predictable Nonce generation is minimized. This reinforces the overall robustness of the encryption process.

# IANA Considerations

This document has no IANA actions.

--- back

# Acknowledgments

The author acknowledges the contributions of the cryptographic community, particularly those involved in the development of the SSH protocol and the advances in AEAD constructions. Special thanks are also extended to the individuals whose feedback has helped refine this design.

