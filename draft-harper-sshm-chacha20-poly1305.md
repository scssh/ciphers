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

This document specifies an authenticated encryption scheme for the SSH Transport Layer Protocol that uses ChaCha20 with a 256‑bit key and Poly1305 as the message authentication code. The construction removes reliance on SSH sequence numbers as the sole nonce source and instead uses a fixed nonce prefix derived from the key exchange together with a per‑packet internal block counter. The design is compatible with RFC 7539 ChaCha20/Poly1305 semantics while addressing nonce management concerns present in previous SSH ciphersuites. This memo updates the SSH Transport Layer semantics for encryption and decryption, key derivation, and packet processing, and provides guidance for implementers and operators.


--- middle

# Introduction

SSH relies on authenticated encryption for confidentiality and integrity in the Transport Layer. Prior SSH authenticated encryption constructions that used sequence numbers directly, or deterministically derived from them, as part or all of the nonce/initialization vector (IV) risked nonce reuse for stream ciphers under certain operational circumstances, such as active manipulation of sequence tracking by an on-path adversary, subtle bugs in sequence number handling, or problematic rekey semantics, which could have catastrophic consequences for confidentiality. This document specifies an authenticated encryption suite built around **ChaCha20** and **Poly1305** that separates a fixed, session-unique **Nonce Prefix** from the per-packet **Block Counter** used by ChaCha20. The fixed prefix is derived from the key exchange and remains immutable during a given **Keying Interval**. The per-packet block counter is derived from the SSH packet sequence number but is treated strictly as an internal block counter for ChaCha20, not as a nonce prefix component controllable by an adversary, with explicit handling to ensure its use cannot cause nonce reuse across different keying intervals or independent sessions. The construction conforms to existing ChaCha20/Poly1305 usage rules defined in **RFC 7539** and follows SSH Transport Layer packet semantics, defining key material layout, nonce construction, MAC key generation, packet encryption, verification, rekey triggers, and limits.

# Conventions and Definitions

This specification uses the key words MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, RECOMMENDED, and MAY as defined in RFC 2119. Fixed_Nonce_Prefix is a 96-bit (12-byte) constant value derived from the key exchange outputs for the life of a given SSH encryption key, produced by a KDF using the outputs of the SSH Key Exchange (KEX) and must be unique per direction (client->server and server->client) and per keying interval. Block_Counter is a 32-bit unsigned integer used as ChaCha20's block counter, derived from the 32-bit packet sequence number for a packet as defined in Section 6. Nonce is the 96-bit ChaCha20/Poly1305 nonce formed by concatenating Fixed_Nonce_Prefix // Block_Counter, expressed in network byte order for ChaCha20 input. K_E is the 32-byte (256-bit) ChaCha20 encryption key. K_MAC is a 16-byte seed value used to derive the Poly1305 one-time key stream (r and s) for the authentication tag; the final Poly1305 key is 32 bytes (r//s) as specified in RFC 7539 after bit masking of r. A Keying Interval is the lifetime of a specific set of K_E and K_MAC values, typically from a KEX until a rekey event.

# Goals and Non-Goals

This document aims to provide an SSH authenticated encryption construction using **ChaCha20** and **Poly1305** consistent with **RFC 7539**, remove direct dependence of the nonce on sequence numbers alone by introducing a KEX-derived fixed nonce prefix per direction and per keying interval, provide explicit MAC key derivation and nonce usage that avoids nonce reuse across packets and across keying intervals, and specify rekey and usage limits to keep total ChaCha20 block usage within secure bounds. It does not aim to replace the SSH MAC-then-encrypt vs encrypt-then-MAC debates for legacy ciphers, instead specifying an **AEAD** construction that produces ciphertext and an authentication tag consistent with ChaCha20/Poly1305 AEAD usage, nor does it aim to change high-level SSH Transport packet framing, compression, or packet length semantics outside of what is necessary to specify AEAD usage.

# Cryptographic Primitives

The primitives used are the stream cipher **ChaCha20** with 20 rounds and a 256-bit key, and the MAC **Poly1305**, which produces 128-bit authentication tags. Implementations **MUST** use the ChaCha20 and Poly1305 constructions and bit and byte ordering exactly as specified in **RFC 7539**.

# Key Derivation and Key Material Layout

After SSH Key Exchange completes, the keying material calculated with the SSH KDF **MUST** output at least 48 bytes for this AEAD construction, apportioned as follows: **K\_E** (32 bytes) is the ChaCha20 encryption key, and **K\_MAC** (16 bytes) is the seed for Poly1305 key stream generation. Implementations **MUST** derive one independent set of these key materials per direction (client→server and server→client). The **Fixed\_Nonce\_Prefix** **MUST** also be derived from the KEX outputs separately for each direction. The KDF inputs used to derive $\mathbf{K\_E}$, $\mathbf{K\_MAC}$, and $\mathbf{Fixed\_Nonce\_Prefix}$ **MUST** include all standard SSH KDF inputs and **MUST** be clearly documented by the implementation. If a KDF yields more than 48 bytes, the additional output **MUST NOT** be used for other cryptographic purposes unless explicitly specified; implementations **SHOULD** consume only the 48 bytes required for these keys and derive any additional per-session values from the same KDF in a deterministic, documented manner.

# Nonce Construction and Usage

Nonce construction is: $\mathbf{Nonce = Fixed\_Nonce\_Prefix \parallel Block\_Counter}$. $\mathbf{Fixed\_Nonce\_Prefix}$ is 12 bytes (96 bits) and is constant for the keying interval and per direction. $\mathbf{Block\_Counter}$ is 4 bytes (32 bits) and is derived from the SSH packet sequence number. The ChaCha20 nonce input **MUST** be formed by placing **Fixed\_Nonce\_Prefix** as the high-order 12 bytes followed by the 4-byte $\mathbf{Block\_Counter}$ in little-endian form if the underlying ChaCha20 implementation expects the RFC 7539 96-bit nonce followed by a 32-bit block counter internally. The effective 128-bit ChaCha20 input state comprises: ChaCha20 32-bit block counter (least significant 32 bits) = $\mathbf{Block\_Counter}$, and ChaCha20 96-bit nonce (most significant 96 bits) = $\mathbf{Fixed\_Nonce\_Prefix}$.

## Block\_Counter derivation

The $\mathbf{Block\_Counter}$ for a packet with SSH sequence number $\mathbf{S}$ (a 32-bit unsigned integer that increments by 1 for each transported SSH packet) is defined as: $\mathbf{Block\_Counter = S}$. Implementations **MUST** treat $\mathbf{S}$ strictly as an internal ChaCha20 block counter and **MUST NOT** use $\mathbf{S}$ alone as the nonce for any other primitive or in any manner that may cause reuse across keying intervals. Because $\mathbf{Block\_Counter}$ is only 32 bits, single keying intervals **MUST** enforce limits on the number of packets to avoid block counter wraparound.

## Fixed\_Nonce\_Prefix derivation

$\mathbf{Fixed\_Nonce\_Prefix}$ **MUST** be derived from the SSH KEX output and session identifier using the KDF in a way that ensures uniqueness per direction and per keying interval. An example derivation is: $\mathbf{Fixed\_Nonce\_Prefix := KDF(session\_id, \text{"chacha20-poly1305-nonce"}, direction\_identifier)}$ where $\mathbf{direction\_identifier}$ is 'C' for client→server and 'S' for server→client, and the KDF returns 12 bytes. Implementations **MUST** document the exact KDF label and method used.

## Constraints and rationale

Using a fixed per-direction per-keying-interval prefix prevents an attacker who can manipulate sequence number semantics from causing nonce reuse across keying intervals or sessions. Any attacker who attempts to replay or reorder packets without matching $\mathbf{Fixed\_Nonce\_Prefix}$ will induce decryption failures because the $\mathbf{Block\_Counter}$ is used only as the per-packet ChaCha20 block counter.

# Poly1305 Key Derivation (MAC Key Stream)

Poly1305 requires a 32-byte one-time key per **RFC 7539**, consisting of 16 bytes $\mathbf{r}$ (with specific bit clamping) followed by 16 bytes $\mathbf{s}$. The one-time Poly1305 key used to authenticate packets during a keying interval **MUST** be derived using $\mathbf{K\_E}$, the $\mathbf{Fixed\_Nonce\_Prefix}$, and a zero $\mathbf{Block\_Counter}$. The derivation steps involve constructing a 12-byte $\mathbf{Nonce\_Derivation = Fixed\_Nonce\_Prefix \parallel 0x00000000}$, initializing ChaCha20 with $\mathbf{Key = K\_E}$ and $\mathbf{Nonce = Nonce\_Derivation}$ with an internal block counter set to 0, generating the first 64 bytes of the ChaCha20 stream (or at minimum the first 32 bytes required), taking the first 32 bytes as the Poly1305 key $\mathbf{K\_poly}$, and applying Poly1305 $\mathbf{r}$ masking as per RFC 7539. Implementations **MUST** ensure the ChaCha20 stream used for Poly1305 key derivation uses the same key $\mathbf{K\_E}$ and the same $\mathbf{Fixed\_Nonce\_Prefix}$ as used for packet encryption, with $\mathbf{Block\_Counter}$ set to zero for this derivation. The use of a zero block counter ensures the Poly1305 key is unique per keying interval and distinct from per-packet block counters used for encryption.

## K\_MAC handling

$\mathbf{K\_MAC}$ (16 bytes) is **NOT** used directly as the final Poly1305 key, but is reserved as a seed that **MAY** be incorporated into the ChaCha20 initial block for additional domain separation, only if this procedure is deterministic, documented, and ensures the resulting Poly1305 key is unique per keying interval and per direction. The mandatory minimum is that $\mathbf{K\_E}$ and $\mathbf{Fixed\_Nonce\_Prefix}$ are used as described to produce the Poly1305 key; any additional use of $\mathbf{K\_MAC}$ **MUST NOT** violate ChaCha20 or Poly1305 assumptions and **MUST** be clearly specified. Implementations **MUST** store the derived Poly1305 key ($\mathbf{r||\mathbf{s}}$) with appropriate protections and **MUST** discard the ChaCha20 keystream material after use.

## Per-packet MAC usage

The Poly1305 key derived above is used as a one-time key per packet for the entire keying interval. Implementations **MUST NOT** reuse a Poly1305 key across different keying intervals. This usage model follows RFC 7539 section recommendations for **AEAD** construction when ChaCha20 is used to generate the Poly1305 key once per keying interval and per direction, and rekeying must be enforced before the Poly1305 key is used beyond recommended limits.

## Alternative: per-packet Poly1305 key

Implementations **MAY** instead choose to derive a Poly1305 key per packet by using $\mathbf{Block\_Counter = 0}$ to derive $\mathbf{r||\mathbf{s}}$ then incrementing the internal ChaCha20 counter for each packet key derivation; this must still ensure Poly1305 keys are never reused and ChaCha20 block counter consumption limits are observed. If an implementation derives a per-packet Poly1305 key with differing $\mathbf{Block\_Counter}$ values, those values **MUST NOT** collide with those used for the packet encryption stream for the same nonce and key.

# Packet Processing: Encryption and Authentication

To produce the on-wire ciphertext and authentication tag, a packet with plaintext $\mathbf{P}$ and sequence number $\mathbf{S}$ is processed using $\mathbf{K\_E}$, $\mathbf{Fixed\_Nonce\_Prefix}$, and the derived Poly1305 key $\mathbf{K\_poly}$. The steps are: Compute $\mathbf{Block\_Counter = S}$; construct $\mathbf{Nonce = Fixed\_Nonce\_Prefix \parallel Block\_Counter}$; encrypt $\mathbf{P}$ using ChaCha20 with $\mathbf{K\_E}$ and $\mathbf{Nonce}$ starting at block counter = $\mathbf{Block\_Counter}$ to get ciphertext $\mathbf{C}$; compute the Poly1305 tag $\mathbf{T}$ over $\mathbf{A}$ = empty string and the ciphertext $\mathbf{C}$ as $\mathbf{T = Poly1305(K\_poly, A \parallel C)}$, following RFC 7539 for padding and length encoding; and output on the wire $\mathbf{C \parallel T}$. The wire format **MUST** place the 16-byte Poly1305 tag $\mathbf{T}$ immediately following the ciphertext $\mathbf{C}$.

## Notes on AAD

This construction uses an empty additional authenticated data ($\mathbf{A = empty}$) to reduce complexity and stay consistent with RFC 7539 permitted usages. Implementations **MUST** ensure any additional SSH fields requiring authentication are included in either the plaintext packet $\mathbf{P}$ before encryption or reflected via standard SSH transport layer validation; they **MUST NOT** rely on implicit inclusion of sequence numbers in AAD.

## Ordering and stream alignment

ChaCha20 encryption **MUST** be performed in full-packet units using the nonce containing the packet's $\mathbf{Block\_Counter}$. Implementers **MUST** ensure the ChaCha20 internal counter and block generation are aligned consistently with the RFC 7539 block counter model so that the derived Poly1305 key material (generated at $\mathbf{Block\_Counter = 0}$ for MAC derivation) does not overlap with blocks consumed for packet encryption.

# Packet Processing: Reception, Authentication, and Decryption

On receipt of a packet $\mathbf{C \parallel T}$, the recipient uses the expected sequence number $\mathbf{S}$ and local keys/derived values. The steps are: Compute $\mathbf{Block\_Counter = S}$; construct $\mathbf{Nonce = Fixed\_Nonce\_Prefix \parallel Block\_Counter}$; compute the Poly1305 tag $\mathbf{T'} = \mathbf{Poly1305(K\_poly, A \parallel C)}$ with $\mathbf{A = empty}$. If $\mathbf{T'}$ does not equal $\mathbf{T}$, the packet **MUST** be treated as failed authentication, and the implementation **MUST** follow SSH failure handling. If authentication succeeds, decrypt $\mathbf{C}$ using ChaCha20 with $\mathbf{K\_E}$ and $\mathbf{Nonce}$, producing plaintext $\mathbf{P}$, which is then processed as a normal SSH packet.

## Timing and constant-time verification

Poly1305 tag comparisons **MUST** be performed in **constant time** with respect to the compared values to avoid leaking authentication failures via timing side channels. Decryption **SHOULD** only proceed after the authentication tag has been successfully verified.

## Replay and out-of-order packets

Because $\mathbf{Block\_Counter}$ is derived from the SSH sequence number, out-of-order delivery or replays will result in a $\mathbf{Block\_Counter}$ that does not match the receiver's expected $\mathbf{S}$. Implementations **MUST** follow SSH transport layer replay window semantics and sequence number handling. Acceptance of out-of-order packets requires authentication verification using the $\mathbf{Block\_Counter}$ derived from the sequence number in the packet context; implementations **MUST** ensure that sequence number handling does not permit reuse of $\mathbf{Block\_Counter}$ values that would cause ChaCha20 nonce reuse.

## Rekeying and Limits

ChaCha20/Poly1305 security depends on never reusing the same $\mathbf{(key, nonce)}$ pair and limiting keystream consumption. Implementations **MUST** enforce limits and rekeying policies: Rekey before $2^{32}$ packets would be sent with the same $\mathbf{Fixed\_Nonce\_Prefix}$ and $\mathbf{K\_E}$ in a single direction (practical limit: rekey well before sequence number approaches $2^{32} - 1$). Implementations **MUST** account for multiple 64-byte ChaCha20 blocks consumed per packet when tracking total blocks used. Rekey before more than $2^{32} - 1$ ChaCha20 blocks have been generated under a single $\mathbf{K\_E/Fixed\_Nonce\_Prefix}$ pair. Because the Poly1305 key is unique per keying interval, implementations **MUST** ensure the key is never reused across different keying intervals. Implementations **SHOULD** trigger rekeying based on whichever comes first: number of packets (e.g., $2^{31}$ packets), number of bytes (e.g., $2^{40}$ bytes), elapsed time (e.g., 1 hour), or explicit administrative policy; these thresholds **MUST** be conservative relative to the theoretical limits. A conservative policy is to rekey when $\mathbf{S}$ approaches $2^{31}$ packets or earlier to avoid $\mathbf{Block\_Counter}$ reuse, which would cause catastrophic keystream reuse. When counting ChaCha20 block usage, a packet of size $N$ bytes (ciphertext) consumes $\text{ceil}(N / 64)$ blocks, and the total blocks generated for both packet encryption and Poly1305 key derivation **MUST** be tracked, with rekeying mandated before the total approaches $2^{32}$.

# Interoperability and Versioning

## Negotiation and algorithm name

This **AEAD** construction **MUST** be exposed through SSH algorithm negotiation. Implementations **SHOULD** introduce a clear algorithm identifier in the SSH Transport Layer encryption algorithm list, for example: $\mathbf{chacha20-poly1305-fixedprefix-00@scssh.github.io}$.

## Negotiation behavior

When negotiating ciphersuites, implementations **MUST** follow SSH Algorithm Negotiation rules. Fallback to existing, agreed algorithms **MAY** occur if the peer does not support the fixed-prefix variant. Implementations **MUST** document differences from other chacha20-poly1305 variants.

## Compatibility notes

To ensure interoperability, implementers **MUST** clearly document: the exact **Fixed\_Nonce\_Prefix** derivation label and KDF inputs; the endianness and byte ordering for **Block\_Counter** in the nonce (little-endian or network order); and the **Poly1305 key derivation details** (which ChaCha20 blocks were used, and whether **K\_MAC** is mixed into derivation).

## Interoperability testing

Implementations **SHOULD** provide test vectors covering key derivation, fixed nonce prefix derivation, Poly1305 key generation, encryption of simple packets, and tag verification to facilitate interoperability testing.

# Security Considerations

The central risk for ChaCha20, reuse of the same $\mathbf{(K\_E, Nonce)}$ pair, is prevented by binding $\mathbf{Fixed\_Nonce\_Prefix}$ to the KEX and mandating rekeying before $\mathbf{Block\_Counter}$ wraparound. Implementers **MUST** ensure $\mathbf{Fixed\_Nonce\_Prefix}$ is unique per direction and per keying interval and that rekeying is enforced well before any 32-bit counter wrap. Poly1305 must never be used with the same one-time key more than once; this specification makes the Poly1305 key unique per keying interval, and implementations **MUST NOT** reuse keys across keying intervals or derive per-packet Poly1305 keys in a manner that collides with ChaCha20 stream blocks used for encryption. Tag comparisons **MUST** use **constant-time comparison routines**, key material must be protected, and implementations should follow platform best practices to mitigate side channels. $\mathbf{Block\_Counter}$ is tied to the SSH sequence number, and implementations **MUST** enforce **replay protection** consistent with SSH Transport semantics, ensuring that acceptance of out-of-order packets does not cause reuse of a $\mathbf{Block\_Counter}$ value already consumed under the same $\mathbf{K\_E/Fixed\_Nonce\_Prefix}$. $\mathbf{Fixed\_Nonce\_Prefix}$ must be derived using the SSH-specified KDF or an equivalent deterministic KDF with documented labels and inputs, ensuring uniqueness and unpredictability. Since authentication must be verified before decryption, malformed packets are rejected early, and implementations should rate-limit expensive cryptographic operations if subject to DoS attacks.

# IANA Considerations

This document requests no IANA actions. Implementations planning to register a distinct algorithm identifier for this construction **SHOULD** follow IANA registration procedures for SSH algorithm names and document the identifier, semantics, and any required test vectors.
--- back

# Example Test Vectors

This appendix provides example test vectors illustrating key derivation, Fixed_Nonce_Prefix derivation, Poly1305 key generation, encryption, and tag verification. Implementations SHOULD use these vectors for interoperability testing and MUST publish additional vectors that match their exact KDF label usage and byte‑ordering conventions.

| Vector | Value |
|---|---|
| K_E (hex) | 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f |
| K_MAC (hex) | 202122232425262728292a2b2c2d2e2f |
| Fixed_Nonce_Prefix (hex) | 303132333435363738393a3b3c3d3e3f404142 | 
| Packet sequence S | 1 |
| Block_Counter (hex) | 00000001 |
| Nonce (hex) | Fixed_Nonce_Prefix || 00000001 |
| Plaintext P (hex) | 0700000001020304050607 (example SSH packet bytes) |
| Ciphertext C (hex) | [to be computed by implementation] |
| Poly1305 Tag T (hex) | [to be computed by implementation] |

Note: The example values above are illustrative. Implementers MUST publish exact computed ciphertext and tag values matching their KDF and nonce byte order choices.

# Acknowledgments
{:numbered="false"}

The author acknowledges the contributions of the cryptographic community, particularly those involved in the development of the SSH protocol and the advances in AEAD constructions. Special thanks are also extended to the individuals whose feedback has helped refine this design.
