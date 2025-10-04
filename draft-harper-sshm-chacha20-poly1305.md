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

SSH relies on authenticated encryption to provide confidentiality and integrity for the Transport Layer. Prior SSH authenticated encryption constructions have used sequence numbers directly (or deterministically derived from sequence numbers) as all or part of the nonce/initialization vector (IV). Under some operational circumstances—such as active manipulation of SSH packet sequence tracking by an on‑path adversary, subtle bugs in sequence number handling, or problematic rekey semantics—this can increase the risk of nonce reuse for stream ciphers, with catastrophic consequences for confidentiality.

This document specifies an authenticated encryption suite built around ChaCha20 and Poly1305 that separates a fixed, session‑unique nonce prefix from the per‑packet block counter used by ChaCha20. The fixed prefix is derived from the key exchange and remains immutable during a given keying interval; the per‑packet block counter is derived from the SSH packet sequence number but is treated strictly as an internal block counter for ChaCha20 (not as a nonce prefix component controllable by an adversary), with explicit handling to ensure that its use cannot cause nonce reuse across different keying intervals or across independent sessions.

The construction conforms to existing ChaCha20/Poly1305 usage rules defined in **RFC 7539** and follows SSH Transport Layer packet semantics. The document defines key material layout, nonce construction, MAC key generation, packet encryption, verification, rekey triggers, and limits.

# Conventions and Definitions

This specification uses the key words MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, RECOMMENDED, and MAY as defined in RFC 2119.

Definitions used in this document:

* **Fixed\_Nonce\_Prefix**: A 96‑bit (12‑byte) constant value derived from the key exchange outputs for the life of a given SSH encryption key. The prefix is produced by a KDF using the outputs of the SSH Key Exchange (KEX) and must be unique per direction (client→server and server→client) and per keying interval.
* **Block\_Counter**: A 32‑bit unsigned integer used as ChaCha20's block counter. For a packet, this value is derived from the 32‑bit packet sequence number as defined in Section 6.
* **Nonce**: The 96‑bit ChaCha20/Poly1305 nonce formed by concatenating Fixed\_Nonce\_Prefix || Block\_Counter, expressed in network byte order for ChaCha20 input.
* **K\_E**: 32‑byte (256‑bit) ChaCha20 encryption key.
* **K\_MAC**: 16‑byte seed value used to derive the Poly1305 one‑time key stream (r and s) for the authentication tag; the final Poly1305 key is 32 bytes (r||s) as specified in RFC 7539 after bit masking of r.
* **Keying Interval**: The lifetime of a specific set of K\_E and K\_MAC values, typically from a KEX until a rekey event.

# Goals and Non‑Goals

This document aims to:

* Provide an SSH authenticated encryption construction using ChaCha20 and Poly1305 consistent with RFC 7539.
* Remove direct dependence of the nonce on sequence numbers alone by introducing a KEX‑derived fixed nonce prefix per direction and per keying interval.
* Provide explicit MAC key derivation and nonce usage that avoids nonce reuse across packets and across keying intervals.
* Specify rekey and usage limits to keep total ChaCha20 block usage within secure bounds.

This document does not aim to:

* Replace the SSH MAC‑then‑encrypt vs encrypt‑then‑MAC debates for legacy ciphers; it specifies an AEAD construction that produces ciphertext and an authentication tag consistent with ChaCha20/Poly1305 AEAD usage.
* Change high‑level SSH Transport packet framing, compression, or packet length semantics outside of what is necessary to specify AEAD usage.

# Cryptographic Primitives

| Primitive | Parameters |
| :--- | :--- |
| Stream Cipher | ChaCha20, 20 rounds, 256‑bit key |
| MAC | Poly1305, producing 128‑bit authentication tags |

Implementations MUST use the ChaCha20 and Poly1305 constructions and bit and byte ordering exactly as specified in **RFC 7539**.

# Key Derivation and Key Material Layout

After SSH Key Exchange completes and the keying material is calculated with the SSH KDF (as specified by the transported KEX algorithm), the KDF MUST output at least 48 bytes of keying material for this AEAD construction. The 48 bytes are apportioned as follows:

| Key Segment | Length | Use |
| :--- | ---: | :--- |
| K\_E | 32 bytes | ChaCha20 encryption key |
| K\_MAC | 16 bytes | Seed for Poly1305 key stream generation (see Section 7) |

Implementations MUST derive one independent set of these key materials per direction (client→server and server→client). The Fixed\_Nonce\_Prefix (Section 6) MUST also be derived from the KEX outputs separately for each direction. The KDF inputs used to derive K\_E, K\_MAC, and Fixed\_Nonce\_Prefix MUST include all standard SSH KDF inputs (session identifier, exchange hash, and the unique letter value per SSH conventions) and MUST be clearly documented by the implementation.

If a KDF in use yields more than 48 bytes of output, the additional output MUST NOT be used for other cryptographic purposes unless explicitly specified; implementations SHOULD consume only the 48 bytes required by this construction for these keys and derive any additional per‑session values (e.g., Fixed\_Nonce\_Prefix) from the same KDF in a deterministic, documented manner.

# Nonce Construction and Usage

Nonce construction:

Nonce = Fixed\_Nonce\_Prefix || Block\_Counter

where:

* **Fixed\_Nonce\_Prefix** is 12 bytes (96 bits) and is constant for the lifetime of the keying interval and per direction.
* **Block\_Counter** is 4 bytes (32 bits) and is derived from the SSH packet sequence number as specified below.

Byte order and placement

The ChaCha20 nonce input MUST be formed by placing Fixed\_Nonce\_Prefix as the high‑order 12 bytes followed by the 4‑byte Block\_Counter in little‑endian form if the underlying ChaCha20 implementation expects the RFC 7539 96‑bit nonce followed by a 32‑bit block counter internally. Implementations MUST ensure that the ordering of bytes matches the ChaCha20 input format required by the implementation library to prevent cross‑implementation mismatches. For clarity, the effective 128‑bit ChaCha20 input state comprises:

* ChaCha20 32‑bit block counter (least significant 32 bits) = **Block\_Counter**
* ChaCha20 96‑bit nonce (most significant 96 bits) = **Fixed\_Nonce\_Prefix**

## Block\_Counter derivation

The Block\_Counter for packet with SSH sequence number S (where S is a 32‑bit unsigned integer that increments by 1 for each transported SSH packet, as per SSH) is defined as:

Block\_Counter = S

Implementations MUST treat S strictly as an internal ChaCha20 block counter and MUST NOT use S alone as the nonce for any other primitive or in any manner that may cause reuse across keying intervals. Because Block\_Counter is only 32 bits, single keying intervals MUST enforce limits on the number of packets to avoid block counter wraparound.

## Fixed\_Nonce\_Prefix derivation

Fixed\_Nonce\_Prefix MUST be derived from the SSH KEX output and session identifier using the KDF in a way that ensures uniqueness per direction and per keying interval. An example derivation (implementations MAY use equivalent derivations produced by the KDF specified by the negotiated KEX) is:

* Fixed\_Nonce\_Prefix := KDF(session\_id, "chacha20-poly1305-nonce", direction\_identifier) where direction\_identifier is 'C' for client→server and 'S' for server→client, and the KDF returns 12 bytes.

Implementations MUST document the exact KDF label and method used to derive Fixed\_Nonce\_Prefix.

## Constraints and rationale

Using a fixed per‑direction per‑keying\_interval prefix prevents an attacker who can manipulate sequence number semantics from causing nonce reuse across keying intervals or sessions. Because the Block\_Counter is used only as the per‑packet ChaCha20 block counter, any attacker who attempts to replay or reorder packets without matching Fixed\_Nonce\_Prefix will induce decryption failures.

# Poly1305 Key Derivation (MAC Key Stream)

Poly1305 requires a 32‑byte one‑time key per **RFC 7539**, consisting of 16 bytes r (with specific bit clamping) followed by 16 bytes s. The one‑time Poly1305 key used to authenticate packets during a keying interval MUST be derived using K\_E, the Fixed\_Nonce\_Prefix, and a zero Block\_Counter as follows.

Derivation steps:

| Step | Operation |
| :--- | :--- |
| 1 | Construct a 12‑byte Nonce\_Derivation\_N once: Nonce\_Derivation = Fixed\_Nonce\_Prefix || 0x00000000 |
| 2 | Initialize ChaCha20 with Key = K\_E and Nonce = Nonce\_Derivation; set ChaCha20 internal block counter to 0 as per RFC 7539 semantics for key stream extraction. |
| 3 | Generate the first 64 bytes of the ChaCha20 stream (or at minimum the first 32 bytes required). |
| 4 | Take the first 32 bytes of the keystream; interpret them as 32 octets k0..k31 in little‑endian order to form the Poly1305 key **K\_poly** = k0||k1||...||k31. |
| 5 | Apply Poly1305 r masking: mask the appropriate bits of the first 16 octets (r) as per RFC 7539 (clear bits 0..3 of byte 3, bits 4..7 of bytes 7, 11, and 15 as required by Poly1305 specification). |

Note: Implementations MUST ensure the ChaCha20 stream used for Poly1305 key derivation uses the same key K\_E and the same Fixed\_Nonce\_Prefix as used for packet encryption, with Block\_Counter set to zero for this derivation. The use of a zero block counter for MAC key derivation ensures the Poly1305 key is unique per keying interval and distinct from per‑packet block counters used for encryption.

## K\_MAC handling

K\_MAC (16 bytes) is NOT used directly as the final Poly1305 key. Instead, K\_MAC is reserved as a seed that is conceptually encoded into the ChaCha20 stream derivation process for additional domain separation if desired by an implementation. Implementations MAY incorporate K\_MAC into the ChaCha20 initial block (for example by XORing K\_MAC into the first 16 bytes of the key schedule or by deriving an intermediate key from K\_E and K\_MAC via the SSH KDF) only if this procedure is deterministic, documented, and ensures that the resulting Poly1305 key is unique per keying interval and per direction. The mandatory minimum is that K\_E and Fixed\_Nonce\_Prefix as described above are used to produce the Poly1305 key; any additional use of K\_MAC for domain separation MUST not violate ChaCha20 or Poly1305 assumptions and MUST be clearly specified.

Implementations MUST store the derived Poly1305 key (r||s) in memory with protections appropriate for secret key material and MUST discard the ChaCha20 keystream material after use.

## Per-packet MAC usage

The Poly1305 key derived above is used as a one‑time key per packet for the entire keying interval. Implementations MUST NOT reuse a Poly1305 key across different keying intervals. Within a single keying interval, the Poly1305 one‑time key derived via the procedure above is used to compute the Poly1305 tag for each packet's ciphertext (see Section 8). This usage model follows RFC 7539 section recommendations for AEAD construction when ChaCha20 is used to generate the Poly1305 key once per keying interval and per direction; rekeying must be enforced before the Poly1305 key is used beyond recommended limits.

## Alternative: per‑packet Poly1305 key

Implementations MAY instead choose to derive a Poly1305 key per packet by using Block\_Counter = 0 to derive r||s then incrementing the internal ChaCha20 counter for each packet key derivation; however, this approach must still ensure that Poly1305 keys are never reused and that ChaCha20 block counter consumption limits are observed. If an implementation derives a per‑packet Poly1305 key from K\_E and the Fixed\_Nonce\_Prefix with differing Block\_Counter values, those Block\_Counter values MUST not collide with those used for the packet encryption stream for the same nonce and key. Implementations choosing per‑packet Poly1305 keys MUST document the exact derivation and ensure it is secure and unambiguous.

# Packet Processing: Encryption and Authentication

This section prescribes precise packet processing steps to produce the on‑wire ciphertext and authentication tag. Packets are processed per direction using the K\_E, Fixed\_Nonce\_Prefix, and Poly1305 key derived for that direction.

Inputs:

| Name | Description |
| :--- | :--- |
| P | Plaintext packet payload as defined by SSH (Length, Padding, Payload) prior to encryption |
| S | SSH packet sequence number (32‑bit unsigned) |
| K\_E | 32‑byte ChaCha20 key for this direction |
| Fixed\_Nonce\_Prefix | 12‑byte nonce prefix for this direction |
| K\_poly | 32‑byte Poly1305 key derived per Section 7 |

Processing steps:

| Step | Operation |
| :--- | :--- |
| 1 | Compute Block\_Counter = S (as 32‑bit unsigned integer). |
| 2 | Construct Nonce = Fixed\_Nonce\_Prefix || Block\_Counter. |
| 3 | Encrypt the plaintext P using ChaCha20 with key K\_E and Nonce, using ChaCha20 as a stream cipher starting at block counter = Block\_Counter. The resulting ciphertext is C. Implementations MUST follow RFC 7539 for ChaCha20 block counter semantics. |
| 4 | Compute the Poly1305 tag T over A = empty string and the ciphertext C using the derived Poly1305 key K\_poly as: T = Poly1305(K\_poly, A || C). The authenticated data A is an empty octet string. The MAC computation MUST follow RFC 7539 and Poly1305 specification for padding and length encoding. |
| 5 | Output on the wire: C || T. The wire format MUST place the 16\_byte Poly1305 tag T immediately following the ciphertext C. |

## Notes on AAD

This construction uses an empty additional authenticated data (A = empty) in order to reduce complexity and stay consistent with RFC 7539 permitted usages. Implementations MUST ensure that any additional SSH fields that require authentication are included in either the plaintext packet P before encryption or are reflected via standard SSH transport layer validation; they MUST NOT rely on implicit inclusion of sequence numbers in AAD.

## Ordering and stream alignment

ChaCha20 encryption MUST be performed in full‑packet units using the nonce containing the packet's Block\_Counter. Implementers MUST ensure that the ChaCha20 internal counter and block generation are aligned consistently with the RFC 7539 block counter model so that the derived Poly1305 key material (generated at Block\_Counter = 0 for MAC derivation) does not overlap with blocks consumed for packet encryption.

# Packet Processing: Reception, Authentication, and Decryption

On receipt of a packet consisting of C || T, the recipient performs the following steps using the appropriate per\_direction keys and derived values.

Inputs:

| Name | Description |
| :--- | :--- |
| C | Received ciphertext |
| T | Received 16‑byte Poly1305 tag |
| S | Expected SSH packet sequence number for this packet |
| K\_E | Local 32‑byte ChaCha20 key for this direction |
| Fixed\_Nonce\_Prefix | Local 12‑byte Fixed\_Nonce\_Prefix for this direction |
| K\_poly | Poly1305 key derived per Section 7 |

Processing steps:

| Step | Operation |
| :--- | :--- |
| 1 | Compute Block\_Counter = S. |
| 2 | Construct Nonce = Fixed\_Nonce\_Prefix || Block\_Counter. |
| 3 | Compute the Poly1305 tag T' = Poly1305(K\_poly, A || C) with A = empty. If T' does not equal T, the packet MUST be treated as failed authentication; the implementation MUST follow SSH failure handling for authentication errors (terminate the connection or follow configured rekey/recovery procedures). |
| 4 | If authentication succeeds, decrypt C using ChaCha20 with K\_E and Nonce, producing plaintext P. The decrypted P is then processed as a normal SSH packet (padding validation, payload extraction, etc.). |

## Timing and constant‑time verification

Poly1305 tag comparisons MUST be performed in constant time with respect to the compared values to avoid leaking authentication failures via timing side channels. Decryption SHOULD only proceed after the authentication tag has been successfully verified.

## Replay and out‑of‑order packets

Because Block\_Counter is derived from the SSH sequence number, out‑of\_order delivery or replays will result in a Block\_Counter that does not match the receiver's expected S for the current processing position. Implementations MUST follow SSH transport layer replay window semantics and sequence number handling when deciding whether to accept out‑of\_order packets. Acceptance of out‑of\_order packets requires authentication verification using the Block\_Counter derived from the sequence number encoded in the packet context; implementations MUST ensure that sequence number handling does not permit reuse of Block\_Counter values that would cause ChaCha20 nonce reuse.

# Rekeying and Limits

ChaCha20/Poly1305 security depends on never reusing the same (key, nonce) pair and on limiting total keystream consumption under a single key. Implementations MUST enforce limits and rekeying policies as follows.

| Requirement | Value / Action |
| :--- | :--- |
| Maximum packets per keying interval | Rekey before **2^32** packets would be sent with the same Fixed\_Nonce\_Prefix and K\_E in a single direction (practical limit: rekey well before sequence number approaches **2^32 - 1**). |
| Maximum ChaCha20 blocks per packet | A single packet encryption may consume multiple 64‑byte ChaCha20 blocks; implementations MUST account for blocks consumed when tracking total blocks used. |
| Keystream block usage limit | Rekey before more than **2^32 - 1** ChaCha20 blocks have been generated under a single K\_E/Fixed\_Nonce\_Prefix pair. |
| Poly1305 tag reuse protection | Because Poly1305 is used with a key derived per keying interval, implementations MUST ensure the Poly1305 key is never reused across different keying intervals. Rekeying resets the Poly1305 key. |
| Rekey trigger recommendations | Implementations SHOULD trigger rekeying based on whichever comes first: number of packets (e.g., **2^31** packets), number of bytes (e.g., **2^40** bytes), elapsed time (e.g., 1 hour), or explicit administrative policy. These thresholds are implementation choices but MUST be conservative relative to the theoretical limits above. |

## Rationale and examples

Because Block\_Counter is the 32‑bit packet sequence number, a naïve policy that allows sequence number wraparound would permit reuse of Block\_Counter values with the same Fixed\_Nonce\_Prefix and K\_E, producing identical ChaCha20 nonces and catastrophic keystream reuse. To avoid this, implementations MUST ensure that rekeying occurs prior to any possibility of Block\_Counter reuse under the same K\_E/Fixed\_Nonce\_Prefix. A conservative policy is to rekey when S approaches **2^31** packets or earlier.

When counting ChaCha20 block usage, consider that each 64‑byte ChaCha20 block corresponds to one increment of the internal block counter; a packet of size N bytes (ciphertext) consumes `ceil(N / 64)` blocks. Implementations MUST track total blocks generated for both packet encryption and for any ChaCha20 usage for Poly1305 key derivation or other permitted uses, and MUST rekey before the total approaches **2^32**.

# Interoperability and Versioning

Negotiation and algorithm name

This AEAD construction MUST be exposed through SSH algorithm negotiation. Implementations SHOULD introduce a clear algorithm identifier in the SSH Transport Layer encryption algorithm list. Example algorithm name (implementations may select an appropriate IANA‑registered name):

| Algorithm identifier | Description |
| :--- | :--- |
| chacha20-poly1305-fixedprefix-00@scssh.github.io | ChaCha20 (256‑bit) with Poly1305, Fixed Nonce Prefix derived from KEX; Block\_Counter = packet sequence number (32‑bit). |

## Negotiation behavior

When negotiating ciphersuites, implementations MUST follow SSH Algorithm Negotiation rules. If the peer does not support the fixed‑prefix variant, implementations MAY fall back to existing, agreed algorithms. Implementations MUST document differences from other chacha20‑poly1305 variants (for example RFC 8439 style AEAD where per‑packet nonces are constructed differently).

## Compatibility notes

Because Fixed\_Nonce\_Prefix derivation and the exact ordering of bytes in the ChaCha20 input can vary between implementations, implementers MUST clearly document:

| Item | MUST document |
| :--- | :--- |
| Fixed\_Nonce\_Prefix derivation label and KDF inputs | The exact KDF label, inputs, and byte length used |
| Endianness and byte ordering for Block\_Counter in nonce | Whether Block\_Counter is placed in little‑endian or network order in the ChaCha20 counter field |
| Poly1305 key derivation details | Which ChaCha20 blocks were used, and whether K\_MAC is mixed into derivation |

## Interoperability testing

Implementations SHOULD provide test vectors (see Appendix A) covering key derivation, fixed nonce prefix derivation, Poly1305 key generation, encryption of simple packets, and tag verification to facilitate interoperability testing.

# Security Considerations

## Nonce misuse and reuse

The central risk for ChaCha20 is reuse of the same (**K\_E**, **Nonce**) pair. This design prevents cross‑keying\_interval reuse by binding Fixed\_Nonce\_Prefix to the KEX and by mandating rekeying before Block\_Counter wraparound. Implementers MUST ensure that Fixed\_Nonce\_Prefix is unique per direction and per keying interval and that rekeying is enforced well before any 32‑bit counter wrap.

## Poly1305 considerations

Poly1305 must never be used with the same one‑time key more than once. This specification makes the Poly1305 key unique per keying interval. Implementations MUST not reuse Poly1305 keys across keying intervals, and MUST not derive per‑packet Poly1305 keys in a manner that collides with ChaCha20 stream blocks used for encryption.

## Side channels and constant‑time operations

Compare authentication tags using **constant‑time comparison routines**. Protect key material in memory (zeroize on key retirement) and follow platform best practices to mitigate side channels. Keep ChaCha20 and Poly1305 implementations free of data‑dependent branches on secret values.

## Replay, reordering, and sequence number handling

Because Block\_Counter is tied to the SSH sequence number, replayed or reordered packets may produce Block\_Counter values that the receiver considers out of window. Implementations MUST enforce **replay protection** consistent with SSH Transport semantics. Acceptance of out‑of\_order packets requires careful handling to prevent nonce reuse; do not accept packets that would cause reuse of a Block\_Counter value already consumed under the same **K\_E/Fixed\_Nonce\_Prefix**.

## KDF and key derivation integrity

Fixed\_Nonce\_Prefix must be derived in a way that ensures uniqueness and unpredictability across sessions. Use the SSH‑specified KDF or an equivalent deterministic KDF with documented labels and inputs. Do not derive Fixed\_Nonce\_Prefix from values that an attacker could influence.

## Denial‑of‑service considerations

Because authentication must be verified before decryption, malformed or adversarial packets will be rejected early. Implementations should rate‑limit expensive cryptographic operations if operating in environments subject to amplification DoS attacks.

# IANA Considerations

This document requests no IANA actions. Implementations planning to register a distinct algorithm identifier for this construction SHOULD follow IANA registration procedures for SSH algorithm names and document the identifier, semantics, and any required test vectors.

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
