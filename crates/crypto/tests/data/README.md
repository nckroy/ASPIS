<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# aspis-crypto's known-answer vectors

*2026-11-26. The vectors of [ADR 0069](../../../../docs/decisions/0069-cryptography-libraries.md), rule 7, and where each comes from.*

Each file here holds test vectors copied from a standard. The values are unchanged. They are written as lowercase hex, without the spaces and line breaks of the source. RFC 10073's Appendix E is the exception: it is JSON with base64 values, kept as published without its line breaks. Each file keeps its source's notice ([0033](../../../../docs/decisions/0033-contributions-docs-license-and-notice-years.md), rule 3), recorded in `REUSE.toml`, and its source's legends are repeated below.

The files share one shape, close to NIST ACVP's: `{"source": "...", "tests": [{"tcId": "...", ...}]}`. Each field takes the RFC's own name. `rfc10073.json` keeps its two appendices apart, and `rfc9001.json` adds two fields beside its tests, as described below.

The tests read the files with the JSON reader in `../common/json.rs`.

Some vectors aren't kept here:

- The FIPS 180-4 and FIPS 202 examples are constants in `../hash.rs`. They are works of the US government, with no notice.
- The GCM specification's test cases are constants in `../aead.rs`. The specification states no license or notice.
- FIPS 197's AES example vectors are constants in `../quic.rs`. They are a work of the US government, with no notice.

## `rfc4231.json`: HMAC-SHA-256, -384 and -512

- **Source:** RFC 4231, "Identifiers and Test Vectors for HMAC-SHA-224, HMAC-SHA-256, HMAC-SHA-384, and HMAC-SHA-512", M. Nystrom, December 2005, section 4, test cases 1 to 7. The HMAC-SHA-224 values are left out. The RFC says: "The test vectors provided in this document may be used for conformance testing."
- **Kept as published:** test case 5 gives only the first 128 bits of each tag, and the file marks it with `"truncatedTo": 16`.
- **License:** `LicenseRef-IETF-BCP78`. The RFC predates the IETF Trust's Legal Provisions.
- **The RFC's notice:**

  > Copyright (C) The Internet Society (2005).
  >
  > This document is subject to the rights, licenses and restrictions contained in BCP 78, and except as set forth therein, the authors retain all their rights.
  >
  > This document and the information contained herein are provided on an "AS IS" basis and THE CONTRIBUTOR, THE ORGANIZATION HE/SHE REPRESENTS OR IS SPONSORED BY (IF ANY), THE INTERNET SOCIETY AND THE INTERNET ENGINEERING TASK FORCE DISCLAIM ALL WARRANTIES, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO ANY WARRANTY THAT THE USE OF THE INFORMATION HEREIN WILL NOT INFRINGE ANY RIGHTS OR ANY IMPLIED WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.

## `rfc5869.json`: HKDF-SHA-256

- **Source:** RFC 5869, "HMAC-based Extract-and-Expand Key Derivation Function (HKDF)", H. Krawczyk and P. Eronen, May 2010, an IETF Stream document, Appendix A.1 to A.3. Test cases 4 to 7 use SHA-1 and are left out.
- **License:** `BSD-3-Clause`. The vectors are Code Components ("tables of values", in the IETF Trust's list), under the Revised BSD License of the Legal Provisions, Section 4. The RFC calls it the "Simplified BSD License"; the Trust corrected that name on 2021-09-21, and says the license text was always the Revised BSD License.
- **The RFC's notice:**

  > Copyright (c) 2010 IETF Trust and the persons identified as the document authors. All rights reserved.
  >
  > This document is subject to BCP 78 and the IETF Trust's Legal Provisions Relating to IETF Documents (http://trustee.ietf.org/license-info) in effect on the date of publication of this document. Please review these documents carefully, as they describe your rights and restrictions with respect to this document. Code Components extracted from this document must include Simplified BSD License text as described in Section 4.e of the Trust Legal Provisions and are provided without warranty as described in the Simplified BSD License.

## `rfc8439.json`: ChaCha20-Poly1305

- **Source:** RFC 8439, "ChaCha20 and Poly1305 for IETF Protocols", Y. Nir and A. Langley, June 2018, an IRTF Stream document: section 2.8.2 (the AEAD test vector) and Appendix A.5 (the decryption example). The nonce of section 2.8.2 is its 32-bit fixed-common part followed by its IV.
- **License:** `LicenseRef-IETF-BCP78`. The Legal Provisions' Code Components license doesn't apply to the IRTF Stream (Section 8.g). For the IRTF Stream, Section 8.c.iii lifts the IETF Standards Process limit from Section 3.a's grant, which covers copying in whole or in part, and says Section 3.c doesn't apply.
- **The RFC's notice:**

  > Copyright (c) 2018 IETF Trust and the persons identified as the document authors. All rights reserved.
  >
  > This document is subject to BCP 78 and the IETF Trust's Legal Provisions Relating to IETF Documents (https://trustee.ietf.org/license-info) in effect on the date of publication of this document. Please review these documents carefully, as they describe your rights and restrictions with respect to this document.

## `rfc7748.json`: X25519

- **Source:** RFC 7748, "Elliptic Curves for Security", A. Langley, M. Hamburg and S. Turner, January 2016, an IRTF Stream document: section 5.2 (the two X25519 test vectors, and the iterated results after one, 1,000 and 1,000,000 iterations) and section 6.1 (the Diffie-Hellman test vector). The X448 values are left out.
- **Not run per change:** the result after 1,000,000 iterations is kept, but the tests run only the first two counts, which take a fraction of a second.
- **License:** `LicenseRef-IETF-BCP78`, as for RFC 8439.
- **The RFC's notice:**

  > Copyright (c) 2016 IETF Trust and the persons identified as the document authors. All rights reserved.
  >
  > This document is subject to BCP 78 and the IETF Trust's Legal Provisions Relating to IETF Documents (http://trustee.ietf.org/license-info) in effect on the date of publication of this document. Please review these documents carefully, as they describe your rights and restrictions with respect to this document.

## `rfc8032.json`: Ed25519

- **Source:** RFC 8032, "Edwards-Curve Digital Signature Algorithm (EdDSA)", S. Josefsson and I. Liusvaara, January 2017, an IRTF Stream document, section 7.1: TEST 1, 2, 3, 1024 and SHA(abc). The RFC's `SECRET KEY` is the 32-octet seed of section 5.1.5.
- **License:** `LicenseRef-IETF-BCP78`, as for RFC 8439.
- **The RFC's notice:**

  > Copyright (c) 2017 IETF Trust and the persons identified as the document authors. All rights reserved.
  >
  > This document is subject to BCP 78 and the IETF Trust's Legal Provisions Relating to IETF Documents (http://trustee.ietf.org/license-info) in effect on the date of publication of this document. Please review these documents carefully, as they describe your rights and restrictions with respect to this document.

## `rfc10073.json`: the composite `id-MLDSA65-Ed25519-SHA512`

- **Source:** RFC 10073, "Composite Module-Lattice-Based Digital Signature Algorithm (ML-DSA) for Use in X.509 Public Key Infrastructure", M. Ounsworth, J. Gray, M. Pala, J. Klaußner and S. Fluhrer, November 2026, an IETF Stream document.
  - `appendixD`: Appendix D's two message-representative examples, which are for `id-MLDSA65-ECDSA-P256-SHA512`. The tests use their pre-hash and the layout after the label. Values are hex, as the RFC prints them.
  - `appendixE`: Appendix E's message `m` and context `ctx`, and the one test object whose `tcId` is `id-MLDSA65-Ed25519-SHA512`, with every field as published, in base64: `pk`, `x5c`, `sk`, `sk_pkcs8`, `s` and `sWithContext`. The other algorithms' objects are left out. `x5c` and `sk_pkcs8` are kept for C28.
- **License:** `BSD-3-Clause`. Appendix E is JSON, and Appendix D's examples are tables of values, both Code Components in the IETF Trust's list, under the Revised BSD License of the Legal Provisions, Section 4.
- **The RFC's notice:**

  > Copyright (c) 2026 IETF Trust and the persons identified as the document authors. All rights reserved.
  >
  > This document is subject to BCP 78 and the IETF Trust's Legal Provisions Relating to IETF Documents (https://trustee.ietf.org/license-info) in effect on the date of publication of this document. Please review these documents carefully, as they describe your rights and restrictions with respect to this document. Code Components extracted from this document must include Revised BSD License text as described in Section 4.e of the Trust Legal Provisions and are provided without warranty as described in the Revised BSD License.

## `rfc9001.json`: QUIC's packet protection

- **Source:** RFC 9001, "Using TLS to Secure QUIC", M. Thomson and S. Turner, May 2021, an IETF Stream document.
  - `initialSalt`: section 5.2's salt for QUIC v1's initial secret.
  - `hkdfLabels`: Appendix A.1's HkdfLabel values.
  - `tests`: Appendix A.1's keys with A.2 (the client's Initial packet) and A.3 (the server's), A.4 (the Retry packet) with section 5.8's secret, key and nonce, and A.5 (the ChaCha20-Poly1305 short-header packet).
- **Kept as published:** A.2 gives the CRYPTO frame alone, "plus enough PADDING frames to make a 1162-byte payload". The file keeps the frame as `cryptoFrame` and the length as `payloadLength`, and the tests pad with zero octets, which are PADDING frames. The Destination Connection ID (`dcid` and `odcid`) and the packet numbers are copied from the RFC's text.
- **License:** `BSD-3-Clause`. The vectors are Code Components ("tables of values"), under the Revised BSD License of the Legal Provisions, Section 4, as for RFC 5869.
- **The RFC's notice:**

  > Copyright (c) 2021 IETF Trust and the persons identified as the document authors. All rights reserved.
  >
  > This document is subject to BCP 78 and the IETF Trust's Legal Provisions Relating to IETF Documents (https://trustee.ietf.org/license-info) in effect on the date of publication of this document. Please review these documents carefully, as they describe your rights and restrictions with respect to this document. Code Components extracted from this document must include Simplified BSD License text as described in Section 4.e of the Trust Legal Provisions and are provided without warranty as described in the Simplified BSD License.

## `acvp/`: ML-KEM-768 and ML-DSA-65

NIST's ACVP vectors, under the NIST Software License. [acvp/README.md](acvp/README.md) names their source and what was changed.
