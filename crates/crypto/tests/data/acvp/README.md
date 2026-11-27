<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# NIST ACVP vectors for ML-KEM-768 and ML-DSA-65

*2026-11-26. The known-answer vectors of [ADR 0069](../../../../../docs/decisions/0069-cryptography-libraries.md), rule 7, for ML-KEM-768 (FIPS 203) and ML-DSA-65 (FIPS 204).*

Source: the National Institute of Standards and Technology (NIST).

## Where they come from

The files are cut down from NIST's Automated Cryptographic Validation Protocol server, `https://github.com/usnistgov/ACVP-Server`, at commit `975de31eb83d87039ec88934fdc47d8c312b892d` (2026-08-12). Each is a `gen-val/json-files/<set>/internalProjection.json`:

| File | Set | SHA-256 of the source file |
|---|---|---|
| `ml-kem-768-keygen.json` | `ML-KEM-keyGen-FIPS203` | `d7a62a2c3476957f56dd8d24f9004ea6776ccfe995ffe71a65bb9506dc9c7b1b` |
| `ml-kem-768-encapdecap.json` | `ML-KEM-encapDecap-FIPS203` | `a556952ce869bb89c3a3196a701dad89647c193a34c86eafb61a9d710d5b810f` |
| `ml-dsa-65-keygen.json` | `ML-DSA-keyGen-FIPS204` | `e67ee6540d40e11506c3c4e3b1f79fc1cefcd49820db99fc61f87cc8ba463baf` |
| `ml-dsa-65-siggen.json` | `ML-DSA-sigGen-FIPS204` | `72dcaf5f69853ca267ccd16af9cb40949786aca0fcfbf05d1ebeba132b93af22` |
| `ml-dsa-65-sigver.json` | `ML-DSA-sigVer-FIPS204` | `47cdd6314c7f746d02421ffcba89d4dbc7bb875ac49e07a029fdfc26fba55437` |

## What was changed

Changed by the ASPIS project on 2026-11-26: test groups and tests were removed, so the tests run in seconds. The schema, and every group and test kept, are unchanged. These are kept:

- **ML-KEM keyGen:** group 2 (ML-KEM-768), tests 26 to 30.
- **ML-KEM encapDecap:** group 2 (encapsulation), tests 26 to 30; group 5 (decapsulation), all ten, five with modified ciphertexts; group 10 (encapsulation key check), all ten, five of which fail the modulus check.
- **ML-DSA keyGen:** group 2 (ML-DSA-65), tests 26 to 30.
- **ML-DSA sigGen:** group 3 (deterministic, external interface, pure), tests 31 to 35; group 15 (hedged, with `rnd`, external interface, pure), tests 211 to 215.
- **ML-DSA sigVer:** group 3 (external interface, pure), all fifteen. Three verify; the rest have a modified z, hint, commitment or message.

## License

The files are under the NIST Software License (`NIST-Software`, in `LICENSES/NIST-Software.txt`), as the repository's README states it. Its notice, kept intact as the license asks:

> NIST-developed software is provided by NIST as a public service. You may use, copy, and distribute copies of the software in any medium, provided that you keep intact this entire notice. You may improve, modify, and create derivative works of the software or any portion of the software, and you may copy and distribute such modifications or works. Modified works should carry a notice stating that you changed the software and should note the date and nature of any such change. Please explicitly acknowledge the National Institute of Standards and Technology as the source of the software.
>
> NIST-developed software is expressly provided "AS IS." NIST MAKES NO WARRANTY OF ANY KIND, EXPRESS, IMPLIED, IN FACT, OR ARISING BY OPERATION OF LAW, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTY OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, NON-INFRINGEMENT, AND DATA ACCURACY. NIST NEITHER REPRESENTS NOR WARRANTS THAT THE OPERATION OF THE SOFTWARE WILL BE UNINTERRUPTED OR ERROR-FREE, OR THAT ANY DEFECTS WILL BE CORRECTED. NIST DOES NOT WARRANT OR MAKE ANY REPRESENTATIONS REGARDING THE USE OF THE SOFTWARE OR THE RESULTS THEREOF, INCLUDING BUT NOT LIMITED TO THE CORRECTNESS, ACCURACY, RELIABILITY, OR USEFULNESS OF THE SOFTWARE.
>
> You are solely responsible for determining the appropriateness of using and distributing the software and you assume all risks associated with its use, including but not limited to the risks and costs of program errors, compliance with applicable laws, damage to or loss of data, programs or equipment, and the unavailability or interruption of operation. This software is not intended to be used in any situation where a failure could cause risk of injury or damage to property. The software developed by NIST employees is not subject to copyright protection within the United States.
