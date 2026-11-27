// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Known answers for the hashes (ADR 0069, rule 7): the examples NIST
//! publishes for FIPS 180-4 and FIPS 202, at
//! <https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values>
//! ("SHA256.pdf", "SHA384.pdf", "SHA512.pdf", "SHA3-256_Msg0.pdf",
//! "SHA3-256_1600.pdf", "SHAKE256_Msg0.pdf" and "SHAKE256_Msg1600.pdf").
//! They are works of the US government and carry no notice. FIPS 202's 5-
//! and 30-bit messages are left out, since the API takes octets.

mod common;

use aspis_crypto::hash::{
    Sha3_256, Sha256, Sha384, Sha512, Shake256, sha3_256, sha256, sha384, sha512, shake256,
};
use common::{Value, hex};

/// FIPS 180-4's one-block message.
const ABC: &[u8] = b"abc";
/// FIPS 180-4's 448-bit, two-block message for SHA-256.
const MSG_448: &[u8] = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
/// FIPS 180-4's 896-bit message for SHA-384 and SHA-512.
const MSG_896: &[u8] = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn\
hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";

/// FIPS 202's 1600-bit message: 200 octets of 0xA3.
fn msg_1600() -> Vec<u8> {
    vec![0xA3; 200]
}

#[test]
fn fips180_4_sha256() {
    let cases: [(&[u8], &str); 2] = [
        (
            ABC,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
        (
            MSG_448,
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        ),
    ];
    for (m, d) in cases {
        assert_eq!(sha256(m).to_vec(), hex(d));
    }
}

#[test]
fn fips180_4_sha384() {
    let cases: [(&[u8], &str); 2] = [
        (
            ABC,
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed\
             8086072ba1e7cc2358baeca134c825a7",
        ),
        (
            MSG_896,
            "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712\
             fcc7c71a557e2db966c3e9fa91746039",
        ),
    ];
    for (m, d) in cases {
        assert_eq!(sha384(m).to_vec(), hex(d));
    }
}

#[test]
fn fips180_4_sha512() {
    let cases: [(&[u8], &str); 2] = [
        (
            ABC,
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        ),
        (
            MSG_896,
            "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018\
             501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
        ),
    ];
    for (m, d) in cases {
        assert_eq!(sha512(m).to_vec(), hex(d));
    }
}

#[test]
fn fips202_sha3_256() {
    assert_eq!(
        sha3_256(b"").to_vec(),
        hex("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a")
    );
    assert_eq!(
        sha3_256(&msg_1600()).to_vec(),
        hex("79f38adec5c20307a98ef76e8324afbfd46cfd81b22e3973c65fa1bd9de31787")
    );
}

/// SHAKE256 of the empty message, 4096 bits out (SHAKE256_Msg0.pdf).
const SHAKE256_MSG0: &str = "\
46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f\
d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be\
141e96616fb13957692cc7edd0b45ae3dc07223c8e92937bef84bc0eab862853\
349ec75546f58fb7c2775c38462c5010d846c185c15111e595522a6bcd16cf86\
f3d122109e3b1fdd943b6aec468a2d621a7c06c6a957c62b54dafc3be87567d6\
77231395f6147293b68ceab7a9e0c58d864e8efde4e1b9a46cbe854713672f5c\
aaae314ed9083dab4b099f8e300f01b8650f1f4b1d8fcf3f3cb53fb8e9eb2ea2\
03bdc970f50ae55428a91f7f53ac266b28419c3778a15fd248d339ede785fb7f\
5a1aaa96d313eacc890936c173cdcd0fab882c45755feb3aed96d477ff96390b\
f9a66d1368b208e21f7c10d04a3dbd4e360633e5db4b602601c14cea737db3dc\
f722632cc77851cbdde2aaf0a33a07b373445df490cc8fc1e4160ff118378f11\
f0477de055a81a9eda57a4a2cfb0c83929d310912f729ec6cfa36c6ac6a75837\
143045d791cc85eff5b21932f23861bcf23a52b5da67eaf7baae0f5fb1369db7\
8f3ac45f8c4ac5671d85735cdddb09d2b1e34a1fc066ff4a162cb263d6541274\
ae2fcc865f618abe27c124cd8b074ccd516301b91875824d09958f341ef274bd\
ab0bae316339894304e35877b0c28a9b1fd166c796b9cc258a064a8f57e27f2a";

/// SHAKE256 of 1600 bits of 0xA3, 4096 bits out (SHAKE256_Msg1600.pdf).
const SHAKE256_MSG1600: &str = "\
cd8a920ed141aa0407a22d59288652e9d9f1a7ee0c1e7c1ca699424da84a904d\
2d700caae7396ece96604440577da4f3aa22aeb8857f961c4cd8e06f0ae6610b\
1048a7f64e1074cd629e85ad7566048efc4fb500b486a3309a8f26724c0ed628\
001a1099422468de726f1061d99eb9e93604d5aa7467d4b1bd6484582a384317\
d7f47d750b8f5499512bb85a226c4243556e696f6bd072c5aa2d9b69730244b5\
6853d16970ad817e213e470618178001c9fb56c54fefa5fee67d2da524bb3b0b\
61ef0e9114a92cdbb6cccb98615cfe76e3510dd88d1cc28ff99287512f24bfaf\
a1a76877b6f37198e3a641c68a7c42d45fa7acc10dae5f3cefb7b735f12d4e58\
9f7a456e78c0f5e4c4471fffa5e4fa0514ae974d8c2648513b5db494cea84715\
6d277ad0e141c24c7839064cd08851bc2e7ca109fd4e251c35bb0a04fb05b364\
ff8c4d8b59bc303e25328c09a882e952518e1a8ae0ff265d61c465896973d749\
0499dc639fb8502b39456791b1b6ec5bcc5d9ac36a6df622a070d43fed781f5f\
149f7b62675e7d1a4d6dec48c1c7164586eae06a51208c0b791244d307726505\
c3ad4b26b6822377257aa152037560a739714a3ca79bd605547c9b78dd1f596f\
2d4f1791bc689a0e9b799a37339c04275733740143ef5d2b58b96a363d4e0807\
6a1a9d7846436e4dca5728b6f760eef0ca92bf0be5615e96959d767197a0beeb";

#[test]
fn fips202_shake256() {
    for (m, expect) in [(Vec::new(), SHAKE256_MSG0), (msg_1600(), SHAKE256_MSG1600)] {
        let expect = hex(expect);
        assert_eq!(expect.len(), 512);
        let mut out = [0u8; 512];
        shake256(&m, &mut out);
        assert_eq!(out.to_vec(), expect);

        // Read in uneven pieces, the reader gives the same octets.
        let mut h = Shake256::new();
        h.update(&m);
        let mut r = h.finalize_xof();
        let mut pieced = Vec::new();
        for n in [1usize, 0, 7, 136, 135, 2, 200, 31] {
            let mut buf = vec![0u8; n];
            r.read(&mut buf);
            pieced.extend_from_slice(&buf);
        }
        assert_eq!(pieced.len(), 512);
        assert_eq!(pieced, expect);
    }
}

/// Every split of a message between two `update` calls gives the one-shot
/// digest, for each hash, and a cloned state forks the transcript.
#[test]
fn incremental_matches_one_shot() {
    let m = msg_1600();
    for split in 0..=m.len() {
        let (a, b) = m.split_at(split);

        let mut h = Sha3_256::new();
        h.update(a);
        let fork = h.clone();
        h.update(b);
        assert_eq!(h.finalize(), sha3_256(&m));
        assert_eq!(fork.finalize(), sha3_256(a));

        let mut h = Sha256::new();
        h.update(a);
        h.update(b);
        assert_eq!(h.finalize(), sha256(&m));

        let mut h = Sha384::new();
        h.update(a);
        h.update(b);
        assert_eq!(h.finalize(), sha384(&m));

        let mut h = Sha512::new();
        h.update(a);
        let fork = h.clone();
        h.update(b);
        assert_eq!(h.finalize(), sha512(&m));
        assert_eq!(fork.finalize(), sha512(a));

        let mut h = Shake256::new();
        h.update(a);
        h.update(b);
        let mut out = [0u8; 64];
        h.finalize_xof().read(&mut out);
        let mut whole = [0u8; 64];
        shake256(&m, &mut whole);
        assert_eq!(out, whole);
    }
}

/// The JSON reader the vector files use reads what they hold.
#[test]
fn json_reader() {
    let v = common::vectors(
        r#" {"source": "tést \"q\" \\ \/ \n", "n": 42, "ok": true,
             "no": false, "z": null, "tests": [ {"tcId": 1, "k": "0aFf"}, [] , {} ],
             "pair": "😀"} "#,
    );
    assert_eq!(v.get("source").as_str(), "tést \"q\" \\ / \n");
    assert_eq!(v.get("n").as_u64(), 42);
    assert!(v.get("ok").as_bool());
    assert!(!v.get("no").as_bool());
    assert_eq!(v.get("z"), &Value::Null);
    let tests = v.get("tests").as_array();
    assert_eq!(tests.len(), 3);
    assert_eq!(tests[0].get("tcId").as_u64(), 1);
    assert_eq!(common::field(&tests[0], "k"), [0x0a, 0xff]);
    assert_eq!(tests[1], Value::Array(Vec::new()));
    assert_eq!(tests[2], Value::Object(Vec::new()));
    assert!(tests[0].try_get("missing").is_none());
    assert_eq!(v.get("pair").as_str(), "\u{1f600}");
    assert_eq!(common::base64("aGVsbG8="), b"hello");
    assert_eq!(common::base64("aGVsbG8h"), b"hello!");
    assert_eq!(common::to_hex(&[0, 0xab]), "00ab");
}
