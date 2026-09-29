use libcrux_hmac::{
    HmacSha256, HmacSha384, HmacSha3_224, HmacSha3_256, HmacSha3_384, HmacSha3_512, HmacSha512,
    HmacState,
};
use libcrux_kats::acvp::kbkdf::{
    schema::{KbkdfPrompt, KbkdfResult},
    FeedbackHmacTests,
};
use nist_kdf::feedback;

fn check<const OUTLEN: usize, H: HmacState<OUTLEN>>(test: &KbkdfPrompt, expected: &KbkdfResult) {
    let mut k_out = vec![0; expected.keyOut.len()];
    feedback::kdf::<OUTLEN, H>(&mut k_out, &test.keyIn, &test.iv, &[&expected.fixedData]).unwrap();
    assert_eq!(k_out, expected.keyOut, "tcId {}", test.tcId);
}

#[test]
fn feedback_hmac() {
    let FeedbackHmacTests { prompts, results } = FeedbackHmacTests::load();
    assert_eq!(prompts.algorithm, "KDF");
    assert_eq!(results.algorithm, "KDF");

    let mut tested = 0;
    for group in prompts.testGroups {
        assert_eq!(group.testType, "AFT");
        assert_eq!(group.kdfMode, "feedback");
        assert_eq!(group.counterLength, 32);
        assert_eq!(group.counterLocation, "before fixed data");

        // The KDF only outputs whole bytes.
        if group.keyOutLength % 8 != 0 {
            continue;
        }

        let check = match group.macMode.as_str() {
            "HMAC-SHA2-256" => check::<32, HmacSha256>,
            "HMAC-SHA2-384" => check::<48, HmacSha384>,
            "HMAC-SHA2-512" => check::<64, HmacSha512>,
            "HMAC-SHA3-224" => check::<28, HmacSha3_224>,
            "HMAC-SHA3-256" => check::<32, HmacSha3_256>,
            "HMAC-SHA3-384" => check::<48, HmacSha3_384>,
            "HMAC-SHA3-512" => check::<64, HmacSha3_512>,
            // Not supported by libcrux-hmac.
            "HMAC-SHA-1" | "HMAC-SHA2-224" | "HMAC-SHA2-512/224" | "HMAC-SHA2-512/256" => continue,
            mac => panic!("unexpected macMode {mac}"),
        };

        for test in &group.tests {
            let expected = results.find_expected_result(group.tgId, test.tcId);
            assert_eq!(expected.keyOut.len() * 8, group.keyOutLength);
            assert_eq!(test.iv.is_empty(), group.zeroLengthIv);
            check(test, expected);
            tested += 1;
        }
    }
    // Guard against silently skipping all tests.
    assert_eq!(tested, 100);
}
