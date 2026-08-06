use libcrux_kats::wycheproof::{ecdh, TestResult};

fn pad_slice_to_arr(b: &[u8]) -> [u8; 48] {
    let mut out = [0u8; 48];
    out[48 - b.len()..].copy_from_slice(b);
    out
}

#[test]
fn ecdh_secp384r1() {
    let test_set = ecdh::TestSet::load_secp384r1_ecpoint();
    let mut tests_run = 0;

    for test_group in test_set.test_groups {
        for test in &test_group.tests {
            // The ecpoint format gives us sec 1 encoded public keys as hex strings and private keys
            // encoded as hex formatted big integers

            // strip leading 0 bytes
            let sk = test
                .private_key
                .iter()
                .position(|b| *b != 0)
                .map_or(test.private_key.as_slice(), |pos| &test.private_key[pos..]);

            assert!(
                sk.len() <= 48,
                "0 prefix stripped sk is larger than 48 bytes, tc_id: {}",
                test.tc_id
            );

            // sk is a 48-byte big endian big integer, so we pad the lower bytes with 0
            let sk_bytes = pad_slice_to_arr(sk);

            if test.public_key.len() == 97 {
                let decode_result = libcrux_p384::PublicKey::from_uncompressed(&test.public_key);

                if decode_result.is_err() {
                    assert_eq!(
                        TestResult::Invalid,
                        test.result,
                        "tc_id: {}, test has invalid compressed point but test result is {:?}",
                        test.tc_id,
                        test.result
                    );
                    tests_run += 1;
                    continue;
                }
            } else if test.public_key.len() == 49 {
                println!("Point decompression not yet implemented, skipping test");
                continue;
                // let valid = compressed_to_raw(&test.public_key, &mut pk_bytes);
                // if !valid {
                //     assert_eq!(
                //         TestResult::Invalid,
                //         test.result,
                //         "tc_id: {}, test has invalid compressed point but test result is {:?}",
                //         test.tc_id,
                //         test.result
                //     );
                //     tests_run += 1;
                //     continue;
                // }
            } else {
                assert_eq!(
                    TestResult::Invalid,
                    test.result,
                    "tc_id: {}, public key has invalid size {}, but test result is {:?}",
                    test.tc_id,
                    test.public_key.len(),
                    test.result
                );
                assert!(
                    test.flags.contains(&"InvalidEncoding".to_string()),
                    "tc_id: {}, public key is invalid but test does not contain InvalidEncoding flag ",
                    test.tc_id
                );
                tests_run += 1;
                continue;
            }

            let result = libcrux_p384::derive_ecdh(&sk_bytes, &test.public_key);
            match test.result {
                // XXX: In the future, wycheproof might add acceptable test cases which we (want to) reject.
                // This needs to be split then.
                TestResult::Valid | TestResult::Acceptable => {
                    assert!(
                        result.is_ok(),
                        "tc_id {}: expected success or acceptable but ECDH failed {:?}",
                        test.tc_id,
                        result
                    );
                    let result = result.unwrap();
                    assert_eq!(
                        test.shared_secret, result,
                        "tc_id {}: shared secret mismatch",
                        test.tc_id,
                    );
                }
                TestResult::Invalid => {
                    assert!(
                        result.is_err(),
                        "tc_id: {}, expected invalid test but ECDH derive succeeded",
                        test.tc_id
                    );
                }
            }
            tests_run += 1;
        }
    }

    // assert_eq!(
    //     test_set.number_of_tests, tests_run,
    //     "invalid number of tests run"
    // );
    println!(
        "Ran {tests_run} / {} ecdh_secp256r1_ecpoint tests",
        test_set.number_of_tests
    );
}

// /// A P-384 Signature
// #[derive(Clone, Default)]
// struct Signature {
//     r: [u8; 32],
//     s: [u8; 32],
// }

// /// ASN.1 DER parser for ECDSA signatures.
// /// Returns None if the signature is malformed.
// fn decode_signature(sig: &[u8]) -> Option<Signature> {
//     use der::{asn1::UintRef, Decode, Reader};
//     // Adapted from https://docs.rs/ecdsa/0.16.9/src/ecdsa/der.rs.html#357-370
//     fn decode_der_rust_crypto(der_bytes: &[u8]) -> der::Result<(UintRef<'_>, UintRef<'_>)> {
//         let mut reader = der::SliceReader::new(der_bytes)?;
//         let header = der::Header::decode(&mut reader)?;
//         header.tag().assert_eq(der::Tag::Sequence)?;

//         let (r, s) = reader.read_nested(header.length(), |reader| {
//             let r = UintRef::decode(reader)?;
//             let s = UintRef::decode(reader)?;
//             Ok::<_, der::Error>((r, s))
//         })?;
//         reader.finish()?;
//         Ok((r, s))
//     }
//     let (r, s) = decode_der_rust_crypto(sig).ok()?;
//     if r.as_bytes().len() > 32 || s.as_bytes().len() > 32 {
//         return None;
//     }
//     Some(Signature {
//         r: pad_slice_to_arr(r.as_bytes()),
//         s: pad_slice_to_arr(s.as_bytes()),
//     })
// }

// /// Generic ecdsa_secp256r1_sha test function
// ///
// /// The [`ecdsa::TestSet`] and signature verification function must correspond to each other.
// fn ecdsa_secp384r1_sha_test<F>(test_set: ecdsa::TestSet, verify: F)
// where
//     F: Fn(u32, &[u8], &[u8], &[u8], &[u8]) -> bool,
// {
//     let mut tests_run = 0;
//     let mut decoding_sig_failed = 0;

//     for test_group in test_set.test_groups {
//         let mut pk_bytes = [0; 64];
//         if test_group.key.key.len() == 65 {
//             assert!(
//                 uncompressed_to_raw(&test_group.key.key, &mut pk_bytes),
//                 "test group with invalid uncompressed public key. Key (DER): {}",
//                 test_group.public_key_der
//             );
//         } else {
//             panic!(
//                 "test group with invalid public key length. Key (DER): {}",
//                 test_group.public_key_der
//             );
//         }
//         for test in &test_group.tests {
//             let Some(sig) = decode_signature(&test.sig) else {
//                 let contains_expected_flag = test.flags.iter().any(|flag| {
//                     // Test cases with these flags can fail the decoding
//                     // Unfortunately, there are also test cases which have this flags, which **should** decode,
//                     // but then fail verification. There currently doesn't seem to be a good way to distinguish
//                     // between these.
//                     [
//                         "BerEncodedSignature",
//                         "InvalidEncoding",
//                         "MissingZero",
//                         "ModifiedSignature",
//                         "InvalidTypesInSignature",
//                         "RangeCheck",
//                         "ModifiedInteger",
//                         "IntegerOverflow",
//                         "InvalidSignature",
//                         "ArithmeticError",
//                     ]
//                     .contains(&flag.as_str())
//                 });
//                 decoding_sig_failed += 1;
//                 assert_eq!(
//                     TestResult::Invalid,
//                     test.result,
//                     "tc_id: {}, signature decoding failed but test is valid",
//                     test.tc_id
//                 );
//                 assert!(
//                     contains_expected_flag,
//                     "tc_id: {}, decoding signature failed, but test contained unexpected flags",
//                     test.tc_id
//                 );
//                 tests_run += 1;
//                 continue;
//             };

//             let valid = verify(test.msg.len() as u32, &test.msg, &pk_bytes, &sig.r, &sig.s);

//             match test.result {
//                 TestResult::Valid => {
//                     assert!(
//                         valid,
//                         "tc_id: {}, test result is valid but verify failed",
//                         test.tc_id
//                     );
//                 }
//                 TestResult::Invalid => {
//                     assert!(
//                         !valid,
//                         "tc_id: {}, test result is invalid but verify succeeded",
//                         test.tc_id
//                     );
//                 }
//                 TestResult::Acceptable => {
//                     unreachable!("not present in test set")
//                 }
//             }

//             tests_run += 1;
//         }
//     }

//     assert_ne!(
//         test_set.number_of_tests, decoding_sig_failed,
//         "invalid signature decode function"
//     );
//     assert_eq!(
//         test_set.number_of_tests, tests_run,
//         "invalid number of tests run"
//     );
//     println!("Ran {tests_run} {} tests", type_name_of_val(&verify),);
// }

// #[test]
// fn ecdsa_secp3841_sha256() {
//     let test_set = ecdsa::TestSet::load_secp384r1_sha256();
//     ecdsa_secp384r1_sha_test(test_set, ecdsa_verif_p256_sha2);
// }

// #[test]
// fn ecdsa_secp384r1_sha512() {
//     let test_set = ecdsa::TestSet::load_secp384r1_sha512();
//     ecdsa_secp384r1_sha_test(test_set, ecdsa_verif_p256_sha512);
// }
