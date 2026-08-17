//! Stream-profile preambles against the versioned conformance corpus.

#![allow(
    clippy::unwrap_used,
    reason = "test fixtures are constructed to be infallible"
)]

use refineid_rapp_core::stream::{StreamError, StreamPreamble};
use serde::Deserialize;

const CORPUS: &str = include_str!("../../../docs/protocol/vectors/rapp-v26.8.17.213.json");

#[derive(Debug, Deserialize)]
struct Corpus {
    stream_preamble: Vec<StreamVector>,
}

#[derive(Debug, Deserialize)]
struct StreamVector {
    name: String,
    encoded_hex: String,
    accepted: bool,
    #[serde(default)]
    error: Option<String>,
}

#[test]
fn stream_preambles_match_golden_bytes_and_rejections() {
    let corpus: Corpus = serde_json::from_str(CORPUS).expect("corpus must parse");
    assert_eq!(corpus.stream_preamble.len(), 5);
    for vector in corpus.stream_preamble {
        let encoded = decode_hex(&vector.encoded_hex);
        let outcome = StreamPreamble::decode(&encoded);
        if vector.accepted {
            let decoded = outcome.expect("accepted preamble must decode");
            assert_eq!(decoded, StreamPreamble, "{} decoded preamble", vector.name);
            assert_eq!(
                decoded.encode().expect("preamble must re-encode"),
                encoded,
                "{} canonical re-encoding",
                vector.name
            );
        } else {
            let error = outcome.expect_err("rejected preamble must not decode");
            let expected = match vector.error.as_deref().expect("rejection class") {
                "Malformed" => StreamError::Malformed,
                "Oversized" => StreamError::Oversized,
                "UnknownPurpose" => StreamError::UnknownPurpose,
                other => panic!("unregistered rejection class {other}"),
            };
            assert_eq!(error, expected, "{} rejection class", vector.name);
        }
    }
}

fn decode_hex(value: &str) -> Vec<u8> {
    assert!(
        value.len().is_multiple_of(2),
        "hex must have an even length"
    );
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = core::str::from_utf8(pair).expect("hex must be ASCII");
            u8::from_str_radix(pair, 16).expect("hex must be hexadecimal")
        })
        .collect()
}
