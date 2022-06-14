#![no_main]
use libfuzzer_sys::fuzz_target;

use streaming_iterator::StreamingIterator;
use tag_length_value_stream::{Parser, Record, TlvBytes, Value};

/// Compare records while comparing NaN to NaN.
fn check_same(a: Option<Record>, b: Option<Record>) {
    match (a, b) {
        (
            Some(Record {
                tag: ta,
                value: Value::Double(va),
            }),
            Some(Record {
                tag: tb,
                value: Value::Double(vb),
            }),
        ) => {
            assert_eq!(ta, tb);
            assert!((va == vb) || (va.is_nan() && vb.is_nan()));
        }
        (
            Some(Record {
                tag: ta,
                value: Value::Float(va),
            }),
            Some(Record {
                tag: tb,
                value: Value::Float(vb),
            }),
        ) => {
            assert_eq!(ta, tb);
            assert!((va == vb) || (va.is_nan() && vb.is_nan()));
        }
        _ => assert_eq!(a, b),
    }
}

fuzz_target!(|data: &[u8]| {
    let parser = Parser::new(data);
    let mut streamer = streaming_iterator::convert(parser);
    let mut generator = TlvBytes::new(&mut streamer);

    let mut rewritten = vec![];

    while let Some(data) = generator.next() {
        for b in data {
            rewritten.push(*b);
        }
    }

    // Both streams should be identical
    let mut original = Parser::new(data);
    let mut updated = Parser::new(rewritten.as_slice());

    loop {
        let a = original.next();
        let b = updated.next();

        check_same(a, b);

        if a.is_none() {
            break;
        }
    }
});
