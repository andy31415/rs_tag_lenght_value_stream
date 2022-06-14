#![no_main]
use libfuzzer_sys::fuzz_target;

use tag_length_value_stream::Parser;

fuzz_target!(|data: &[u8]| {
    let parser = Parser::new(data);

    while let Some(record) = parser.next() {
        // do nothing, just consume
    }
});
