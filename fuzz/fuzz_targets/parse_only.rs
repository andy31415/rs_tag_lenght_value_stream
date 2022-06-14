#![no_main]
use libfuzzer_sys::fuzz_target;

use tag_length_value_stream::Parser;

fuzz_target!(|data: &[u8]| {
    let mut parser = Parser::new(data);

    while let Some(_record) = parser.next() {
        // do nothing, just consume
    }
});
