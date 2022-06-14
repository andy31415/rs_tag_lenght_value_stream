#![no_main]
use libfuzzer_sys::fuzz_target;

use tag_length_value_stream::Parser;

fuzz_target!(|data: &[u8]| {
    for _record in Parser::new(data) {
        // do nothing, just consume
    }
});
