#![no_main]
use libfuzzer_sys::fuzz_target;

use tag_length_value_stream::Parser;
use tag_length_value_stream::TlvBytes;
use streaming_iterator::StreamingIterator;

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
    let mut updated  = Parser::new(rewritten.as_slice());
    
    loop {
        let a = original.next();
        let b = updated.next();
        
        assert_eq!(a, b);

        if a.is_none() {
            break;
        }
    }
    
    
});
