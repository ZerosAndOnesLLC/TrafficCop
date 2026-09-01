#![no_main]

use libfuzzer_sys::fuzz_target;

// The YAML config parser is the largest untrusted-adjacent parsing surface
// (remote config providers fetch YAML over the network). Must never panic.
fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = serde_norway::from_str::<trafficcop::Config>(s);
    }
});
