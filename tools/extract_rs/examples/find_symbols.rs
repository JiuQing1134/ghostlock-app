//! Temporary reverse-engineering helper: list recovered kallsyms entries whose
//! name contains a substring.
//!
//! usage: cargo run --release --example find_symbols -- <boot.img> <substr>...

use std::path::Path;

use ghostlock_extract::boot::BootImage;
use ghostlock_extract::derive::relative_symbols;
use ghostlock_extract::kallsyms;
use ghostlock_extract::kallsyms_finder;

fn main() {
    let mut args = std::env::args().skip(1);
    let boot_path = args.next().unwrap_or_else(|| {
        eprintln!("usage: find_symbols <boot.img> <substr>...");
        std::process::exit(2);
    });
    let needles: Vec<String> = args.map(|s| s.to_ascii_lowercase()).collect();
    let boot = BootImage::load(Path::new(&boot_path)).expect("load boot image");
    let btf_at = boot.embedded_btf_at();
    let btf_pair = btf_at.as_ref().map(|(offset, blob)| (*offset, blob.len()));
    let ks = kallsyms_finder::recover(&boot.kernel, btf_pair).expect("kallsyms recovery");
    let base = kallsyms::unique(&ks.symbols, "_text")
        .or_else(|| kallsyms::unique(&ks.symbols, "_head"))
        .expect("_text/_head");
    let (rel, _) = relative_symbols(&ks.symbols, base);
    for (name, offsets) in &rel {
        let lower = name.to_ascii_lowercase();
        if needles.iter().all(|needle| lower.contains(needle)) {
            for offset in offsets {
                println!("+0x{offset:x} {name}");
            }
        }
    }
}
