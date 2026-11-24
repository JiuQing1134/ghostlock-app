//! Temporary reverse-engineering helper: run the pselect/futex stack-layout
//! derivation on a boot image and print the internal frame arithmetic.
//!
//! usage: cargo run --release --example pselect_probe -- <boot.img>

use std::path::Path;

use ghostlock_extract::boot::BootImage;
use ghostlock_extract::btf::Btf;
use ghostlock_extract::derive::{PSELECT_ROUTE_NFDS, derive_pselect_layout, relative_symbols};
use ghostlock_extract::kallsyms;
use ghostlock_extract::kallsyms_finder;

fn main() {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "boot.img".to_string());
    let boot = BootImage::load(Path::new(&path)).expect("load boot image");
    let btf_at = boot.embedded_btf_at();
    let btf_pair = btf_at.as_ref().map(|(offset, blob)| (*offset, blob.len()));
    let ks = kallsyms_finder::recover(&boot.kernel, btf_pair).expect("kallsyms recovery");
    let base = kallsyms::unique(&ks.symbols, "_text")
        .or_else(|| kallsyms::unique(&ks.symbols, "_head"))
        .expect("_text/_head");
    let (rel, sorted) = relative_symbols(&ks.symbols, base);
    let (_, blob) = boot.embedded_btf_at().expect("embedded BTF");
    let btf = Btf::new(&blob).expect("BTF");
    match derive_pselect_layout(&boot.kernel, &rel, &sorted, &btf, PSELECT_ROUTE_NFDS) {
        Ok(layout) => println!(
            "ok chain={} futex_chain={} frames={:?} buffer=0x{:x} \
             waiter_local=0x{:x} pselect_word0={:#x} futex_waiter={:#x} shift={}",
            layout.chain,
            layout.futex_chain,
            layout.frames,
            layout.pselect_buffer,
            layout.waiter_local,
            layout.pselect_word0,
            layout.futex_waiter,
            layout.shift
        ),
        Err(err) => println!("error: {err}"),
    }
}
