//! Temporary reverse-engineering helper: print selected task_struct/cred BTF
//! field offsets for the target image.
//!
//! usage: cargo run --release --example btf_task_fields -- <boot.img>

use std::path::Path;

use ghostlock_extract::boot::BootImage;
use ghostlock_extract::btf::Btf;

fn main() {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "boot.img".to_string());
    let boot = BootImage::load(Path::new(&path)).expect("load boot image");
    let (_, blob) = boot.embedded_btf_at().expect("embedded BTF");
    let btf = Btf::new(&blob).expect("BTF");
    for field in [
        "usage",
        "prio",
        "normal_prio",
        "sched_task_group",
        "pi_lock",
        "pi_waiters",
        "pi_top_task",
        "pi_blocked_on",
        "pid",
        "tgid",
        "atomic_flags",
        "real_cred",
        "cred",
        "comm",
        "tasks",
        "seccomp",
    ] {
        println!("task_struct.{field} = {:?}", btf.field("task_struct", field));
    }
    for field in [
        "usage",
        "uid",
        "cap_inheritable",
        "cap_permitted",
        "cap_effective",
        "cap_bset",
        "cap_ambient",
        "security",
        "user",
        "user_ns",
        "group_info",
        "ucounts",
    ] {
        println!("cred.{field} = {:?}", btf.field("cred", field));
    }
    for field in [
        "tree",
        "pi_tree",
        "task",
        "lock",
        "wake_state",
        "ww_ctx",
    ] {
        println!("rt_mutex_waiter.{field} = {:?}", btf.field("rt_mutex_waiter", field));
    }
    println!("cred.size = {:?}", btf.size("cred"));
    println!("task_struct.size = {:?}", btf.size("task_struct"));
}
