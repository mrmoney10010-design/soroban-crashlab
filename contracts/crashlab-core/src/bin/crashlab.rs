//! CrashLab CLI — campaign control helpers for operators.
//!
//! Run `crashlab run cancel <id>` to request cooperative cancellation for the
//! campaign identified by `id`. The running worker must poll
//! [`crashlab_core::cancel_requested`] or use [`crashlab_core::CancelSignal`].

use crashlab_core::{
    cancel_marker_path, default_state_dir, request_cancel_run, RunId,
};

fn main() {
    let mut args = std::env::args();
    let _prog = args.next();

    let a = args.next();
    let b = args.next();
    let c = args.next();

    if args.next().is_some() {
        eprintln!("usage: crashlab run cancel <id>");
        std::process::exit(1);
    }

    match (a.as_deref(), b.as_deref(), c.as_deref()) {
        (Some("run"), Some("cancel"), Some(id_str)) => {
            let id: u64 = match id_str.parse() {
                Ok(v) => v,
                Err(_) => {
                    eprintln!("invalid run id: {id_str}");
                    std::process::exit(1);
                }
            };
            let base = default_state_dir();
            let run_id = RunId(id);
            match request_cancel_run(run_id, &base) {
                Ok(()) => {
                    let path = cancel_marker_path(run_id, &base);
                    println!("cancel requested for run {id} ({})", path.display());
                }
                Err(e) => {
                    eprintln!("failed to request cancel: {e}");
                    std::process::exit(1);
                }
            }
        }
        _ => {
            eprintln!("usage: crashlab run cancel <id>");
            std::process::exit(1);
        }
    }
}
