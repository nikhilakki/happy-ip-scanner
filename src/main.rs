mod cli;
mod engine;
mod export;
mod gui;

use clap::Parser;
use cli::{CliArgs, run_cli};
use gui::run_gui;

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = CliArgs::parse();

    // No arguments at all, or an explicit --gui, launches the desktop application.
    let gui_mode = args.gui || std::env::args_os().len() == 1;

    // Scanning opens thousands of sockets; a low file-descriptor limit would make busy
    // ports look closed. Best effort: nothing to do if the OS refuses.
    engine::limits::raise_open_file_limit();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    if gui_mode {
        // Keep the runtime entered so the GUI thread can `tokio::spawn` scans.
        let _guard = runtime.enter();
        run_gui().map_err(|e| format!("Failed to launch GUI: {e}"))?;
        Ok(())
    } else {
        runtime.block_on(run_cli(args))
    }
}
