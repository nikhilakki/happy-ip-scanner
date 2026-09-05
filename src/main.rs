mod cli;
mod engine;
mod export;
mod gui;

use clap::Parser;
use cli::{run_cli, CliArgs};
use gui::run_gui;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    // If executed without arguments, or if explicitly requested with --gui, launch the Desktop GUI
    let launch_gui_mode = args.len() == 1 || args.iter().any(|arg| arg == "--gui");

    if launch_gui_mode {
        // Set up background Tokio runtime so async tasks (pinging, scanning) can be spawned from GUI
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Failed to initialize background Tokio runtime");
        let _guard = rt.enter();

        run_gui().map_err(|e| format!("Failed to launch GUI: {}", e))?;
        Ok(())
    } else {
        // Run CLI mode
        let cli_args = CliArgs::parse();
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Failed to initialize Tokio runtime");

        rt.block_on(async {
            run_cli(cli_args).await
        })
    }
}
