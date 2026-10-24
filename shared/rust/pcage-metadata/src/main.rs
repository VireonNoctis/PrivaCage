use pcage_metadata::{inspect_file, scrub_file};
use std::{env, path::Path, process::ExitCode};

const MAX_BYTES: u64 = 100 * 1024 * 1024;

fn main() -> ExitCode {
    match run(env::args().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

fn run(arguments: Vec<String>) -> Result<(), String> {
    match arguments.as_slice() {
        [command, input] if command == "inspect" => {
            let report = inspect_file(Path::new(input), MAX_BYTES).map_err(|e| e.to_string())?;
            println!("{}", serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?);
            Ok(())
        }
        [command, input, output] if command == "scrub" => {
            let report = scrub_file(Path::new(input), Path::new(output), MAX_BYTES)
                .map_err(|e| e.to_string())?;
            println!("{}", serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?);
            Ok(())
        }
        _ => Err(
            "Usage:\n  pcage-metadata inspect <input>\n  pcage-metadata scrub <input> <separate-output>\n\nSupported: JPEG, PNG, WebP. Processing is local; input files are never overwritten."
                .to_owned(),
        ),
    }
}
