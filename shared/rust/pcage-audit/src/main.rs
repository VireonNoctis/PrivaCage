use pcage_audit::{MAX_CHECKPOINT_BYTES, verify_checkpoint_json};
use std::{
    env,
    fs::File,
    io::{self, Read},
    process,
};

fn run() -> Result<(), String> {
    let mut args = env::args_os();
    let program = args.next().unwrap_or_default();
    let path = args
        .next()
        .ok_or_else(|| format!("Usage: {} <checkpoint.json>", program.to_string_lossy()))?;
    if args.next().is_some() {
        return Err("provide exactly one checkpoint file".to_owned());
    }

    let file = File::open(&path).map_err(|error| format!("cannot open checkpoint: {error}"))?;
    let mut bytes = Vec::with_capacity(4096);
    file.take((MAX_CHECKPOINT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read checkpoint: {error}"))?;
    if bytes.len() > MAX_CHECKPOINT_BYTES {
        return Err("checkpoint exceeds the 2 MiB input limit".to_owned());
    }
    let input =
        std::str::from_utf8(&bytes).map_err(|_| "checkpoint is not valid UTF-8 JSON".to_owned())?;
    let report = verify_checkpoint_json(input).map_err(|error| error.to_string())?;
    println!("{}", report.render());
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("PRIVACAGE AUDIT CHECKPOINT: INVALID\n{error}");
        process::exit(1);
    }
}
