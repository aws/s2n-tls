#![allow(non_camel_case_types)]

use anyhow::Error;
use std::path::PathBuf;
use xshell::Shell;

type Result<T = (), E = Error> = core::result::Result<T, E>;

mod crypto;
mod error;
mod stuffer;
mod tls;
mod utils;

mod refactor;
mod replace;
mod transpile;

fn main() -> Result {
    let args: Vec<_> = std::env::args().collect();
    let c_src = args.get(2).expect("missing s2n-tls dir");
    let c_src = PathBuf::from(c_src).canonicalize()?;
    let sh = Shell::new()?;

    sh.change_dir(&c_src);

    match args.get(1).map(|v| v.as_str()) {
        Some("transpile") => {
            transpile::run(&sh)?;
        }
        Some("refactor") => {
            refactor::run(&sh)?;
        }
        Some(command) => {
            panic!("invalid command: {command:?}");
        }
        None => {
            panic!("missing command");
        }
    }

    Ok(())
}
