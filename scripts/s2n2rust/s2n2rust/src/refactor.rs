use crate::Result;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use xshell::{cmd, Shell};

type Overrides = Arc<std::collections::HashSet<PathBuf>>;

mod text_scan;

pub fn run(sh: &Shell) -> Result {
    let c_src = sh.current_dir();
    let rust_src = c_src.join("scripts/s2n2rust/target/s2n-tls");

    let overrides = {
        let _d = sh.push_dir(&rust_src);
        Arc::new(crate::replace::run(sh)?)
    };

    text_scan::run(&sh, &c_src, &rust_src, &overrides)?;

    {
        let _d = sh.push_dir(&rust_src);
        cmd!(sh, "cargo fmt").run()?;
    }

    Ok(())
}
