use crate::{Result, Shell};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

pub struct Overrides<'a> {
    shell: &'a Shell,
    modules: HashSet<PathBuf>,
}

impl<'a> Overrides<'a> {
    pub fn write(&mut self, path: &str, contents: &str) -> Result {
        println!("Replacing {path}");
        let path = Path::new("src").join(path);
        self.shell.write_file(&path, contents)?;
        self.modules.insert(path);
        Ok(())
    }
}

#[allow(dead_code)]
mod libc;

pub fn run(sh: &Shell) -> Result<HashSet<PathBuf>> {
    let mut o = Overrides {
        shell: sh,
        modules: Default::default(),
    };

    o.write("libc.rs", include_str!("./replace/libc.rs"))?;

    crate::crypto::run(&mut o)?;
    crate::error::run(&mut o)?;
    crate::stuffer::run(&mut o)?;
    crate::tls::run(&mut o)?;
    crate::utils::run(&mut o)?;

    Ok(o.modules)
}
