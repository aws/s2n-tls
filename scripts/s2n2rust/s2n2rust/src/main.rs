use anyhow::Error;
use serde::{Deserialize, Serialize};
use std::fs::{create_dir_all, remove_dir_all, write};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use xshell::{cmd, Shell};

type Result<T = (), E = Error> = core::result::Result<T, E>;

fn main() -> Result {
    let args: Vec<_> = std::env::args().collect();
    let dir = args.get(1).expect("missing s2n-tls dir");
    let dir = PathBuf::from(dir);
    let sh = xshell::Shell::new()?;

    sh.change_dir(dir);

    let include = setup_include(&sh)?;
    let commands = collect_commands(&sh)?;
    let commands = process_commands(&sh, commands, &include)?;

    let out = transpile(&sh, &commands)?;
    clean_up_entrypoints(&sh, &out)?;

    Ok(())
}

fn collect_commands(sh: &Shell) -> Result<PathBuf> {
    let out_dir = sh
        .current_dir()
        .join("scripts/s2n2rust/target/cmake-commands");
    let _ = remove_dir_all(&out_dir);

    // TODO get this working
    let build_testing = "off";

    cmd!(
        sh,
        "cmake . -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING={build_testing} -DBUILD_SHARED_LIBS=off -B{out_dir} -DCMAKE_EXPORT_COMPILE_COMMANDS=1"
    )
    .run()?;
    let commands = out_dir.join("compile_commands.json");
    Ok(commands)
}

fn setup_include(sh: &Shell) -> Result<PathBuf> {
    let src_dir = sh.current_dir();

    let include = src_dir.join("scripts/s2n2rust/target/include");
    let _ = remove_dir_all(&include);
    create_dir_all(&include)?;

    {
        let s2n_api = sh.read_file("api/s2n.h")?;
        let mut out = vec![];

        macro_rules! w {
            ($($t:tt)*) => {
                writeln!(out, $($t)*)?;
            }
        }

        for line in s2n_api.lines() {
            let Some(suffix) = line.trim().strip_prefix("#define S2N_") else {
                w!("{line}");
                continue;
            };

            match suffix {
                suffix if suffix.starts_with("API") => {
                    w!("{line}");
                }
                suffix
                    if suffix.starts_with("SSL")
                        || suffix.starts_with("TLS")
                        || suffix.starts_with("UNKNOWN_PROTOCOL_VERSION")
                        || suffix.starts_with("SUCCESS")
                        || suffix.starts_with("FAILURE")
                        || suffix.starts_with("CALLBACK_BLOCKED")
                        || suffix.starts_with("MINIMUM_SUPPORTED_")
                        || suffix.starts_with("MAXIMUM_SUPPORTED_") =>
                {
                    let (name, value) = suffix.split_once(' ').unwrap();
                    let lower = name.to_lowercase();
                    // use a `typedef enum` so c2rust generates a rust `const`
                    w!("typedef enum {{ S2N_{name} = {value} }} s2n_value_{lower};");
                }
                _ => {
                    println!("UNHANDLED: {suffix:?}");
                    w!("{line}");
                }
            }
        }

        create_dir_all(include.join("api/unstable"))?;

        write(include.join("api/s2n.h"), out)?;

        for unstable in sh.read_dir("api/unstable/")? {
            let mut src = sh.read_file(&unstable)?;
            let dest = include
                .join("api/unstable")
                .join(unstable.file_name().unwrap());

            // replace the system path with a local path
            src = src.replace("#include <s2n.h>", "#include \"api/s2n.h\"");

            write(dest, src)?;
        }
    }

    {
        let s2n_errno = sh.read_file("error/s2n_errno.h")?;
        let mut out = vec![];

        writeln!(out, "{}", include_str!("./s2n_errno.h").trim_start())?;

        writeln!(out, "{}", "typedef enum {")?;
        for line in s2n_errno.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("S2N_ERR_") {
                writeln!(out, "{line}")?;
                continue;
            }
        }
        writeln!(out, "{}", "} s2n_error;")?;

        let error = include.join("error");
        create_dir_all(&error)?;
        write(error.join("s2n_errno.h"), out)?
    }

    {
        let utils = include.join("utils");
        create_dir_all(&utils)?;

        {
            let _v = sh.push_env("S2N_SAFETY_STUB", "1");
            let _dir = sh.push_dir(&include);
            cmd!(sh, "python3 ../../../s2n_safety_macros.py").run()?;
        }

        write(
            utils.join("s2n_ensure.h"),
            include_str!("./s2n_ensure.h").trim_start(),
        )?;

        write(
            utils.join("s2n_result.h"),
            include_str!("./s2n_result.h").trim_start(),
        )?;
    }

    Ok(include)
}

fn process_commands(sh: &Shell, commands: PathBuf, overrides: &Path) -> Result<PathBuf> {
    // TODO get the version from the environment
    let system_include = "/usr/lib/clang/6.0/include";
    let system_include = format!(" -I{system_include}");

    let overrides = overrides.display();
    let overrides = format!("-I{overrides} -I{overrides}/api");

    let f = std::fs::File::open(commands)?;
    let f = std::io::BufReader::new(f);

    #[derive(Clone, Debug, Serialize, Deserialize)]
    struct Command {
        directory: String,
        command: String,
        file: String,
    }

    let mut cmds: Vec<Command> = serde_json::from_reader(f)?;

    for cmd in &mut cmds {
        // find the first space
        let index = cmd.command.find(' ').unwrap();
        cmd.command.insert_str(index + 1, &overrides);

        cmd.command = cmd
            .command
            // this argument isn't used
            .replace("-Wa,--noexecstack", "")
            // don't warn on `include_next` errors
            .replace("-pedantic", "");

        cmd.command += &system_include;
        // we may generate more functions than we actually end up using
        cmd.command += " -Wno-unused-function";
    }

    cmds.retain(|cmd| {
        // we override this with a different impl
        if cmd.file.ends_with("s2n_errno.c") || cmd.file.ends_with("s2n_result.c") {
            return false;
        }

        // TODO pull this from argument
        let refactoring = false;

        if refactoring {
            // the inline asm is currently broken
            if cmd.file.ends_with("s2n_random.c") {
                return false;
            }

            // stuffer_text uses varargs, which is broken
            if cmd.file.ends_with("s2n_stuffer_text.c") {
                return false;
            }

            // toggle the different subdirectories
            let list = [
                //"/crypto/",
                "/stuffer/",
                //"/tls/",
                "/utils/",
            ];

            return list.iter().any(|dir| cmd.file.contains(dir));
        }

        true
    });

    let out = sh
        .current_dir()
        .join("scripts/s2n2rust/target/compile_commands.json");

    let f = std::fs::File::create(&out)?;
    let f = std::io::BufWriter::new(f);
    serde_json::to_writer(f, &cmds)?;

    Ok(out)
}

fn transpile(sh: &Shell, commands: &Path) -> Result<PathBuf> {
    let out = sh.current_dir().join("scripts/s2n2rust/target/s2n-tls/");

    create_dir_all(&out)?;
    let _ = remove_dir_all(&out);
    cmd!(
        sh,
        "c2rust transpile {commands} --output-dir {out} --emit-build-files"
    )
    .run()?;

    Ok(out)
}

fn clean_up_entrypoints(sh: &Shell, out: &Path) -> Result {
    let _dir = sh.push_dir(out);

    {
        let librs = sh.read_file("lib.rs")?;
        let mut out = vec![];
        for line in librs.lines() {
            // inline-asm is stable in 1.59
            if line == "#![feature(asm)]" {
                continue;
            }

            // don't wrap the root in a `src` module
            if line == "pub mod src {" || line == "} // mod src" {
                continue;
            }

            writeln!(out, "{line}")?;
        }

        sh.write_file("src/lib.rs", out)?;
        sh.remove_path("lib.rs")?;
    }

    // clean up extra unneeded files
    {
        sh.remove_path("build.rs")?;
        // we make our own
        sh.remove_path("Cargo.toml")?;
        sh.remove_path("rust-toolchain.toml")?;
    }

    sh.write_file("Cargo.toml", include_str!("./project.toml").trim_start())?;

    Ok(())
}
