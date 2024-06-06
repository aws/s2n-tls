fn main() {
    for (name, value) in std::env::vars() {
        if let Some(version) = name.strip_prefix("DEP_AWS_LC_") {
            if let Some(version) = version.strip_suffix("_INCLUDE") {
                let version = version.to_string();

                println!("cargo:rerun-if-env-changed={}", name);

                let include = value;
                let root = env(format!("DEP_AWS_LC_{version}_ROOT"));
                let link = env(format!("DEP_AWS_LC_{version}_LIBCRYPTO"));

                println!("cargo::rustc-env=LIBCRYPTO_INCLUDE={include}");
                println!("cargo::rustc-env=LIBCRYPTO_ROOT={root}");
                println!("cargo::rustc-env=LIBCRYPTO_LINK={link}");

                return;
            }
        }
    }

    panic!("missing DEP_AWS_LC paths");
}

fn env<N: AsRef<str>>(name: N) -> String {
    let name = name.as_ref();
    option_env(name).unwrap_or_else(|| panic!("missing env var {name:?}"))
}

fn option_env<N: AsRef<str>>(name: N) -> Option<String> {
    let name = name.as_ref();
    println!("cargo:rerun-if-env-changed={}", name);
    std::env::var(name).ok()
}
