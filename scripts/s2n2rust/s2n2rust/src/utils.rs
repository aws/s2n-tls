use crate::replace::Overrides;
use crate::Result;

#[allow(dead_code)]
pub mod s2n_fork_detection;
#[allow(dead_code)]
pub mod s2n_mem;
#[allow(dead_code)]
pub mod s2n_random;
#[allow(dead_code)]
pub mod s2n_result;
#[allow(dead_code)]
pub mod s2n_safety;

pub fn run(o: &mut Overrides) -> Result {
    o.write(
        "utils/s2n_fork_detection.rs",
        include_str!("./utils/s2n_fork_detection.rs"),
    )?;
    //o.write("utils/s2n_mem.rs", include_str!("./utils/s2n_mem.rs"))?;
    o.write("utils/s2n_random.rs", include_str!("./utils/s2n_random.rs"))?;
    o.write("utils/s2n_result.rs", include_str!("./utils/s2n_result.rs"))?;
    o.write("utils/s2n_safety.rs", include_str!("./utils/s2n_safety.rs"))?;
    Ok(())
}
