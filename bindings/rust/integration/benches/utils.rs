pub use anyhow::{anyhow, Error};
#[derive(Debug, Clone)]
pub struct Arguments<'a> {
    argument: Vec<&'a str>,
}

impl<'a> From<&'a str> for Arguments<'a> {
    fn from(s: &'a str) -> Arguments<'a> {
        assert_ne!(s.len(), 0, "Arguments string can not be empty");
        let s_split = s.split(' ');
        Arguments {
            argument: s_split.collect::<Vec<&str>>(),
        }
    }
}

impl<'a> Arguments<'a> {
    pub fn get_endpoint(self) -> Result<&'a str, anyhow::Error> {
        let mut counter = 0;
        for element in &self.argument {
            counter += 1;
            if element.eq(&"-c") {
                let result = self.argument[counter + 1]
                    .trim_end_matches('_')
                    .trim_start_matches('_');
                return Ok(result);
            }
        }
        Err(anyhow!("Unable to find endpoint in arguments."))
    }

    pub fn get_vec(self) -> Vec<&'a str> {
        self.argument
    }
}

#[test]
#[should_panic]
fn argument_empty_test() {
    let _a: Arguments = "".into();
}
