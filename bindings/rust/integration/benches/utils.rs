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
    #[allow(dead_code)]
    pub fn get_dash_c(self) -> Result<&'a str, ()> {
        let mut counter = 0;
        for element in &self.argument {
            counter += 1;
            if element.eq(&"-c") {
                return Ok(self.argument[counter]);
            }
        }
        Err(())
    }

    pub fn get_endpoint(self) -> Result<&'a str, ()> {
        let mut counter = 0;
        for element in &self.argument {
            counter += 1;
            if element.eq(&"-c") {
                return Ok(self.argument[counter + 1]);
            }
        }
        Err(())
    }

    pub fn get_vec(self) -> Vec<&'a str> {
        self.argument
    }
}

#[test]
fn argument_get_dash_c_test() {
    let args: Arguments = "reset --hard --force -c foo.pem".into();
    assert_eq!(
        args.get_dash_c().unwrap(),
        "foo.pem",
        "Failed to fetch the correct argument"
    );
}

#[test]
#[should_panic]
fn argument_empty_test() {
    let _a: Arguments = "".into();
}
