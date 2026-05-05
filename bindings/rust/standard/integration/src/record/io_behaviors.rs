#[test]
fn read_behaviors() {
    // when we successfully read data but the record is incomplete, poll pending 
    // is returned and peek len returns 0

    // when we successfully read data and the record is complete, poll complete
    // is returned and peek len returns the length of the plaintext data to be
    // read.
}