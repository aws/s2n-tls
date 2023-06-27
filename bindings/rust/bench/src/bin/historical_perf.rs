use csv::Writer;
use serde_json::Value;
use std::{
    env,
    fs::{read_dir, read_to_string, OpenOptions},
    path::Path,
};

/// Return (f64, f64) of (mean, standard error)
fn process_group(path: &Path) -> (f64, f64) {
    let estimates_path = path.join("s2n-tls/new/estimates.json");
    let json_str = read_to_string(estimates_path).unwrap();
    let json_value: Value = serde_json::from_str(json_str.as_str()).unwrap();
    let means = json_value.get("mean").unwrap();
    (
        means.get("point_estimate").unwrap().as_f64().unwrap(),
        means.get("standard_error").unwrap().as_f64().unwrap(),
    )
}

fn main() {
    const CSV_OUT_PATH: &str = "perf.csv";

    let tag_name = env::args().nth(1).expect("need tag name");
    let csv_exists = Path::new(CSV_OUT_PATH).is_file();

    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .append(true)
        .open(CSV_OUT_PATH)
        .unwrap();
    let mut csv_writer = Writer::from_writer(file);

    if !csv_exists {
        let mut vec = Vec::new();
        vec.push("tag-name".to_string());
        for dir_entry in read_dir("target/criterion").unwrap() {
            let dir_path = dir_entry.unwrap().path();
            let dir_name = dir_path.file_name().unwrap();
            if dir_name != "report" {
                vec.push(dir_name.to_str().unwrap().to_string());
                vec.push(format!("{}-mean", dir_name.to_str().unwrap()));
            }
        }
        csv_writer.write_record(vec).unwrap();
    }

    csv_writer.write_field(tag_name).unwrap();

    for dir_entry in read_dir("target/criterion").unwrap() {
        let dir_path = dir_entry.unwrap().path();
        let dir_name = dir_path.file_name().unwrap();
        println!("Name: {}", dir_name.to_str().unwrap());
        if dir_name != "report" {
            let (mean, stderr) = process_group(&dir_path);
            csv_writer.write_field(mean.to_string()).unwrap();
            csv_writer.write_field(stderr.to_string()).unwrap();
        }
    }

    csv_writer.write_record(None::<&[u8]>).unwrap();

    csv_writer.flush().unwrap();
}
