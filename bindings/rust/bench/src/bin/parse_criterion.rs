// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use csv::Writer;
use serde_json::Value;
use std::{
    env,
    fs::{read_dir, read_to_string, OpenOptions},
    path::Path,
};

/// Return (f64, f64) of (mean, standard error) from Criterion json of result
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

/// take in two arguments: tag name and csv path
fn main() {
    // parse arguments
    let tag_name = env::args().nth(1).expect("need tag name");
    let csv_out_path = env::args().nth(2).expect("need csv path");
    let csv_exists = Path::new(&csv_out_path).is_file();

    // open file, make csv_writer
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .append(true)
        .open(csv_out_path)
        .unwrap();
    let mut csv_writer = Writer::from_writer(file);

    // add headers if csv was just made
    if !csv_exists {
        let mut headers = Vec::new();

        // first header is tag-name
        headers.push("tag-name".to_string());

        // go through each directory in target/criterion/ to get benchmark names
        for dir_entry in read_dir("target/criterion").unwrap() {
            let dir_path = dir_entry.unwrap().path();
            let dir_name = dir_path.file_name().unwrap();

            // ignore Criterion's report directory
            if dir_name != "report" {
                // for each bench dir, need to have both mean and stderr headers
                headers.push(dir_name.to_str().unwrap().to_string());
                headers.push(format!("{}-stderr", dir_name.to_str().unwrap()));
            }
        }
        csv_writer.write_record(headers).unwrap();
    }

    // start writing a new record (row in csv)
    csv_writer.write_field(tag_name).unwrap();

    // go through each directory in target/criterion/ to get bench results
    for dir_entry in read_dir("target/criterion").unwrap() {
        let dir_path = dir_entry.unwrap().path();
        let dir_name = dir_path.file_name().unwrap();

        if dir_name != "report" {
            let (mean, stderr) = process_group(&dir_path);
            csv_writer.write_field(mean.to_string()).unwrap();
            csv_writer.write_field(stderr.to_string()).unwrap();
        }
    }

    // tell csv_writer we reached end of record with empty write_record()
    csv_writer.write_record(None::<&[u8]>).unwrap();

    csv_writer.flush().unwrap();
}
