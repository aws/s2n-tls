// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::process::{Command, Stdio};

fn find_instruction_count(output: &str) -> Result<i64, io::Error> {
    let reader = BufReader::new(output.as_bytes());
    for line in reader.lines() {
        let line = line?;
        if line.contains("PROGRAM TOTALS") {
            if let Some(instructions) = line.split_whitespace().next() {
                return instructions
                    .replace(',', "")
                    .parse::<i64>()
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e));
            }
        }
    }
    panic!("Failed to find instruction count in annotated file");
}

fn main() -> Result<(), io::Error> {
    // Get the test name from the command line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: cargo run <test_name>");
        std::process::exit(1);
    }
    let test_name = &args[1];

    // Get the commit ID from the environment
    let commit_id = env::var("COMMIT_ID").expect("COMMIT_ID environment variable not set");

    // Define the path to the annotated file
    let file_path = format!("target/regression_artifacts/{commit_id}/{test_name}.annotated");

    // Change the working directory to the parent directory
    let current_dir = env::current_dir()?;
    let parent_dir = current_dir
        .parent()
        .expect("Failed to find parent directory");
    env::set_current_dir(parent_dir)?;

    let output_file_path = format!("{test_name}_instruction_counts.csv");
    let mut output_file = File::create(output_file_path)?;
    writeln!(output_file, "Run,Instruction Count")?;

    let mut instruction_counts = Vec::new();

    for run_number in 1..=100 {
        // Set the environment variable, run the test
        Command::new("cargo")
            .arg("test")
            .env("PERF_MODE", "valgrind")
            .stderr(Stdio::null())
            .output()
            .expect("Failed to run cargo test");

        // Read the file contents
        let file_content = std::fs::read_to_string(&file_path)?;
        // Find the instruction count
        match find_instruction_count(&file_content) {
            Ok(instruction_count) => {
                instruction_counts.push(instruction_count);
                writeln!(output_file, "{run_number},{instruction_count}")?;
                println!(
                    "Run {run_number}: Instruction Count = {instruction_count}"
                );
            }
            Err(e) => {
                eprintln!("Failed to find instruction count in {file_path}: {e}");
                instruction_counts.push(-1);
            }
        }
    }

    // Calculate the range, minimum, and percentage variance
    if let (Some(&min), Some(&max)) = (
        instruction_counts.iter().min(),
        instruction_counts.iter().max(),
    ) {
        let range = max - min;
        let percentage_variance = (range as f64 / min as f64) * 100.0;
        println!("Instruction Count Range: {range}");
        println!("Percentage Variance: {:.6}%", percentage_variance);
    } else {
        eprintln!("Could not calculate range and percentage variance due to insufficient data.");
    }

    Ok(())
}
