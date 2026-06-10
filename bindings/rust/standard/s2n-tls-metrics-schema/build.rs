// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::io::Write;
use std::{env, fs, path::Path};

struct AlertCsvEntry {
    value: u8,
    description: String,
}

impl AlertCsvEntry {
    fn from_csv_line(line: &str) -> Option<Self> {
        let mut fields = line.split(',');
        let value = fields.next().unwrap();
        let description = fields.next().unwrap();
        if description == "Unassigned" || description.contains("RESERVED") {
            return None;
        }

        let value: u8 = value.parse().ok()?;

        Some(Self {
            value,
            description: description.to_owned(),
        })
    }
}

fn parse_csv() -> Vec<AlertCsvEntry> {
    let csv = include_str!("resources/tls-parameters-6.csv");
    csv.lines()
        .skip(1)
        .filter_map(AlertCsvEntry::from_csv_line)
        .collect()
}

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("alerts_generated.rs");

    let entries = parse_csv();

    let mut constants = String::new();
    let mut match_arms = String::new();
    let mut array_entries = String::new();

    for entry in &entries {
        constants.push_str(&format!(
            "pub const {}: Alert = Alert({});\n",
            entry.description.to_uppercase(),
            entry.value
        ));
        match_arms.push_str(&format!(
            "{} => Some(\"{}\"),\n",
            entry.value, entry.description
        ));
        array_entries.push_str(&format!(
            "Alert::{},",
            entry.description.to_ascii_uppercase()
        ));
    }

    let count = entries.len();
    let generated = format!(
        "\
// Auto-generated from tls-parameters-6.csv — do not edit.

impl Alert {{
    {constants}

    pub const DEFINED_ALERTS: [Alert; {count}] = [{array_entries}];
    
    pub fn get_description(&self) -> Option<&'static str> {{
        match self.0 {{
            {match_arms}
            _ => None,
        }}
    }}
}}

"
    );

    fs::File::create(&dest_path)
        .unwrap()
        .write_all(generated.as_bytes())
        .unwrap();

    println!("cargo::rerun-if-changed=resources/tls-parameters-6.csv");
}
