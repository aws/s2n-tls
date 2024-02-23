// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use plotters::{
    prelude::{
        ChartBuilder, IntoDrawingArea, IntoSegmentedCoord, LabelAreaPosition, Rectangle,
        SVGBackend, SegmentValue,
    },
    style::{AsRelative, Color, IntoFont, Palette, Palette99, RGBAColor, WHITE},
};
use std::{
    collections::BTreeMap,
    error::Error,
    fs::{read_dir, read_to_string},
    path::Path,
};

struct Stats {
    mean: f64,
    stderr: f64,
}

fn get_bytes_from_snapshot(path: &Path, i: i32) -> i32 {
    // number of bytes in snapshot starts on 8th line, 12th character
    read_to_string(format!("{}/{i}.snapshot", path.display()))
        .unwrap()
        .lines()
        .nth(7)
        .unwrap()[11..]
        .parse()
        .unwrap()
}

/// Get the difference in bytes between two snapshots, which is memory of the
/// `i`th TlsConnPair (client and server)
fn get_bytes_diff(path: &Path, i: i32) -> i32 {
    get_bytes_from_snapshot(path, i + 1) - get_bytes_from_snapshot(path, i)
}

fn get_memory_data(path: &Path) -> Stats {
    let data: Vec<f64> = (0..100).map(|i| get_bytes_diff(path, i) as f64).collect();
    let mean = data.iter().sum::<f64>() / (data.len() as f64);
    let variance: f64 =
        data.iter().map(|x| (x - mean) * (x - mean)).sum::<f64>() / ((data.len() - 1) as f64);
    let stdev = variance.sqrt();
    let stderr = stdev / (data.len() as f64).sqrt();

    Stats { mean, stderr }
}

/// Gets data from memory benching and plots it
fn plot_memory_data(param_name: &str, target_name: &str) -> Result<(), Box<dyn Error>> {
    // go through each library name directory (ex. "s2n-tls") and calculate stats
    let mut stats: BTreeMap<String, Stats> = Default::default(); // btree to sort by name
    for dir_entry in read_dir(format!("target/memory/{param_name}/{target_name}"))? {
        let dir_path = dir_entry?.path();
        let dir_name = dir_path.file_name().unwrap().to_str().unwrap().to_string();
        stats.insert(dir_name.clone(), get_memory_data(&dir_path));
    }

    // calculate things for plotting
    let num_bars = stats.len();
    let x_labels: Vec<String> = stats.iter().map(|kv| kv.0.clone()).collect();
    let max_mem = 120_000.0; // constant to keep scale same for all graphs

    // setup plotting
    let chart_path = format!("images/memory-{target_name}-{param_name}.svg");
    let drawing_area = SVGBackend::new(&chart_path, (600, 500)).into_drawing_area();
    drawing_area.fill(&WHITE)?;

    let mut ctx = ChartBuilder::on(&drawing_area)
        .caption(
            format!("Memory of {target_name} with {param_name}"),
            ("sans-serif", 30).into_font(),
        )
        .set_label_area_size(LabelAreaPosition::Left, (15).percent()) // axes padding
        .set_label_area_size(LabelAreaPosition::Bottom, (6).percent())
        .build_cartesian_2d(
            (0..num_bars - 1).into_segmented(),
            0.0..(1.1 * max_mem), // upper y bound on plot is 1.1 * y_max
        )?;

    let axis_label_style = ("sans-serif", 18).into_font();

    ctx.configure_mesh()
        .light_line_style(RGBAColor(235, 235, 235, 1.0)) // change gridline color
        .bold_line_style(RGBAColor(225, 225, 225, 1.0))
        .x_labels(num_bars)
        .x_label_formatter(&|x| {
            // change axis labels to name of bar
            let x = match *x {
                SegmentValue::CenterOf(x) => x,
                _ => 0,
            };
            x_labels.get(x).unwrap().to_string()
        })
        .x_label_style(axis_label_style.clone())
        .y_desc("Memory (kB)")
        .y_labels(10) // max number of labels on y axis
        .y_label_formatter(&|y| format!("{} kB", y / 1000.0))
        .y_label_style(axis_label_style)
        .draw()?;

    // draw bars
    // x coord is index of bench name in x_labels
    ctx.draw_series(stats.iter().enumerate().map(|(i, (_name, stats))| {
        // define each bar as a Rectangle
        let x0 = SegmentValue::Exact(i);
        let x1 = SegmentValue::Exact(i + 1);
        let color = Palette99::pick(i).filled();
        let mut bar = Rectangle::new([(x0, 0.0), (x1, stats.mean)], color);
        bar.set_margin(0, 0, 30, 30); // spacing between bars
        bar
    }))?;

    Ok(())
}

/// Plots all available data in target/memory and stores graphs in images
fn main() -> Result<(), Box<dyn Error>> {
    // iterate through param options ex. shrink-buffers or reuse-config
    for param_dir_entry in read_dir("target/memory")? {
        let param_dir_path = param_dir_entry?.path();
        let param_name = param_dir_path.file_name().unwrap().to_str().unwrap();

        // iterate through targets, ex. client or server
        for target_dir_entry in read_dir(&param_dir_path)? {
            let target_name = target_dir_entry?.file_name().to_string_lossy().to_string();
            plot_memory_data(param_name, &target_name)?;
        }
    }

    Ok(())
}
