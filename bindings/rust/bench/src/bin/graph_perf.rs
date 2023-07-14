// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use plotters::{
    prelude::{
        BindKeyPoints, ChartBuilder, ErrorBar, IntoDrawingArea, LabelAreaPosition, Rectangle,
        SVGBackend, SeriesLabelPosition,
    },
    series::LineSeries,
    style::{AsRelative, Color, IntoFont, Palette, Palette99, RGBAColor, BLACK, WHITE},
};
use semver::Version;
use serde_json::Value;
use std::{
    collections::{BTreeSet, HashMap},
    fs::{read_dir, read_to_string},
    path::Path,
};

/// Return (f64, f64) of (mean, standard error) from Criterion result JSON
fn process_single_json(path: &Path) -> (f64, f64) {
    let json_str = read_to_string(path).unwrap();
    let json_value: Value = serde_json::from_str(json_str.as_str()).unwrap();
    let means = json_value.get("mean").unwrap();
    (
        means.get("point_estimate").unwrap().as_f64().unwrap(),
        means.get("standard_error").unwrap().as_f64().unwrap(),
    )
}

/// Vec of (version, mean, stderr) sorted by version for a given bench group
type BenchGroupData = Vec<(Version, f64, f64)>;

/// Get data from folder of Criterion json outputs, given directory of jsons
/// Outputs a Vec of (version, mean, stderr) sorted by version
fn parse_bench_group_data(path: &Path) -> BenchGroupData {
    let mut data: BenchGroupData = read_dir(path)
        .unwrap()
        .map(|dir_entry_res| {
            let path = dir_entry_res.unwrap().path();
            let data = process_single_json(&path);
            let tag = path.file_stem().unwrap().to_str().unwrap();
            let version = Version::parse(&tag[1..]).unwrap();
            (version, data.0, data.1)
        })
        .collect();
    data.sort_by(|(version1, _, _), (version2, _, _)| version1.cmp(version2));
    data
}

/// Gets data from all bench groups given a prefix (ex. "handshake") for the bench group names
fn get_all_data(prefix: &str) -> Vec<(String, BenchGroupData)> {
    read_dir("target/historical-perf")
        .unwrap()
        .map(|dir_entry_res| dir_entry_res.unwrap().path())
        .filter(|path| {
            path.file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with(prefix)
        })
        .map(|path| {
            (
                path.file_name().unwrap().to_string_lossy().into_owned(),
                parse_bench_group_data(&path),
            )
        })
        .collect()
}

/// Plots given data with given chart parameters
fn plot_bench_groups<F: Fn(&f64) -> String>(
    data: Vec<(String, BenchGroupData)>,
    bench_name: &str,
    y_label: &str,
    y_label_formatter: F,
) {
    // get all versions present in data
    let mut versions = data
        .iter()
        .flat_map(|(_, data)| data.iter().map(|(version, _, _)| version.clone()))
        .collect::<BTreeSet<Version>>();

    // fill in missing versions (1.3.15, 1.3.30-1.3.37)
    versions.insert(Version::new(1, 3, 15));
    versions.extend((30..38).map(|p| Version::new(1, 3, p)));

    // get `versions` as Vec to index into it
    let versions = versions.into_iter().collect::<Vec<Version>>();

    // get the indices of all of the versions for plotting
    let version_to_index = versions
        .iter()
        .enumerate()
        .map(|(i, version)| (version, i))
        .collect::<HashMap<_, _>>();
    let num_versions = versions.len();

    // get ymax for plotting range
    let y_max = *data
        .iter()
        .flat_map(|(_, data)| data.iter().map(|(_, mean, _)| mean))
        .max_by(|a, b| a.partial_cmp(b).unwrap())
        .unwrap();

    // setup plotting
    let path = format!("historical-perf/historical-perf-{bench_name}.svg");
    let drawing_area = SVGBackend::new(&path, (1000, 500)).into_drawing_area();
    drawing_area.fill(&WHITE).unwrap();

    let mut ctx = ChartBuilder::on(&drawing_area)
        .caption(
            format!("Performance of {bench_name} by version since Jun 2022"),
            ("sans-serif", 30).into_font(),
        )
        .set_label_area_size(LabelAreaPosition::Left, (17).percent()) // axes padding
        .set_label_area_size(LabelAreaPosition::Bottom, (11).percent())
        .build_cartesian_2d(
            (0..num_versions).with_key_points((1..num_versions).step_by(2).collect()), // labels on every other version
            0.0..(1.2 * y_max), // upper y bound on plot is 1.2 * y_max
        )
        .unwrap();

    let axis_label_style = ("sans-serif", 18).into_font();

    ctx.configure_mesh()
        .light_line_style(RGBAColor(235, 235, 235, 1.0)) // change gridline color
        .bold_line_style(RGBAColor(225, 225, 225, 1.0))
        .x_desc("Version") // axis labels
        .x_labels(num_versions)
        .x_label_style(axis_label_style.clone())
        .x_label_formatter(&|x| versions.get(*x).unwrap().to_string()) // change x coord (index of version in `versions`) to version string
        .y_desc(y_label)
        .y_labels(5) // max 5 labels on y axis
        .y_label_formatter(&y_label_formatter)
        .y_label_style(axis_label_style)
        .draw()
        .unwrap();

    // go through each bench group and plot them
    for (i, (group_name, data)) in data.iter().enumerate() {
        // remove data that returned error while benching
        // heuristic: times < 1% of y_max are invalid/had error
        let filtered_data = data
            .iter()
            .filter(|(_, y, _)| *y > 0.01 * y_max)
            .collect::<Vec<_>>();

        let color = Palette99::pick(i);

        // draw error bars
        // x coord is index of version in `versions`
        ctx.draw_series(filtered_data.iter().map(|(version, mean, stderr)| {
            ErrorBar::new_vertical(
                version_to_index[version],
                *mean - *stderr,
                *mean,
                *mean + *stderr,
                &color,
                3,
            )
        }))
        .unwrap();

        // draw lines
        ctx.draw_series(LineSeries::new(
            filtered_data
                .iter()
                .map(|(version, mean, _stderr)| (version_to_index[version], *mean)),
            color.stroke_width(2),
        ))
        .unwrap()
        .label(group_name)
        .legend(move |(x, y)| Rectangle::new([(x, y - 5), (x + 10, y + 5)], color.filled()));
    }

    // enable legend
    ctx.configure_series_labels()
        .position(SeriesLabelPosition::LowerRight)
        .margin(10)
        .border_style(BLACK)
        .background_style(WHITE)
        .draw()
        .unwrap();
}

fn main() {
    let handshake_data = get_all_data("handshake");
    let mut throughput_data = get_all_data("throughput");

    // convert data from ms for transfer of x amount of data -> bytes/s throughput
    throughput_data = throughput_data
        .into_iter()
        .map(|(group_name, data)| {
            const TRANSFER_SIZE: f64 = 1e5;
            const NANO_SIZE: f64 = 1e-9;
            (
                group_name,
                data.into_iter()
                    .map(|(version, mean, stderr)| {
                        let mean_throughput = TRANSFER_SIZE / (mean * NANO_SIZE);
                        let stderr_throughput =
                            mean_throughput - TRANSFER_SIZE / ((mean + stderr) * NANO_SIZE);
                        (version, mean_throughput, stderr_throughput) // change
                    })
                    .collect(),
            )
        })
        .collect();

    plot_bench_groups(handshake_data, "handshake", "Time", |y| {
        format!("{} ms", y / 1e6)
    });
    plot_bench_groups(throughput_data, "throughput", "Throughput", |y| {
        format!("{} GB/s", y / 1e9)
    });
}
