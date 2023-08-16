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

struct Stats {
    mean: f64,
    stderr: f64,
}

struct VersionDataPoint {
    version: Version, // x coordinate
    mean: f64,        // y coordinate
    stderr: f64,      // y error bar
}

struct VersionDataSeries {
    name: String, // ex. throughput-AES_128_GCM_SHA256
    data: Vec<VersionDataPoint>,
}

struct DataPoint {
    x: i32,
    y: f64,
    y_bar: f64,
}

struct DataSeries {
    name: String,
    data: Vec<DataPoint>,
}

/// Get the relevant stats in a given JSON bench output
fn process_single_json(path: &Path) -> Stats {
    let json_str = read_to_string(path).unwrap();
    let json_value: Value = serde_json::from_str(json_str.as_str()).unwrap();
    let stats = json_value.get("mean").unwrap();
    Stats {
        mean: stats.get("point_estimate").unwrap().as_f64().unwrap(),
        stderr: stats.get("standard_error").unwrap().as_f64().unwrap(),
    }
}

/// Get data from directory of Criterion json outputs, given directory path
/// Outputs a Vec of (version, mean, stderr) sorted by version
fn parse_bench_group_data(path: &Path) -> Vec<VersionDataPoint> {
    let mut data: Vec<VersionDataPoint> = read_dir(path)
        .unwrap()
        .map(|dir_entry| {
            let path = dir_entry.unwrap().path();
            let stats = process_single_json(&path);
            let tag = path.file_stem().unwrap().to_str().unwrap();
            let version = Version::parse(&tag[1..]).unwrap();
            VersionDataPoint {
                version,
                mean: stats.mean,
                stderr: stats.stderr,
            }
        })
        .collect();
    data.sort_by(|data_point_1, data_point_2| data_point_1.version.cmp(&data_point_2.version));
    data
}

/// Gets data from all bench groups given a prefix (ex. "handshake") for the bench group names
fn get_all_data(prefix: &str) -> Vec<VersionDataSeries> {
    read_dir("target/historical-perf")
        .unwrap()
        .map(|dir_entry| dir_entry.unwrap().path())
        .filter(|path| {
            // get all paths starting with prefix
            path.file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with(prefix)
        })
        .map(|path| {
            // get data in each directory
            VersionDataSeries {
                name: path.file_name().unwrap().to_string_lossy().into_owned(),
                data: parse_bench_group_data(&path),
            }
        })
        .collect()
}

fn get_unique_versions(data: &[VersionDataSeries]) -> BTreeSet<Version> {
    data.iter()
        .flat_map(|data_series| {
            data_series
                .data
                .iter()
                .map(|version_data_point| version_data_point.version.clone())
        })
        .collect()
}

/// Converts all VersionDataSeries in version_data to DataSeries
fn convert_to_data_series(
    version_data: Vec<VersionDataSeries>,
    version_to_x: &HashMap<&Version, i32>,
) -> Vec<DataSeries> {
    version_data
        .into_iter()
        .map(|version_data_series| DataSeries {
            name: version_data_series.name,
            data: version_data_series
                .data
                .into_iter()
                .map(|version_data_point| DataPoint {
                    // map VersionDataPoints to DataPoints
                    x: version_to_x[&&version_data_point.version],
                    y: version_data_point.mean,
                    y_bar: version_data_point.stderr * 1.96, // 95% confidence interval
                })
                .collect(),
        })
        .collect()
}

/// Plots given DataSeries with given chart parameters
fn plot_data<F: Fn(&i32) -> String, G: Fn(&f64) -> String>(
    data: &[DataSeries],
    image_name: &str,
    bench_name: &str,
    x_label_formatter: &F,
    y_label: &str,
    y_label_formatter: &G,
) {
    // get x_max and y_max for plotting range
    let x_max = data
        .iter()
        .flat_map(|data_series| data_series.data.iter().map(|data_point| data_point.x))
        .max_by(|a, b| a.partial_cmp(b).unwrap())
        .unwrap();
    let y_max = data
        .iter()
        .flat_map(|data_series| data_series.data.iter().map(|data_point| data_point.y))
        .max_by(|a, b| a.partial_cmp(b).unwrap())
        .unwrap();

    // setup plotting
    let path = format!("images/historical-perf-{image_name}.svg");
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
            // bounds for plot
            // plot every other x coord starting from 1 (not 0 which is default)
            (0..(x_max + 1)).with_key_points((1..(x_max + 1)).step_by(2).collect()),
            0.0..(1.2 * y_max),
        )
        .unwrap();

    let axis_label_style = ("sans-serif", 18).into_font();

    ctx.configure_mesh()
        .light_line_style(RGBAColor(235, 235, 235, 1.0)) // gridline color
        .bold_line_style(RGBAColor(225, 225, 225, 1.0))
        .x_desc("Version") // axis labels
        .x_labels(20) // max number of labels
        .x_label_style(axis_label_style.clone())
        .x_label_formatter(x_label_formatter)
        .y_desc(y_label)
        .y_labels(5)
        .y_label_formatter(y_label_formatter)
        .y_label_style(axis_label_style)
        .draw()
        .unwrap();

    // go through each DataSeries and plot them
    for (i, data_series) in data.iter().enumerate() {
        // remove data that returned error while benching
        // heuristic: times < 1% of y_max are invalid/had error
        let filtered_data = data_series
            .data
            .iter()
            .filter(|data_point| data_point.y > 0.01 * y_max)
            .collect::<Vec<_>>();

        let color = Palette99::pick(i);

        // draw error bars
        ctx.draw_series(filtered_data.iter().map(|data_point| {
            ErrorBar::new_vertical(
                data_point.x,
                data_point.y - data_point.y_bar,
                data_point.y,
                data_point.y + data_point.y_bar,
                &color,
                3,
            )
        }))
        .unwrap();

        // draw lines with legend entry
        ctx.draw_series(LineSeries::new(
            filtered_data
                .iter()
                .map(|data_point| (data_point.x, data_point.y)),
            color.stroke_width(2),
        ))
        .unwrap()
        .label(&data_series.name)
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
    let throughput_data = get_all_data("throughput");

    // combine all versions present in handshake and throughput data
    // also fill in missing version v1.3.15 and v1.3.30-v1.3.37
    let mut versions = get_unique_versions(&handshake_data);
    versions.extend(get_unique_versions(&throughput_data).into_iter());
    versions.extend((15..16).chain(30..38).map(|p| Version::new(1, 3, p)));
    let versions = versions.into_iter().collect::<Vec<Version>>();

    // map versions to x coordinates
    let version_to_x = versions
        .iter()
        .enumerate()
        .map(|(i, version)| (version, i as i32))
        .collect::<HashMap<&Version, i32>>();

    // convert from Vec<VersionDataSeries> to Vec<DataSeries> for plotting
    let handshake_data: Vec<DataSeries> = convert_to_data_series(handshake_data, &version_to_x);
    let mut throughput_data = convert_to_data_series(throughput_data, &version_to_x);

    // convert data from ns to transfer of 100KB of data -> bytes/s throughput
    throughput_data = throughput_data
        .into_iter()
        .map(|data_series| {
            const TRANSFER_SIZE: f64 = 1e5;
            const NANO_SIZE: f64 = 1e-9;
            DataSeries {
                name: data_series.name,
                data: data_series
                    .data
                    .into_iter()
                    .map(|data_point| {
                        let mean_throughput = TRANSFER_SIZE / (data_point.y * NANO_SIZE);
                        let stderr_throughput = mean_throughput
                            - TRANSFER_SIZE / ((data_point.y + data_point.y_bar) * NANO_SIZE);
                        DataPoint {
                            x: data_point.x,
                            y: mean_throughput,
                            y_bar: stderr_throughput,
                        }
                    })
                    .collect(),
            }
        })
        .collect();

    let x_label_formatter = |x: &i32| format!("{}", versions[*x as usize]);

    plot_data(
        &handshake_data,
        "handshake",
        "handshake",
        &x_label_formatter,
        "Time",
        &|y| format!("{} ms", y / 1e6),
    );
    plot_data(
        &throughput_data,
        "throughput",
        "round trip throughput",
        &x_label_formatter,
        "Throughput",
        &|y| format!("{} GB/s", y / 1e9),
    );
}
