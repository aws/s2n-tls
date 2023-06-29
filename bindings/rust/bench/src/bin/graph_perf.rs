// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use csv::Reader;
use plotters::{
    prelude::{
        BindKeyPoints, ChartBuilder, ErrorBar, IntoDrawingArea, LabelAreaPosition, Rectangle,
        SVGBackend,
    },
    series::LineSeries,
    style::{AsRelative, Color, IntoFont, Palette, Palette99, RGBAColor, BLACK, WHITE},
};
use semver::Version;
use std::{collections::HashMap, error::Error};

fn main() -> Result<(), Box<dyn Error>> {
    let mut csv_reader = Reader::from_path("historical-perf/perf.csv")?;

    // map bench name -> points (x, y, y_bar)
    let mut map: HashMap<&str, Vec<(Version, f64, f64)>> = HashMap::new();

    // get headers of csv as Vec<String>
    let headers = csv_reader.headers()?.clone();
    let headers: Vec<String> = headers
        .iter()
        .skip(1) // skip first header "tag"
        .step_by(2) // skip stderr headers
        .map(|s| s.to_string())
        .collect::<Vec<String>>();

    // initialize data vectors
    for header in headers.iter() {
        map.insert(header, Vec::new());
    }

    // read in all the tags as Versions
    let mut tag_names = Reader::from_path("historical-perf/perf.csv")?
        .records()
        .map(|record_res| Version::parse(&record_res.unwrap()[0][1..]).unwrap())
        .collect::<Vec<_>>();
    let num_tags = tag_names.len();

    // fill in missing versions (1.3.15, 1.3.30-1.3.37)
    tag_names.push(Version::new(1, 3, 15));
    tag_names.extend((30..38).map(|p| Version::new(1, 3, p)));
    tag_names.sort();

    // get the indices of all of the tags for plotting
    let tag_names_to_index = tag_names
        .iter()
        .enumerate()
        .map(|(i, version)| (version, i))
        .collect::<HashMap<_, _>>();

    // keep track of ymax for plotting range
    let mut y_max = 0.0;

    // read in all the data
    // loop through each record (row in csv), one per tag/version
    for record in csv_reader.records().map(|res| res.unwrap()) {
        let mut record_iter = record.into_iter();

        // first item in record is tag
        let tag = Version::parse(&record_iter.next().unwrap()[1..])?;

        // every two items after is y/y-stderr pair
        // loop through each header and track (tag_name, y, y_bar)
        for header in headers.iter() {
            let (y, y_stderr) = (
                record_iter.next().unwrap().parse()?,
                record_iter.next().unwrap().parse::<f64>()?,
            );
            if y > y_max {
                y_max = y;
            }
            map.get_mut(header.as_str())
                .unwrap()
                .push((tag.clone(), y, y_stderr * 1.96)); // 1.96 is stderr coefficient for 95% confidence interval
        }
    }

    // setup plotting
    let drawing_area =
        SVGBackend::new("historical-perf/historical-perf.svg", (1000, 500)).into_drawing_area();
    drawing_area.fill(&WHITE)?;

    let mut ctx = ChartBuilder::on(&drawing_area)
        .caption(
            "Handshake performance over versions since Jun 2022",
            ("sans-serif", 30).into_font(),
        )
        .set_label_area_size(LabelAreaPosition::Left, (10).percent()) // axes padding
        .set_label_area_size(LabelAreaPosition::Bottom, (8).percent())
        .build_cartesian_2d(
            (0..num_tags + 1).with_key_points((1..num_tags).step_by(2).collect()), // put labels on every other tag
            0.0..(1.3 * y_max), // upper y bound on plot is 1.3 * y_max
        )?;

    ctx.configure_mesh()
        .light_line_style(RGBAColor(235, 235, 235, 1.0)) // change gridline color
        .bold_line_style(RGBAColor(225, 225, 225, 1.0))
        .x_desc("Version") // axes labels
        .y_desc("Time (ms)")
        .x_labels(num_tags)
        .x_label_formatter(&|x| {
            // change x coord (index of tag in tag_names) to string
            if let Some(tag_name) = tag_names.get(*x) {
                tag_name.to_string()
            } else {
                "hi".to_string()
            }
        })
        .y_labels(5) // max 5 labels on y axis
        .y_label_formatter(&|y| format!("{} ms", y / 1000000.0))
        .draw()?;

    // go through each handshake type and plot them
    for (i, (bench_name, data)) in map.iter().enumerate() {
        // remove data that returned error while benching
        // heuristic: times < 1% of y_max are invalid/had error
        let filtered_data = data
            .iter()
            .filter(|(_, y, _)| *y > 0.01 * y_max)
            .collect::<Vec<_>>();

        let color = Palette99::pick(i);

        // draw error bars
        // x coord is index of tag name in list of tag names
        ctx.draw_series(filtered_data.iter().map(|(x, y, y_bar)| {
            ErrorBar::new_vertical(
                tag_names_to_index[x],
                *y - *y_bar,
                *y,
                *y + *y_bar,
                &color,
                3,
            )
        }))?;

        // draw lines
        ctx.draw_series(LineSeries::new(
            filtered_data
                .iter()
                .map(|(x, y, _y_bar)| (tag_names_to_index[x], *y)),
            color.stroke_width(2),
        ))?
        .label(*bench_name)
        .legend(move |(x, y)| Rectangle::new([(x, y - 5), (x + 10, y + 5)], color.filled()));
    }

    // enable legend
    ctx.configure_series_labels()
        .border_style(BLACK)
        .background_style(WHITE)
        .draw()?;

    Ok(())
}
