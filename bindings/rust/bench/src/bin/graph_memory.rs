use plotters::{
    prelude::{
        ChartBuilder, IntoDrawingArea, IntoSegmentedCoord, LabelAreaPosition, Rectangle,
        SVGBackend, SegmentValue,
    },
    style::{AsRelative, Color, IntoFont, Palette, Palette99, RGBAColor, WHITE},
};
use std::{
    collections::HashMap,
    error::Error,
    fs::{read_dir, read_to_string},
};

struct Stats {
    mean: f64,
    stderr: f64,
}

fn get_bytes_from_snapshot(name: &str, i: i32) -> i32 {
    // number of bytes in snapshot starts on 8th line, 12th character
    read_to_string(format!("target/memory/{name}/{i}.snapshot"))
        .unwrap()
        .lines()
        .nth(7)
        .unwrap()[11..]
        .parse()
        .unwrap()
}

/// Get the difference in bytes between two snapshots, which is memory of the
/// `i`th TlsConnPair (client and server)
fn get_bytes_diff(name: &str, i: i32) -> i32 {
    get_bytes_from_snapshot(name, i + 1) - get_bytes_from_snapshot(name, i)
}

fn get_memory_data(name: &str) -> Stats {
    let data: Vec<f64> = (0..100).map(|i| get_bytes_diff(name, i) as f64).collect();
    let mean = data.iter().sum::<f64>() / (data.len() as f64);
    let variance: f64 =
        data.iter().map(|x| (x - mean) * (x - mean)).sum::<f64>() / ((data.len() - 1) as f64);
    let stdev = variance.sqrt();
    let stderr = stdev / (data.len() as f64).sqrt();

    Stats { mean, stderr }
}

fn main() -> Result<(), Box<dyn Error>> {
    // get data from each directory in target/memory
    // map bench name to its memory stats
    let mut stats: HashMap<String, Stats> = Default::default();
    for dir_entry in read_dir("target/memory")? {
        let dir_path = dir_entry?.path();
        let dir_name = dir_path.file_name().unwrap().to_str().unwrap().to_string();

        if dir_name != "xtree" {
            stats.insert(dir_name.clone(), get_memory_data(&dir_name));
        }
    }

    let num_bars = stats.len();
    let x_labels: Vec<String> = stats.iter().map(|kv| kv.0.clone()).collect();
    let max_mem = stats
        .iter()
        .max_by(|a, b| f64::total_cmp(&a.1.mean, &b.1.mean))
        .unwrap()
        .1
        .mean;

    let drawing_area = SVGBackend::new("images/memory.svg", (1000, 500)).into_drawing_area();
    drawing_area.fill(&WHITE)?;

    let mut ctx = ChartBuilder::on(&drawing_area)
        .caption(
            "Memory usage of a connection pair",
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
        bar.set_margin(0, 0, 100, 100); // spacing between bars
        bar
    }))?;

    Ok(())
}
