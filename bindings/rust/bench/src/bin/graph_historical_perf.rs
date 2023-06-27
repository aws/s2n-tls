use std::{collections::HashMap, error::Error};

use csv::Reader;
use plotters::{
    prelude::{ChartBuilder, ErrorBar, IntoDrawingArea, SVGBackend},
    style::RED,
};

fn main() -> Result<(), Box<dyn Error>> {
    let mut csv_reader = Reader::from_path("perf.csv")?;
    let mut map: HashMap<&str, Vec<(usize, f64, f64)>> = HashMap::new();
    let headers = csv_reader.headers()?.clone();
    let headers: Vec<&str> = headers
        .iter()
        .skip(1)
        .step_by(2)
        .collect::<Vec<&str>>()
        .clone();
    for header in headers.iter() {
        map.insert(header, Vec::new());
    }

    let num_entries = Reader::from_path("perf.csv")?.records().count();

    for (i, record_res) in csv_reader.records().enumerate() {
        let record = record_res?;
        let mut record_iter = record.into_iter();
        let _tag = record_iter.next().unwrap();
        for header in headers.iter() {
            map.get_mut(header).unwrap().push((
                num_entries - i,
                record_iter.next().unwrap().parse()?,
                record_iter.next().unwrap().parse()?,
            ));
        }
    }

    let drawing_area = SVGBackend::new("historical-perf.svg", (400, 250)).into_drawing_area();
    let mut ctx = ChartBuilder::on(&drawing_area)
        .build_cartesian_2d(0..num_entries + 1, 0..7000000)
        .unwrap();
    ctx.configure_mesh().draw().unwrap();
    for (bench_name, data) in map.iter() {
        let anno = ctx
            .draw_series(data.iter().map(|(x, y, y_bar)| {
                ErrorBar::new_vertical(
                    *x,
                    (*y - 1.96 * *y_bar) as i32,
                    *y as i32,
                    (*y + 1.96 * *y_bar) as i32,
                    RED,
                    10,
                )
            }))
            .unwrap();
        anno.label(*bench_name);
    }

    println!("{map:?}");

    Ok(())
}
