use ladder_lib::{server::stat::CounterValue, BytesCount};
use std::fmt::Write;
use tui::{
	backend::Backend,
	layout::{Constraint, Direction, Layout, Rect},
	style::{Color, Style},
	symbols,
	text::Span,
	widgets::{Axis, Block, Borders, Chart, Dataset, GraphType},
	Frame,
};

const DEFAULT_RESERVE_FRAMES_NUM: usize = 32;
const ZERO_BYTE: &str = "0 B/s";
const Y_AXIE_MAX_FACTOR: f64 = 1.1;

pub struct SpeedChart {
	send: ChartData,
	recv: ChartData,
	style: Style,
	needs_redraw: bool,
}

impl SpeedChart {
	pub fn new() -> Self {
		Self {
			send: ChartData::new(DEFAULT_RESERVE_FRAMES_NUM),
			recv: ChartData::new(DEFAULT_RESERVE_FRAMES_NUM),
			style: Style::default().fg(Color::White),
			needs_redraw: false,
		}
	}

	pub fn needs_redraw(&self) -> bool {
		self.needs_redraw
	}

	#[allow(clippy::cast_precision_loss)]
	pub fn update(&mut self, total_speed: &CounterValue) {
		// Have to cast to f64 to avoid reallocating heap memory on each draw
		self.recv.push(total_speed.recv as f64);
		self.send.push(total_speed.send as f64);
		self.needs_redraw = true;
	}

	#[allow(clippy::cast_sign_loss)]
	#[allow(clippy::cast_possible_truncation)]
	pub fn draw<B: Backend>(&mut self, f: &mut Frame<B>, area: Rect) {
		let chunks = Layout::default()
			.direction(Direction::Horizontal)
			.constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
			.split(area);

		let mut draw_chart = |name: &str, data: &ChartData, area: Rect, style: Style| {
			// Because all speed values are non-negative (cast from u64),
			// it's safe to ignore sign
			let curr_speed = data.as_ref().last().map_or(0, |(_, speed)| *speed as u64);
			let title = format!("{} speed({}/s)", name, BytesCount(curr_speed));

			let bounds_x = data.bounds_x();
			let (bounds_y, labels) = data.bounds_y();

			let dataset = Dataset::default()
				.marker(symbols::Marker::Braille)
				.graph_type(GraphType::Line)
				.style(style)
				.data(data.as_ref());

			let chart = Chart::new(vec![dataset])
				.block(Block::default().borders(Borders::ALL))
				.x_axis(Axis::default().bounds(bounds_x))
				.y_axis(
					Axis::default()
						.style(Style::default().fg(Color::White))
						.title(Span::raw(title))
						.bounds(bounds_y)
						.labels(labels.iter().map(Span::raw).collect()),
				);

			f.render_widget(chart, area);
		};

		// draw 'recv' chart
		draw_chart("recv", &self.recv, chunks[0], self.style);
		draw_chart("send", &self.send, chunks[1], self.style);
		self.needs_redraw = false;
	}
}

struct ChartData {
	max_buf_len: usize,
	buf: Vec<(f64, f64)>,
	bounds_y: [f64; 2],
	bounds_y_labels: [String; 3],
}

impl ChartData {
	fn new(max_buf_len: usize) -> Self {
		let bounds_y_labels = [
			ZERO_BYTE.to_owned(),
			ZERO_BYTE.to_owned(),
			ZERO_BYTE.to_owned(),
		];

		Self {
			max_buf_len,
			buf: Vec::with_capacity(max_buf_len),
			bounds_y: Default::default(),
			bounds_y_labels,
		}
	}

	#[allow(clippy::cast_sign_loss)]
	#[allow(clippy::cast_precision_loss)]
	#[allow(clippy::cast_possible_truncation)]
	fn push(&mut self, value: f64) {
		if self.buf.len() == self.max_buf_len {
			self.buf.remove(0);
		}
		self.buf.push((0.0, value));

		for (ind, (x, _)) in self.buf.iter_mut().enumerate() {
			// Index values are usually small (there shouldn't be that many rows),
			// so precision is not a problem.
			*x = ind as f64;
		}

		let mut max = self
			.buf
			.iter()
			.max_by_key(|(_x, y)| *y as u64)
			.map_or(0.0, |(_x, y)| *y);
		max *= Y_AXIE_MAX_FACTOR;
		let max = max as u64;

		// make it divisible by 2048
		let end = std::cmp::max(max, 2048);
		let end = (end / 2048 + 1) * 2048;

		self.bounds_y_labels[1].clear();
		write!(&mut self.bounds_y_labels[1], "{}", BytesCount(end / 2)).unwrap();
		self.bounds_y_labels[2].clear();
		write!(&mut self.bounds_y_labels[2], "{}", BytesCount(end)).unwrap();

		// No need to worry about precision on bounds.
		self.bounds_y = [0.0, end as f64];
	}

	#[allow(clippy::cast_precision_loss)]
	pub fn bounds_x(&self) -> [f64; 2] {
		if self.max_buf_len > 0 {
			// No need to worry about precision on bounds.
			[0.0, (self.max_buf_len - 1) as f64]
		} else {
			[0.0, 0.0]
		}
	}

	pub fn bounds_y(&self) -> ([f64; 2], &[String; 3]) {
		(self.bounds_y, &self.bounds_y_labels)
	}
}

impl AsRef<[(f64, f64)]> for ChartData {
	fn as_ref(&self) -> &[(f64, f64)] {
		&self.buf
	}
}
