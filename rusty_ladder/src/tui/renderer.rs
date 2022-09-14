/**********************************************************************

Copyright (C) 2021 by reddal

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

**********************************************************************/

use super::{BoxStdErr, ColumnIndex};
use ladder_lib::server::stat::{CounterValue, Snapshot};
use tui::{
	backend::Backend,
	layout::{Alignment, Constraint, Direction, Layout, Rect},
	style::{Color, Style},
	text::{Span, Spans},
	widgets::Paragraph,
	Frame, Terminal,
};

const ZERO_BYTE: &str = "0 B/s";
const Y_AXIE_MAX_FACTOR: f64 = 1.1;

pub(super) struct Renderer {
	/// Style of the speed chart.
	style_hint: Style,
	conn_table: ConnTable,
	speed_chart: SpeedChart,
}

impl Renderer {
	pub fn new() -> Self {
		Self {
			style_hint: Style::default().bg(Color::White).fg(Color::Black),
			conn_table: ConnTable::new(),
			speed_chart: SpeedChart::new(),
		}
	}

	#[allow(clippy::cast_possible_truncation)]
	pub fn update_table<'a>(&mut self, snapshots: impl Iterator<Item = &'a Snapshot>) {
		self.conn_table.update_table(snapshots);
	}

	#[allow(clippy::cast_precision_loss)]
	pub fn update_speed_chart(&mut self, total_speed: &CounterValue) {
		self.speed_chart.update_speed_chart(total_speed);
	}

	pub fn set_sort_column(&mut self, sort_column: Option<ColumnIndex>) {
		self.conn_table.set_sort_column(sort_column);
	}

	pub fn set_selected_row(&mut self, row: Option<usize>, following: bool) {
		self.conn_table.set_selected_row(row, following);
	}

	pub fn draw<B: Backend>(&mut self, terminal: &mut Terminal<B>) -> Result<(), BoxStdErr> {
		terminal.draw(|f| {
			let constraints = [
				Constraint::Percentage(40),
				Constraint::Max(100),
				Constraint::Length(1),
				Constraint::Length(1),
			];
			let rects = Layout::default()
				.direction(Direction::Vertical)
				.constraints(constraints.as_ref())
				.split(f.size());

			debug_assert_eq!(constraints.len(), rects.len());

			let mut areas = rects.into_iter();
			self.speed_chart.draw(f, areas.next().unwrap());
			self.conn_table.draw(f, areas.next().unwrap());
			self.draw_hints(f, areas.next().unwrap());
			self.draw_hints_following(f, areas.next().unwrap());
		})?;

		Ok(())
	}

	fn draw_hints<B: Backend>(&self, f: &mut Frame<B>, area: Rect) {
		let text = Spans::from(vec![
			Span::styled("Q/ESC", self.style_hint),
			Span::raw(" Exit    "),
			Span::styled("UP", self.style_hint),
			Span::raw(" Select up    "),
			Span::styled("DOWN", self.style_hint),
			Span::raw(" Select down    "),
			Span::styled("LEFT", self.style_hint),
			Span::raw(" Sort left    "),
			Span::styled("RIGHT", self.style_hint),
			Span::raw(" Sort right    "),
		]);
		f.render_widget(Paragraph::new(text).alignment(Alignment::Center), area);
	}

	fn draw_hints_following<B: Backend>(&self, f: &mut Frame<B>, area: Rect) {
		let (status_str, status_style) = if self.conn_table.following_row {
			("ON ", self.conn_table.style_following)
		} else {
			("OFF", self.conn_table.style_selected)
		};
		let text = Spans::from(vec![
			Span::styled("F", self.style_hint),
			Span::raw(" Focus on row (current: "),
			Span::styled(status_str, status_style),
			Span::raw(" )"),
		]);
		f.render_widget(Paragraph::new(text).alignment(Alignment::Center), area);
	}
}

mod conn_table {
	use crate::tui::{display_helper::SecondsCount, ColumnIndex, RowTexts, ROW_ITEM_INFO};
	use ladder_lib::{
		server::stat::{snapshot, Snapshot},
		BytesCount,
	};
	use log::trace;
	use std::{fmt::Write, time::SystemTime};
	use tui::{
		backend::Backend,
		layout::{Constraint, Rect},
		style::{Color, Modifier, Style},
		widgets::{Block, Borders, Cell, Row, Table, TableState},
		Frame,
	};

	struct TableDrawer<'a> {
		rows_texts: &'a [(RowTexts, bool, Option<usize>)],
		dead_style: Style,
		outbound_styles: &'a [Style],
		sort_column: Option<ColumnIndex>,
		highlight_style: Style,
		selected_style: Style,
		title_str: &'a str,
		widths: &'a [Constraint],
		area: Rect,
	}

	impl<'a> TableDrawer<'a> {
		fn draw<B: Backend>(self, f: &mut Frame<B>, table_state: &mut TableState) {
			// get rows iterator
			let rows = {
				// map all rows with the styles
				self.rows_texts
					.iter()
					.map(|(cell_texts, is_dead, outbound_id)| {
						let style = if *is_dead {
							// dead
							self.dead_style
						} else {
							outbound_id.map_or_else(
								|| {
									// still handshaking with client
									self.outbound_styles[0]
								},
								|ind| {
									// finished handshaking with client
									self.outbound_styles[ind % self.outbound_styles.len()]
								},
							)
						};
						Row::new(cell_texts.iter().map(String::as_str)).style(style)
					})
			};

			// texts for row header
			let header = {
				let cells = ROW_ITEM_INFO
					.iter()
					.enumerate()
					.map(|(ind, (header_text, _))| {
						let mut cell = Cell::from(*header_text);
						if let Some(sort_column) = self.sort_column {
							if sort_column as usize == ind {
								cell = cell.style(self.selected_style);
							}
						};
						cell
					});
				Row::new(cells)
			};

			// draw table
			let table = Table::new(rows)
				.block(
					Block::default()
						.borders(Borders::TOP | Borders::BOTTOM)
						.title(self.title_str),
				)
				.header(header)
				.highlight_style(self.highlight_style)
				.widths(self.widths);
			f.render_stateful_widget(table, self.area, table_state);
		}
	}

	pub(super) struct ConnTable {
		pub following_row: bool,
		/// a list of (texts, is_dead, Option(outbound_id))
		rows_texts: Vec<(RowTexts, bool, Option<usize>)>,
		sort_column: Option<ColumnIndex>,
		/// Style of the row that represent a dead session.
		style_dead: Style,
		/// Style of the selected row that is set to following.
		pub style_following: Style,
		/// Style of the selected row.
		pub style_selected: Style,
		/// Style of each rows will be `outbound_styles[outbound.ind % outbound_styles.len()]`.
		styles_outbound: Vec<Style>,
		table_state: TableState,
		title_str: String,
		widths: Vec<Constraint>,
	}

	impl ConnTable {
		pub fn new() -> Self {
			let widths = {
				let total: u16 = ROW_ITEM_INFO.iter().map(|x| x.1).sum();
				ROW_ITEM_INFO
					.iter()
					.map(|x| Constraint::Ratio(u32::from(x.1), u32::from(total)))
					.collect()
			};

			Self {
				following_row: false,
				rows_texts: Vec::with_capacity(64),
				sort_column: None,
				table_state: TableState::default(),
				styles_outbound: vec![
					Style::default().fg(Color::White),
					Style::default().fg(Color::LightGreen),
					Style::default().fg(Color::LightBlue),
					Style::default().fg(Color::LightCyan),
					Style::default().fg(Color::LightMagenta),
				],
				style_selected: Style::default()
					.fg(Color::Black)
					.add_modifier(Modifier::BOLD)
					.bg(Color::Cyan),
				style_following: Style::default()
					.fg(Color::Black)
					.add_modifier(Modifier::BOLD)
					.bg(Color::Yellow),
				style_dead: Style::default().fg(Color::DarkGray),
				title_str: String::default(),
				widths,
			}
		}

		pub fn set_sort_column(&mut self, sort_column: Option<ColumnIndex>) {
			self.sort_column = sort_column;
		}

		pub fn set_selected_row(&mut self, row: Option<usize>, following: bool) {
			trace!(
				"Selecting row {}/{}",
				row.map_or("none".to_owned(), |x| x.to_string()),
				self.rows_texts.len()
			);
			self.table_state.select(row);
			self.following_row = following;
		}

		#[allow(clippy::cast_possible_truncation)]
		pub fn update_table<'a>(&mut self, snapshots: impl Iterator<Item = &'a Snapshot>) {
			macro_rules! format_to {
            ($dst:expr, $($arg:tt)*) => {
				write!($dst, $($arg)*).unwrap();
            };
        }

			self.rows_texts.clear();
			if let (_, Some(size)) = snapshots.size_hint() {
				self.rows_texts.reserve(size);
			}
			trace!("Updating rows");

			let now = SystemTime::now();
			for s in snapshots {
				trace!("Updating conn {:x} text", s.basic.conn_id);
				let mut row_text = RowTexts::default();
				let row_text_mut = &mut row_text;

				// Only need 16 bit
				let id = s.basic.conn_id as u16;

				format_to!(ColumnIndex::ConnId.get_mut(row_text_mut), "{:x}", id);
				format_to!(
					ColumnIndex::Inbound.get_mut(row_text_mut),
					"{}",
					s.basic.inbound_tag
				);

				let mut lasted: u64 = now
					.duration_since(s.basic.start_time)
					.expect("Invalid system time")
					.as_secs();

				let mut state_text = match &s.state {
					snapshot::State::Handshaking => "Handshaking",
					snapshot::State::Connecting(i) => {
						format_to!(ColumnIndex::Dst.get_mut(row_text_mut), "{}", i.to);
						format_to!(
							ColumnIndex::Outbound.get_mut(row_text_mut),
							"{}",
							i.outbound_tag
						);
						"Connecting"
					}
					snapshot::State::Proxying {
						out,
						recv,
						send,
						recv_speed,
						send_speed,
					} => {
						format_to!(ColumnIndex::Dst.get_mut(row_text_mut), "{}", out.to);
						format_to!(
							ColumnIndex::Outbound.get_mut(row_text_mut),
							"{}",
							out.outbound_tag
						);
						if s.is_dead() {
							format_to!(
								ColumnIndex::Recv.get_mut(row_text_mut),
								"{}",
								BytesCount(*recv)
							);
							format_to!(
								ColumnIndex::Send.get_mut(row_text_mut),
								"{}",
								BytesCount(*send)
							);
						} else {
							format_to!(
								ColumnIndex::Recv.get_mut(row_text_mut),
								"{}/s",
								BytesCount(*recv_speed)
							);
							format_to!(
								ColumnIndex::Send.get_mut(row_text_mut),
								"{}/s",
								BytesCount(*send_speed)
							);
						}
						"Proxying"
					}
				};

				if let Some(end_time) = s.end_time {
					trace!("conn is dead");
					lasted = end_time
						.duration_since(s.basic.start_time)
						.expect("Invalid system time")
						.as_secs();
					state_text = "Dead";
				}
				let state_text = state_text;

				format_to!(
					ColumnIndex::Lasted.get_mut(row_text_mut),
					"{}",
					SecondsCount(lasted)
				);
				format_to!(ColumnIndex::State.get_mut(row_text_mut), "{}", state_text);
				trace!("Row texts: {:?}", row_text_mut);

				self.rows_texts
					.push((row_text, s.is_dead(), s.outbound_ind()));
			}
			trace!("Done updating text, rows count: {}", self.rows_texts.len());
		}

		pub fn draw<B: Backend>(&mut self, f: &mut Frame<B>, area: Rect) {
			let title_str = {
				self.title_str.clear();
				let title_str = &mut self.title_str;
				title_str.push_str("Connections");
				if let Some(row_ind) = self.table_state.selected() {
					write!(title_str, "[{}/{}]", row_ind, self.rows_texts.len()).unwrap();
				}
				title_str.as_str()
			};
			let highlight_style = if self.following_row {
				self.style_following
			} else {
				self.style_selected
			};

			TableDrawer {
				rows_texts: &self.rows_texts,
				dead_style: self.style_dead,
				outbound_styles: &self.styles_outbound,
				sort_column: self.sort_column,
				highlight_style,
				selected_style: self.style_selected,
				title_str,
				widths: &self.widths,
				area,
			}
			.draw(f, &mut self.table_state);
		}
	}
}
use conn_table::ConnTable;

mod speed_chart {
	use crate::tui::DEFAULT_RESERVE_FRAMES_NUM;
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

	use super::{Y_AXIE_MAX_FACTOR, ZERO_BYTE};

	pub(super) struct SpeedChart {
		send: ChartData,
		recv: ChartData,
		style: Style,
	}

	impl SpeedChart {
		pub fn new() -> Self {
			Self {
				send: ChartData::new(DEFAULT_RESERVE_FRAMES_NUM),
				recv: ChartData::new(DEFAULT_RESERVE_FRAMES_NUM),
				style: Style::default().fg(Color::White),
			}
		}

		#[allow(clippy::cast_precision_loss)]
		pub fn update_speed_chart(&mut self, total_speed: &CounterValue) {
			// Have to cast to f64 to avoid reallocating heap memory on each draw
			self.recv.push(total_speed.recv as f64);
			self.send.push(total_speed.send as f64);
		}

		#[allow(clippy::cast_sign_loss)]
		#[allow(clippy::cast_possible_truncation)]
		pub fn draw<B: Backend>(&self, f: &mut Frame<B>, area: Rect) {
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
}
use speed_chart::SpeedChart;
