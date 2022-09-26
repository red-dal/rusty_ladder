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

use super::BoxStdErr;
use ladder_lib::server::stat::{CounterValue, Snapshot};
use tui::{
	backend::Backend,
	layout::{Alignment, Constraint, Direction, Layout, Rect},
	style::{Color, Style},
	text::{Span, Spans},
	widgets::Paragraph,
	Frame, Terminal,
};

pub(super) struct View {
	/// Style of the speed chart.
	style_hint: Style,
	pub conn_table: ConnTable,
	pub speed_chart: SpeedChart,
}

impl View {
	pub fn new() -> Self {
		Self {
			style_hint: Style::default().bg(Color::White).fg(Color::Black),
			conn_table: ConnTable::new(),
			speed_chart: SpeedChart::new(),
		}
	}

	pub fn update(&mut self, s: &[Snapshot]) {
		self.conn_table.update(s);
		let mut total_speed = CounterValue::new();
		for s in s {
			total_speed += s.speed();
		}
		self.speed_chart.update(&total_speed);
	}

	pub fn draw<B: Backend>(
		&mut self,
		terminal: &mut Terminal<B>,
		force: bool,
	) -> Result<(), BoxStdErr> {
		if !force && !self.conn_table.needs_redraw() && !self.speed_chart.needs_redraw() {
			return Ok(());
		}
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
			("ON ", self.conn_table.conf.following_style)
		} else {
			("OFF", self.conn_table.conf.selected_style)
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

mod conn_table;
use conn_table::ConnTable;

mod speed_chart;
use speed_chart::SpeedChart;
