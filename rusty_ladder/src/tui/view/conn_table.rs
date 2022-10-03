use crate::tui::display_helper::SecondsCount;
use ladder_lib::{
	server::stat::{snapshot, Id, Snapshot},
	BytesCount,
};
use smol_str::SmolStr;
use std::{cmp::Ordering, convert::TryInto, fmt::Write, num::NonZeroUsize};
use tui::{
	backend::Backend,
	layout::{Constraint, Rect},
	style::{Color, Modifier, Style},
	widgets::{Block, Borders, Cell, Row, Table, TableState},
	Frame,
};

macro_rules! format_to {
    ($dst:expr, $($arg:tt)*) => {
        write!($dst, $($arg)*).unwrap();
    };
}

/// A wrapping index that can only be within
/// `[None, 0, 1, ..., limit - 1]`.
struct WrappingIndex {
	ind: Option<usize>,
	limit: NonZeroUsize,
}

impl WrappingIndex {
	fn new(limit: NonZeroUsize) -> Self {
		Self { ind: None, limit }
	}

	/// Move to next value of the following:
	///
	///```no_rust
	///  +-> None -> 0 -> ... -> limit - 1 -+
	///  |                                  |
	///  +----------------------------------+
	/// ```
	fn go_next(&mut self) {
		self.ind = if let Some(ind) = self.ind {
			if ind >= self.limit.get() - 1 {
				None
			} else {
				Some(ind + 1)
			}
		} else {
			Some(0)
		}
	}

	/// Same with [`go_next`] but reverse.
	fn go_prev(&mut self) {
		self.ind = if let Some(ind) = self.ind {
			if ind == 0 {
				None
			} else {
				Some(ind - 1)
			}
		} else {
			Some(self.limit.get() - 1)
		}
	}

	fn value(&self) -> Option<usize> {
		self.ind
	}
}

type FormatFunc = dyn Send + Sync + Fn(&Snapshot, &mut String);
type CompareFunc = dyn Send + Sync + Fn(&Snapshot, &Snapshot) -> Ordering;

struct Column {
	name: &'static str,
	width: u16,
	format_func: Box<FormatFunc>,
	compare_func: Box<CompareFunc>,
}

impl Column {
	fn new_id() -> Self {
		Self {
			name: "ID",
			width: 3,
			format_func: Box::new(|s, output| {
				format_to!(output, "{}", s.id());
			}),
			compare_func: Box::new(|a, b| cmp_with(a, b, |i| &i.basic.conn_id).reverse()),
		}
	}

	fn new_inbound() -> Self {
		Column {
			name: "INBOUND",
			width: 4,
			format_func: Box::new(|s, output| {
				output.push_str(&s.basic.inbound_tag);
			}),
			compare_func: Box::new(|a, b| cmp_with(a, b, |i| &i.basic.inbound_tag)),
		}
	}

	fn new_outbound() -> Self {
		Column {
			name: "OUTBOUND",
			width: 4,
			format_func: Box::new(|s, output| {
				if let Some(tag) = s.outbound_tag() {
					output.push_str(tag);
				}
			}),
			compare_func: Box::new(|a, b| {
				cmp_with(a, b, |i| i.outbound_tag().map_or("", SmolStr::as_str))
			}),
		}
	}

	fn new_dst() -> Self {
		Column {
			name: "DST",
			width: 12,
			format_func: Box::new(|s, output| {
				if let Some(dst) = s.to() {
					format_to!(output, "{}", dst);
				}
			}),
			compare_func: Box::new(|a, b| cmp_with(a, b, Snapshot::to)),
		}
	}

	fn new_recv() -> Self {
		Column {
			name: "RECV",
			width: 4,
			format_func: Box::new(|s, output| {
				format_to!(output, "{}", BytesCount(s.speed().recv));
				if !s.is_dead() {
					output.push_str("/s");
				}
			}),
			compare_func: Box::new(|a, b| cmp_with(a, b, Snapshot::recv)),
		}
	}

	fn new_send() -> Self {
		Column {
			name: "SEND",
			width: 4,
			format_func: Box::new(|s, output| {
				format_to!(output, "{}", BytesCount(s.speed().send));
				if !s.is_dead() {
					output.push_str("/s");
				}
			}),
			compare_func: Box::new(|a, b| cmp_with(a, b, Snapshot::send)),
		}
	}

	fn new_lasted() -> Self {
		Column {
			name: "LASTED",
			width: 4,
			format_func: Box::new(get_lasted),
			compare_func: Box::new(cmp_lasted),
		}
	}

	fn new_state() -> Self {
		Column {
			name: "STATE",
			width: 4,
			format_func: Box::new(get_state),
			compare_func: Box::new(|a, b| {
				cmp_with(a, b, |i| match &i.state {
					snapshot::State::Handshaking => 0,
					snapshot::State::Connecting(_) => 1,
					snapshot::State::Proxying {
						out: _,
						recv: _,
						send: _,
						recv_speed: _,
						send_speed: _,
					} => 2,
				})
			}),
		}
	}
}

pub(super) struct Config {
	pub dead_style: Style,
	pub following_style: Style,
	pub selected_style: Style,
	pub outbounds_style: Vec<Style>,
	widths: Vec<Constraint>,
	cols: Vec<Column>,
}

impl Config {
	fn get_outbounds_style(&self, ind: usize) -> &Style {
		let ind = ind % self.outbounds_style.len();
		&self.outbounds_style[ind]
	}
}

enum SelectState {
	None,
	Selecting(usize),
	Following(Id),
}

#[allow(clippy::struct_excessive_bools)]
pub struct ColumnOptions {
	pub id: bool,
	pub state: bool,
	pub inbound: bool,
	pub outbound: bool,
	pub dst: bool,
	pub recv: bool,
	pub send: bool,
	pub lasted: bool,
}

impl Default for ColumnOptions {
	fn default() -> Self {
		Self {
			id: true,
			state: true,
			inbound: true,
			outbound: true,
			dst: true,
			recv: true,
			send: true,
			lasted: true,
		}
	}
}

pub struct ConnTable {
	// Row related
	pub following_row: bool,
	table_state: TableState,
	row_data: Vec<RowData>,
	// Column related
	sort_column: WrappingIndex,

	title_str: String,
	pub(super) conf: std::sync::Arc<Config>,
	needs_redraw: bool,
}

impl ConnTable {
	pub fn new(opts: &ColumnOptions) -> Self {
		let cols = {
			let mut cols = Vec::new();
			if opts.id {
				cols.push(Column::new_id());
			}
			if opts.state {
				cols.push(Column::new_state());
			}
			if opts.inbound {
				cols.push(Column::new_inbound());
			}
			if opts.outbound {
				cols.push(Column::new_outbound());
			}
			if opts.dst {
				cols.push(Column::new_dst());
			}
			if opts.recv {
				cols.push(Column::new_recv());
			}
			if opts.send {
				cols.push(Column::new_send());
			}
			if opts.lasted {
				cols.push(Column::new_lasted());
			}
			cols
		};
		if cols.is_empty() {
			panic!("Must have at least one column in conn_table");
		}

		let widths = {
			let total: u16 = cols.iter().map(|x| x.width).sum();
			cols.iter()
				.map(|x| Constraint::Ratio(x.width.into(), total.into()))
				.collect()
		};

		Self {
			// Row
			following_row: false,
			row_data: Vec::new(),
			table_state: TableState::default(),
			// Column
			sort_column: WrappingIndex::new(
				cols.len()
					.try_into()
					.expect("TUI table must have at least one column"),
			),
			conf: Config {
				outbounds_style: vec![
					Style::default().fg(Color::White),
					Style::default().fg(Color::LightGreen),
					Style::default().fg(Color::LightBlue),
					Style::default().fg(Color::LightCyan),
					Style::default().fg(Color::LightMagenta),
				],
				selected_style: Style::default()
					.fg(Color::Black)
					.add_modifier(Modifier::BOLD)
					.bg(Color::Cyan),
				following_style: Style::default()
					.fg(Color::Black)
					.add_modifier(Modifier::BOLD)
					.bg(Color::Yellow),
				dead_style: Style::default().fg(Color::DarkGray),
				cols,
				widths,
			}
			.into(),
			title_str: String::default(),
			needs_redraw: false,
		}
	}

	pub fn needs_redraw(&self) -> bool {
		self.needs_redraw
	}

	/// Sort `self.row_data` and change selected row if necessary.
	fn sort_row_data(&mut self) {
		if let Some(ind) = self.sort_column.value() {
			let compare_func = &self.conf.cols[ind].compare_func;
			self.row_data.sort_unstable_by(|a, b| {
				cmp_alive_dead(a, b)
					.then_with(|| (compare_func)(&a.s, &b.s))
					.then_with(|| cmp_start_time(a, b))
			});
		} else {
			self.row_data
				.sort_unstable_by(|a, b| cmp_alive_dead(a, b).then_with(|| cmp_start_time(a, b)));
		}
		self.needs_redraw = true;
	}

	fn get_select_state(&self) -> SelectState {
		if let Some(ind) = self.selected_row() {
			if self.following_row {
				SelectState::Following(self.row_data[ind].s.id())
			} else {
				SelectState::Selecting(ind)
			}
		} else {
			SelectState::None
		}
	}

	// --------------- row operation --------------

	pub fn toggle_following(&mut self) {
		self.following_row = !self.following_row;
		self.needs_redraw = true;
	}

	fn move_selected_row(
		&mut self,
		mut move_func: impl FnMut(&mut WrappingIndex),
		count: NonZeroUsize,
	) {
		let next_ind = if let Some(row_count) = NonZeroUsize::new(self.row_data.len()) {
			let mut ind = WrappingIndex {
				ind: self.selected_row(),
				limit: row_count,
			};
			for _ in 0..count.get() {
				move_func(&mut ind);
			}
			ind.value()
		} else {
			None
		};
		self.select_row(next_ind);
	}

	pub fn set_selected_row_prev(&mut self, count: NonZeroUsize) {
		self.move_selected_row(WrappingIndex::go_prev, count);
	}

	pub fn set_selected_row_next(&mut self, count: NonZeroUsize) {
		self.move_selected_row(WrappingIndex::go_next, count);
	}

	#[inline]
	pub fn selected_row(&self) -> Option<usize> {
		self.table_state.selected()
	}

	#[inline]
	pub fn select_row(&mut self, index: Option<usize>) {
		self.table_state.select(index);
		self.needs_redraw = true;
	}

	// --------------- column operations --------------

	fn handle_column_change(&mut self) {
		let prev_select_state = self.get_select_state();
		self.sort_row_data();
		if let SelectState::Following(id) = prev_select_state {
			self.select_row(self.row_data.iter().position(|rd| rd.s.id() == id));
		}
	}

	#[inline]
	pub fn set_sort_column_prev(&mut self) {
		self.sort_column.go_prev();
		self.handle_column_change();
	}

	#[inline]
	pub fn set_sort_column_next(&mut self) {
		self.sort_column.go_next();
		self.handle_column_change();
	}

	// ---------------- draw & update ----------------

	pub fn update<'a>(&mut self, snapshots: impl IntoIterator<Item = &'a Snapshot>) {
		let prev_select_state = self.get_select_state();
		// Fill `row_data`
		{
			let curr_len = self.row_data.len();
			let mut buf = String::with_capacity(32);
			let buf = &mut buf;
			let mut count = 0;
			for (ind, s) in snapshots.into_iter().enumerate() {
				buf.clear();
				if ind < curr_len {
					self.row_data[ind].update(buf, s, self.conf.cols.iter());
				} else {
					let rd = RowData::new(buf, s, self.conf.cols.iter());
					self.row_data.push(rd);
				}
				count += 1;
			}
			self.row_data.truncate(count);
		}
		self.sort_row_data();
		// Fix selected row index after update.
		let new_ind = match prev_select_state {
			SelectState::None => None,
			SelectState::Selecting(ind) => {
				if ind >= self.row_data.len() {
					None
				} else {
					Some(ind)
				}
			}
			SelectState::Following(id) => self.row_data.iter().position(|rd| rd.s.id() == id),
		};
		self.select_row(new_ind);
		// Keep following previous id.
		self.needs_redraw = true;
	}

	pub fn draw<B: Backend>(&mut self, f: &mut Frame<B>, area: Rect) {
		{
			self.title_str.clear();
			self.title_str.push_str("Connections");
			if let Some(ind) = self.table_state.selected() {
				write!(&mut self.title_str, "[{}/{}]", ind, self.row_data.len()).unwrap();
			}
		}

		let highlight_style = if self.following_row {
			self.conf.following_style
		} else {
			self.conf.selected_style
		};

		// get rows iterator
		let rows = {
			// map all rows with the styles
			self.row_data.iter().map(|rd| {
				let style = if rd.is_dead {
					// dead
					self.conf.dead_style
				} else {
					*self
						.conf
						.get_outbounds_style(rd.outbound_id.unwrap_or_default())
				};
				Row::new(rd.texts()).style(style)
			})
		};

		// texts for row header
		let header = {
			let cells = self.conf.cols.iter().enumerate().map(|(ind, col)| {
				let mut cell = Cell::from(col.name);
				if let Some(sort_column) = self.sort_column.value() {
					if sort_column as usize == ind {
						cell = cell.style(self.conf.selected_style);
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
					.title(self.title_str.as_str()),
			)
			.header(header)
			.highlight_style(highlight_style)
			.widths(&self.conf.widths);
		f.render_stateful_widget(table, area, &mut self.table_state);
		self.needs_redraw = false;
	}
}

fn get_state(s: &Snapshot, output: &mut String) {
	let name = match &s.state {
		snapshot::State::Handshaking => "Handshaking",
		snapshot::State::Connecting(_) => "Connecting",
		snapshot::State::Proxying {
			out: _,
			recv: _,
			send: _,
			recv_speed: _,
			send_speed: _,
		} => {
			if s.is_dead() {
				"Done"
			} else {
				"Proxying"
			}
		}
	};
	output.push_str(name);
}

fn get_lasted(s: &Snapshot, output: &mut String) {
	let end_time = s.end_time.unwrap_or_else(std::time::SystemTime::now);
	let lasted = end_time
		.duration_since(s.basic.start_time)
		.expect("Invalid system time")
		.as_secs();
	format_to!(output, "{}", SecondsCount(lasted));
}

fn cmp_alive_dead(a: &RowData, b: &RowData) -> Ordering {
	match (a.s.end_time, b.s.end_time) {
		(None, Some(_)) => Ordering::Less,
		(Some(_), None) => Ordering::Greater,
		_ => Ordering::Equal,
	}
}

fn cmp_start_time(a: &RowData, b: &RowData) -> Ordering {
	// Reverse because later (larger) start_time should come first.
	cmp_with(&a.s, &b.s, |i| i.basic.start_time).reverse()
}

fn cmp_lasted(a: &Snapshot, b: &Snapshot) -> Ordering {
	match (a.end_time, b.end_time) {
		// Both alive, compare who comes later.
		(None, None) => cmp_with(a, b, |i| i.basic.start_time).reverse(),
		(None, Some(_)) => Ordering::Less,
		(Some(_), None) => Ordering::Greater,
		// Both dead, compare how long they lasted.
		(Some(a_end_time), Some(b_end_time)) => {
			let a_lasted = a_end_time
				.duration_since(a.basic.start_time)
				.expect("end_time earlier than start_time");
			let b_lasted = b_end_time
				.duration_since(b.basic.start_time)
				.expect("end_time earlier than start_time");
			a_lasted.cmp(&b_lasted)
		}
	}
}

fn cmp_with<'a, T, F, R>(a: &'a T, b: &'a T, func: F) -> Ordering
where
	F: Fn(&'a T) -> R,
	R: Ord + 'a,
{
	let a = func(a);
	let b = func(b);
	a.cmp(&b)
}

struct StringList {
	buf: String,
	end_pos: Vec<usize>,
}

impl Default for StringList {
	fn default() -> Self {
		Self {
			buf: String::with_capacity(256),
			end_pos: Vec::new(),
		}
	}
}

impl StringList {
	pub fn clear(&mut self) {
		self.buf.clear();
		self.end_pos.clear();
	}

	pub fn push(&mut self, s: &str) {
		self.buf.push_str(s);
		self.end_pos.push(self.buf.len());
	}

	pub fn iter(&self) -> impl Iterator<Item = &'_ str> {
		(0..self.end_pos.len()).filter_map(move |ind| self.get(ind))
	}

	pub fn get(&self, ind: usize) -> Option<&str> {
		let curr_end = *self.end_pos.get(ind)?;
		Some(if ind == 0 {
			&self.buf[..curr_end]
		} else {
			let prev_end = self.end_pos[ind - 1];
			&self.buf[prev_end..curr_end]
		})
	}
}

struct RowData {
	texts: StringList,
	is_dead: bool,
	outbound_id: Option<usize>,
	s: Snapshot,
}

impl RowData {
	fn new<'a>(buf: &mut String, s: &Snapshot, cols: impl Iterator<Item = &'a Column>) -> Self {
		let mut texts = StringList::default();
		for col in cols {
			buf.clear();
			(col.format_func)(s, buf);
			texts.push(buf);
		}
		Self {
			texts,
			is_dead: s.is_dead(),
			outbound_id: s.outbound_ind(),
			s: s.clone(),
		}
	}

	fn update<'a>(
		&mut self,
		buf: &mut String,
		s: &Snapshot,
		cols: impl Iterator<Item = &'a Column>,
	) {
		self.is_dead = s.is_dead();
		self.outbound_id = s.outbound_ind();
		self.s = s.clone();
		self.texts.clear();
		for col in cols {
			buf.clear();
			(col.format_func)(s, buf);
			self.texts.push(buf);
		}
	}

	fn texts(&self) -> impl Iterator<Item = &str> {
		self.texts.iter()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::convert::TryInto;

	#[test]
	fn wrapping_index_go_next() {
		let mut i = WrappingIndex::new(4.try_into().unwrap());
		assert_eq!(i.value(), None);
		i.go_next();
		assert_eq!(i.value(), Some(0));
		i.go_next();
		assert_eq!(i.value(), Some(1));
		i.go_next();
		assert_eq!(i.value(), Some(2));
		i.go_next();
		assert_eq!(i.value(), Some(3));
		i.go_next();
		assert_eq!(i.value(), None);
	}

	#[test]
	fn wrapping_index_go_prev() {
		let mut i = WrappingIndex::new(4.try_into().unwrap());
		assert_eq!(i.value(), None);
		i.go_prev();
		assert_eq!(i.value(), Some(3));
		i.go_prev();
		assert_eq!(i.value(), Some(2));
		i.go_prev();
		assert_eq!(i.value(), Some(1));
		i.go_prev();
		assert_eq!(i.value(), Some(0));
		i.go_prev();
		assert_eq!(i.value(), None);
	}

	#[test]
	fn string_list_push() {
		let mut sl = StringList::default();
		assert!(sl.buf.is_empty());
		assert!(sl.end_pos.is_empty());
		sl.push("hello");
		assert_eq!(sl.buf, "hello");
		assert_eq!(sl.end_pos, vec![5]);
		sl.push("world");
		assert_eq!(sl.buf, "helloworld");
		assert_eq!(sl.end_pos, vec![5, 10]);
		sl.push("another");
		assert_eq!(sl.buf, "helloworldanother");
		assert_eq!(sl.end_pos, vec![5, 10, 17]);
		sl.push("word");
		assert_eq!(sl.buf, "helloworldanotherword");
		assert_eq!(sl.end_pos, vec![5, 10, 17, 21]);
	}

	#[test]
	fn string_list_clear() {
		let mut sl = StringList::default();
		assert!(sl.buf.is_empty());
		assert!(sl.end_pos.is_empty());
		sl.push("hello");
		sl.push("hello");
		sl.push("hello");
		sl.push("hello");
		sl.clear();
		assert!(sl.buf.is_empty());
		assert!(sl.end_pos.is_empty());
	}

	#[test]
	fn string_list_iter() {
		let mut sl = StringList::default();
		assert!(sl.buf.is_empty());
		assert!(sl.end_pos.is_empty());
		assert_eq!(sl.iter().collect::<Vec<&str>>(), Vec::<&str>::new());
		sl.push("Hello");
		assert_eq!(sl.iter().collect::<Vec<_>>(), vec!["Hello"]);
		sl.push("World");
		assert_eq!(sl.iter().collect::<Vec<_>>(), vec!["Hello", "World"]);
		sl.push("test");
		assert_eq!(
			sl.iter().collect::<Vec<_>>(),
			vec!["Hello", "World", "test"]
		);
		sl.push("test");
		assert_eq!(
			sl.iter().collect::<Vec<_>>(),
			vec!["Hello", "World", "test", "test"]
		);
	}

	#[test]
	fn string_list_get() {
		let mut sl = StringList::default();
		assert!(sl.buf.is_empty());
		assert!(sl.end_pos.is_empty());

		sl.push("Hello");
		sl.push("World");
		assert_eq!(sl.get(0), Some("Hello"));
		assert_eq!(sl.get(1), Some("World"));
		assert_eq!(sl.get(2), None);

		sl.push("test");
		assert_eq!(sl.get(1), Some("World"));
		assert_eq!(sl.get(2), Some("test"));
		assert_eq!(sl.get(3), None);
	}
}
