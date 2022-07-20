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

mod data_manager;
mod display_helper;
mod events;
mod renderer;

use super::BoxStdErr;
use crossterm::{cursor, execute, terminal};
use data_manager::DataManager;
use display_helper::SecondsCount;
use events::{Event, EventManager, InputEvent};
use ladder_lib::server::stat::{CounterValue, Id, Monitor, Snapshot};
use log::trace;
use renderer::Renderer;
use std::{collections::HashMap, convert::TryFrom, io, sync::mpsc, time::Duration};
use tui::{backend::CrosstermBackend, Terminal};

type RowTexts = [String; ColumnIndex::ColNum as usize];

/// Default interval between each TUI update
pub const DEFAULT_UPDATE_INTERVAL: Duration = Duration::from_secs(1);

const DEFAULT_RESERVE_FRAMES_NUM: usize = 32;

/// (header name, cell length) of each column
const ROW_ITEM_INFO: &[(&str, u16); ColumnIndex::ColNum as usize] = &[
	("ID", 3),
	("INBOUND", 4),
	("OUTBOUND", 4),
	("DST", 12),
	("RECV", 4),
	("SEND", 4),
	("LASTED", 4),
	("STATE", 4),
];

#[derive(Copy, Clone)]
enum ColumnIndex {
	ConnId,
	Inbound,
	Outbound,
	Dst,
	Recv,
	Send,
	Lasted,
	State,
	ColNum,
}

impl ColumnIndex {
	fn from_num(num: isize) -> Option<ColumnIndex> {
		Some(match num {
			0 => Self::ConnId,
			1 => Self::Inbound,
			2 => Self::Outbound,
			3 => Self::Dst,
			4 => Self::Recv,
			5 => Self::Send,
			6 => Self::Lasted,
			7 => Self::State,
			_ => return None,
		})
	}

	fn get_mut<'a, T>(&self, row_texts: &'a mut [T; ColumnIndex::ColNum as usize]) -> &'a mut T {
		&mut row_texts[*self as usize]
	}

	fn first() -> Self {
		Self::ConnId
	}

	fn last() -> Self {
		Self::State
	}
}

pub fn run(
	stop_receiver: mpsc::Receiver<()>,
	update_interval: Duration,
	monitor: Monitor,
	rt: tokio::runtime::Handle,
) -> Result<(), BoxStdErr> {
	setup_panic();
	trace!(
		"Running TUI with tickrate {} ms",
		update_interval.as_millis()
	);
	let backend = CrosstermBackend::new(io::stdout());
	let mut terminal = Terminal::new(backend)?;

	setup_terminal()?;

	let events = EventManager::new(stop_receiver, update_interval);

	// let mut last_update_time = Instant::now();

	let mut renderer = Renderer::new();
	let mut data_manager = DataManager::new(rt, monitor);

	let mut sort_column: Option<ColumnIndex> = None;

	let mut row_manager = SelectedRowManager::default();

	loop {
		// Try to get an event.
		let e = events.next()?;
		let res = match e {
			Event::Update => handle_update(&mut data_manager, &mut row_manager, sort_column),
			Event::Input(ie, count) => handle_input(
				&mut data_manager,
				&mut row_manager,
				&mut renderer,
				&mut sort_column,
				ie,
				count,
			),
			Event::Stop => UpdateResult::Stop,
			Event::Resize {
				width: _,
				height: _,
			} => UpdateResult::Update(UpdateOptions::default()),
		};

		match res {
			UpdateResult::Stop => {
				cleanup_terminal()?;
				return Ok(());
			}
			UpdateResult::Update(options) => {
				if options.selected_row {
					renderer
						.set_selected_row(row_manager.curr_row_index(), row_manager.is_following());
				}

				if options.chart {
					let total_speed = sum_speed(data_manager.snapshots().map(Snapshot::speed));
					renderer.update_speed_chart(&total_speed);
				}

				if options.table_text {
					renderer.update_table(data_manager.snapshots());
				}
			}
		}
		renderer.draw(&mut terminal)?;
	}
}

enum UpdateResult {
	Stop,
	Update(UpdateOptions),
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Default)]
struct UpdateOptions {
	/// True if texts in renderer's table need update.
	table_text: bool,
	/// True if charts in renderer needs update.
	chart: bool,
	/// True if selected row in renderer's table needs update.
	selected_row: bool,
}

fn handle_update(
	// last_update_time: &mut Instant,
	data_manager: &mut DataManager,
	row_manager: &mut SelectedRowManager,
	sort_column: Option<ColumnIndex>,
) -> UpdateResult {
	trace!("Update event");
	data_manager.update();
	// immediately sort these data
	data_manager.sort(sort_column);
	// update selected row
	row_manager.update(data_manager.snapshots());

	trace!(
		"Update finished, data rows count: {}",
		data_manager.row_count()
	);

	// only update speed chart on 'Update' event
	UpdateResult::Update(UpdateOptions {
		table_text: true,
		chart: true,
		selected_row: true,
	})
}

fn handle_input(
	data_manager: &mut DataManager,
	row_manager: &mut SelectedRowManager,
	renderer: &mut Renderer,
	sort_column: &mut Option<ColumnIndex>,
	ie: InputEvent,
	count: usize,
) -> UpdateResult {
	let mut options = UpdateOptions::default();
	match ie {
		InputEvent::Quit => {
			return UpdateResult::Stop;
		}
		InputEvent::MoveUp => {
			row_manager.move_selected(RowDirection::Up, count);
			options.selected_row = true;
		}
		InputEvent::MoveDown => {
			row_manager.move_selected(RowDirection::Down, count);
			options.selected_row = true;
		}
		InputEvent::MoveLeft => {
			move_column(sort_column, ColumnDirection::Left);
			data_manager.sort(*sort_column);
			row_manager.update(data_manager.snapshots());
			renderer.set_sort_column(*sort_column);
			options.selected_row = true;
			options.table_text = true;
		}
		InputEvent::MoveRight => {
			move_column(sort_column, ColumnDirection::Right);
			data_manager.sort(*sort_column);
			row_manager.update(data_manager.snapshots());
			renderer.set_sort_column(*sort_column);
			options.selected_row = true;
			options.table_text = true;
		}
		InputEvent::ToggleFollowing => {
			row_manager.toggle_following();
			options.selected_row = true;
			options.table_text = true;
		}
	};
	UpdateResult::Update(options)
}

fn sum_speed(speeds: impl Iterator<Item = CounterValue>) -> CounterValue {
	let mut res = CounterValue::new();
	for s in speeds {
		res += s;
	}
	res
}

#[derive(Clone, Copy)]
enum ColumnDirection {
	Left = -1_isize,
	Right = 1_isize,
}

fn move_column(col: &mut Option<ColumnIndex>, dir: ColumnDirection) {
	*col = col.map_or_else(
		|| match dir {
			ColumnDirection::Left => Some(ColumnIndex::last()),
			ColumnDirection::Right => Some(ColumnIndex::first()),
		},
		|c| {
			let delta = dir as isize;
			let next_col = (c as isize) + delta;
			ColumnIndex::from_num(next_col)
		},
	);
}

#[derive(Clone, Copy)]
enum RowDirection {
	Up = -1_isize,
	Down = 1_isize,
}

fn setup_panic() {
	let default_hook = std::panic::take_hook();
	std::panic::set_hook(Box::new(move |panic_info| {
		// Exits raw mode.
		if let Err(err) = cleanup_terminal() {
			log::error!("Error when cleaning up terminal in panic hook ({})", err);
		};
		default_hook(panic_info);
	}));
}

fn setup_terminal() -> Result<(), BoxStdErr> {
	let mut stdout = io::stdout();

	execute!(stdout, terminal::EnterAlternateScreen)?;
	// execute!(stdout, EnableMouseCapture)?;
	execute!(stdout, cursor::Hide)?;

	// Needed for when ytop is run in a TTY since TTYs don't actually have an alternate screen.
	// Must be executed after attempting to enter the alternate screen so that it only clears the
	// 		primary screen if we are running in a TTY.
	// If not running in a TTY, then we just end up clearing the alternate screen which should have
	// 		no effect.
	execute!(stdout, terminal::Clear(terminal::ClearType::All))?;

	terminal::enable_raw_mode()?;
	Ok(())
}

fn cleanup_terminal() -> Result<(), BoxStdErr> {
	let mut stdout = io::stdout();

	// Needed for when ytop is run in a TTY since TTYs don't actually have an alternate screen.
	// Must be executed before attempting to leave the alternate screen so that it only modifies the
	// 		primary screen if we are running in a TTY.
	// If not running in a TTY, then we just end up modifying the alternate screen which should have
	// 		no effect.
	execute!(stdout, cursor::MoveTo(0, 0))?;
	execute!(stdout, terminal::Clear(terminal::ClearType::All))?;

	// execute!(stdout, DisableMouseCapture)?;
	execute!(stdout, terminal::LeaveAlternateScreen)?;
	execute!(stdout, cursor::Show)?;

	terminal::disable_raw_mode()?;

	Ok(())
}

#[derive(Default)]
struct SelectedRowManager {
	conns_to_rows: HashMap<Id, usize>,
	rows_to_conns: Vec<Id>,
	curr_row_index: Option<usize>,
	is_following: bool,
}

impl SelectedRowManager {
	/// Call this when snapshots is updated or sorted.
	fn update<'a>(&mut self, snapshots: impl Iterator<Item = &'a Snapshot>) {
		let old_conn_id = self.curr_row_index.map(|ind| self.rows_to_conns[ind]);
		self.conns_to_rows.clear();
		self.rows_to_conns.clear();
		for (row_ind, snapshot) in snapshots.enumerate() {
			let id = snapshot.id();
			debug_assert!(!self.conns_to_rows.contains_key(&id));
			self.conns_to_rows.insert(id, row_ind);
			self.rows_to_conns.push(id);
		}
		if self.is_following {
			if let Some(id) = old_conn_id {
				if let Some(new_row_ind) = self.conns_to_rows.get(&id) {
					self.curr_row_index = Some(*new_row_ind);
				} else {
					self.curr_row_index = None;
				}
			}
		} else if let Some(row_ind) = self.curr_row_index {
			if row_ind >= self.rows_to_conns.len() {
				self.curr_row_index = None;
			}
		}
	}

	fn is_following(&self) -> bool {
		self.is_following
	}

	fn toggle_following(&mut self) {
		self.is_following = !self.is_following;
	}

	fn curr_row_index(&self) -> Option<usize> {
		self.curr_row_index
	}

	fn move_selected(&mut self, dir: RowDirection, move_count: usize) {
		self.is_following = false;

		let total_rows_count = self.rows_to_conns.len();
		let curr_row = &mut self.curr_row_index;

		if total_rows_count == 0 {
			*curr_row = None;
			return;
		}
		*curr_row = curr_row.map_or_else(
			|| {
				Some(match dir {
					RowDirection::Up => total_rows_count - 1,
					RowDirection::Down => 0,
				})
			},
			|curr_row| add_dir(curr_row, total_rows_count, dir, move_count),
		);
	}
}

fn add_dir(
	curr_row: usize,
	total_rows_count: usize,
	dir: RowDirection,
	move_count: usize,
) -> Option<usize> {
	let delta = dir as isize * isize::try_from(move_count).unwrap();
	let next_row = isize::try_from(curr_row).unwrap() + delta;
	// If next_row >= 0
	if let Ok(next_row) = usize::try_from(next_row) {
		if next_row < total_rows_count {
			return Some(next_row);
		}
	}
	None
}
