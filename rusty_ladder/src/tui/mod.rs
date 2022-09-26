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

mod display_helper;
mod events;
mod view;

use self::view::View;
use super::BoxStdErr;
use crossterm::{cursor, execute, terminal};
use events::{Event, EventManager, InputEvent};
use ladder_lib::{
	server::stat::{Monitor, Snapshot},
	Server,
};
use log::trace;
use std::{io, sync::mpsc, time::Duration};
use tui::{backend::CrosstermBackend, Terminal};

/// Default interval between each TUI update
pub const DEFAULT_UPDATE_INTERVAL: Duration = Duration::from_secs(1);

pub struct Tui {
	view: View,
}

impl Tui {
	pub fn new(s: &Server) -> Self {
		Self { view: View::new(s) }
	}

	pub fn run(
		mut self,
		stop_receiver: mpsc::Receiver<()>,
		update_interval: Duration,
		monitor: &Monitor,
	) -> Result<(), BoxStdErr> {
		run(&mut self.view, stop_receiver, update_interval, monitor)
	}
}

fn run(
	view: &mut View,
	stop_receiver: mpsc::Receiver<()>,
	update_interval: Duration,
	monitor: &Monitor,
) -> Result<(), BoxStdErr> {
	setup_panic();
	trace!(
		"Running TUI with tickrate {} ms",
		update_interval.as_millis()
	);
	let backend = CrosstermBackend::new(io::stdout());
	let mut terminal = Terminal::new(backend)?;

	setup_terminal()?;

	let events_receiver = EventManager::new(stop_receiver, update_interval);
	let mut snapshots = Vec::new();

	loop {
		// Try to get an event.
		let e = events_receiver.next()?;
		let mut stop = false;
		let mut force_redraw = false;
		match e {
			Event::Update => {
				get_snapshots(monitor, &mut snapshots);
				view.update(&snapshots);
			}
			// Checking input
			Event::Input(ie, count) => match ie {
				InputEvent::Quit => stop = true,
				InputEvent::MoveUp => {
					view.conn_table.set_selected_row_prev(count);
				}
				InputEvent::MoveDown => {
					view.conn_table.set_selected_row_next(count);
				}
				InputEvent::MoveLeft => {
					view.conn_table.set_sort_column_prev();
				}
				InputEvent::MoveRight => {
					view.conn_table.set_sort_column_next();
				}
				InputEvent::ToggleFollowing => {
					view.conn_table.toggle_following();
				}
			},
			Event::Stop => stop = true,
			Event::Resize {
				width: _,
				height: _,
			} => force_redraw = true,
		};

		if stop {
			cleanup_terminal()?;
			return Ok(());
		}
		view.draw(&mut terminal, force_redraw)?;
	}
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

fn get_snapshots(monitor: &Monitor, result: &mut Vec<Snapshot>) {
	trace!("Getting data from monitor...");
	result.clear();
	monitor.query(&ladder_lib::server::stat::Filter::new_all(), result);
	trace!("{} snapshots received.", result.len());
}
