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

use crossterm::event::{self, Event as RawEvent, KeyCode, KeyModifiers};
use event::KeyEvent;
use std::{sync::mpsc, thread, time::Duration};

const KEYS_QUIT: &[KeyEvent] = &[
	KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE),
	KeyEvent::new(KeyCode::Char('Q'), KeyModifiers::NONE),
	KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
	KeyEvent::new(KeyCode::Char('C'), KeyModifiers::CONTROL),
	KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE),
];

const KEY_UP: KeyEvent = KeyEvent::new(KeyCode::Up, KeyModifiers::NONE);
const KEY_DOWN: KeyEvent = KeyEvent::new(KeyCode::Down, KeyModifiers::NONE);
const KEY_LEFT: KeyEvent = KeyEvent::new(KeyCode::Left, KeyModifiers::NONE);
const KEY_RIGHT: KeyEvent = KeyEvent::new(KeyCode::Right, KeyModifiers::NONE);
const KEY_FOLLOWING: KeyEvent = KeyEvent::new(KeyCode::Char('f'), KeyModifiers::NONE);
const KEY_FOLLOWING_2: KeyEvent = KeyEvent::new(KeyCode::Char('F'), KeyModifiers::NONE);

#[derive(Debug)]
pub enum Event {
	Update,
	Input(InputEvent, usize),
	Stop,
	Resize { width: u16, height: u16 },
}

pub struct EventManager {
	event_receiver: mpsc::Receiver<Event>,
	_input_handle: thread::JoinHandle<()>,
	_update_handle: thread::JoinHandle<()>,
	_stop_handle: thread::JoinHandle<()>,
}

impl EventManager {
	pub fn new(stop_receiver: mpsc::Receiver<()>, update_interval: Duration) -> Self {
		let (event_sender, event_receiver) = mpsc::channel();
		let input_handle = {
			let sender = event_sender.clone();
			thread::spawn(move || {
				if let Err(e) = read_events(&sender) {
					log::error!("Error when reading terminal events ({})", e);
				}
			})
		};
		let stop_handle = {
			let sender = event_sender.clone();
			thread::spawn(move || wait_for_stop(&stop_receiver, &sender))
		};
		let update_handle = {
			let sender = event_sender;
			thread::spawn(move || periodic_update(update_interval, &sender))
		};
		EventManager {
			event_receiver,
			_input_handle: input_handle,
			_update_handle: update_handle,
			_stop_handle: stop_handle,
		}
	}

	/// Returns an event when available.
	///
	/// This methods will block until there is a new event or error.
	///
	/// # Error
	/// Returns error when no more events can be received,
	/// maybe caused by event threads panicking or not properly initialized.
	pub fn next(&self) -> Result<Event, mpsc::RecvError> {
		self.event_receiver.recv()
	}
}

fn try_read_duplicate_events(
	stream: &mut PeekableEventReader,
	curr: &KeyEvent,
) -> crossterm::Result<usize> {
	let mut count = 0;
	while let Some(next) = stream.peek()? {
		if let RawEvent::Key(next) = &next {
			if next == curr {
				count += 1;
				continue;
			}
		}
		break;
	}
	Ok(count)
}

#[derive(Default)]
struct PeekableEventReader {
	buf: Option<RawEvent>,
}

impl PeekableEventReader {
	fn read(&mut self) -> crossterm::Result<RawEvent> {
		self.buf.take().map_or_else(event::read, Ok)
	}

	fn peek(&mut self) -> crossterm::Result<Option<&RawEvent>> {
        if self.buf.is_some() {
            return Ok(self.buf.as_ref());
        }
		if event::poll(Duration::from_secs(0))? {
			let e = event::read()?;
			self.buf = Some(e);
			return Ok(self.buf.as_ref());
		}
		Ok(None)
	}
}

fn read_events(sender: &mpsc::Sender<Event>) -> crossterm::Result<()> {
	let mut stream = PeekableEventReader::default();
	loop {
		let e = stream.read()?;
		let event = match e {
			RawEvent::Key(key_event) => {
				if let Some(ie) = InputEvent::from_key_event(&key_event) {
					let additional_count = try_read_duplicate_events(&mut stream, &key_event)?;
					Some(Event::Input(ie, 1 + additional_count))
				} else {
					None
				}
			}
			RawEvent::Resize(width, height) => Some(Event::Resize { width, height }),
			_ => None,
		};
		if let Some(event) = event {
			if let Err(err) = sender.send(event) {
				log::error!("Cannot send key event ({})", err);
			}
		}
	}
}

fn wait_for_stop(stop_receiver: &mpsc::Receiver<()>, sender: &mpsc::Sender<Event>) {
	if let Err(e) = stop_receiver.recv() {
		// This error is caused by sender thread panicking, so it's safe to ignore.
		// The whole thing is going to stop anyway.
		log::debug!("Error when trying to send stop signal: {e}");
	}
	if let Err(_e) = sender.send(Event::Stop) {
		// Same as above.
		log::debug!("Error when trying to send stop to events");
	};
}

fn periodic_update(dur: Duration, sender: &mpsc::Sender<Event>) {
	loop {
		if sender.send(Event::Update).is_err() {
			break;
		}
		thread::sleep(dur);
	}
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum InputEvent {
	Quit,
	MoveUp,
	MoveDown,
	MoveLeft,
	MoveRight,
	ToggleFollowing,
}

impl InputEvent {
	pub fn from_key_event(e: &KeyEvent) -> Option<Self> {
		if KEYS_QUIT.contains(e) {
			return Some(Self::Quit);
		}
		let e = *e;
		Some(if e == KEY_UP {
			Self::MoveUp
		} else if e == KEY_DOWN {
			Self::MoveDown
		} else if e == KEY_LEFT {
			Self::MoveLeft
		} else if e == KEY_RIGHT {
			Self::MoveRight
		} else if e == KEY_FOLLOWING_2 || e == KEY_FOLLOWING {
			Self::ToggleFollowing
		} else {
			return None;
		})
	}
}
