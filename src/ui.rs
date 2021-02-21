use crate::scan::Scan;
use std::collections::BTreeMap;
use std::fmt::Display;
use std::io::{stdin, stdout, Write};
use std::str::FromStr;

// ASCII codes for backspace and escape keys (why does Rust not have escape
// sequences for these? https://doc.rust-lang.org/stable/reference/tokens.html#ascii-escapes).
const BACK: char = 0x08 as char;
const ESCAPE: char = 0x1B as char;

/// Wait for a single key to be pressed in the terminal.
fn wait_key() -> char {
    use crossterm::event::{read, Event, KeyCode};

    loop {
        break match read().unwrap() {
            Event::Key(event) => match event.code {
                KeyCode::Backspace => BACK,
                KeyCode::Enter => '\n',
                KeyCode::Tab => '\t',
                KeyCode::Delete => BACK,
                KeyCode::Char(c) => c,
                KeyCode::Esc => ESCAPE,
                // Arrow and function keys among others are ignored.
                _ => continue,
            },
            // Ignore resize and mouse events (which are not enabled anyway).
            _ => continue,
        };
    }
}

/// Print a message inline and wait for the user to type another line.
/// Behaves much like Python's `input`.
pub fn prompt<F: FromStr>(message: &str) -> Result<F, F::Err> {
    {
        let stdout = stdout();
        let mut stdout = stdout.lock();
        stdout.write_all(message.as_bytes()).unwrap();
        stdout.flush().unwrap();
    }
    let mut input = String::new();
    stdin().read_line(&mut input).unwrap();
    input.trim().parse()
}

/// Shows an interactive list picker, where users can refine their search.
/// Not picking an item results in a panic.
pub fn list_picker<T: Display>(items: &[T]) -> &T {
    use crossterm::{
        cursor::MoveTo,
        execute,
        terminal::{Clear, ClearType},
    };

    let (_cols, rows) = crossterm::terminal::size().unwrap();
    let rows = rows as usize;
    let mapping = items
        .iter()
        .enumerate()
        .map(|(i, item)| (item.to_string(), i))
        .collect::<BTreeMap<_, _>>();

    let mut filter = String::new();
    let picked = loop {
        let filtered = mapping
            .iter()
            .filter(|(key, _)| key.to_lowercase().contains(&filter))
            .collect::<Vec<_>>();

        let y = (rows - 1).checked_sub(filtered.len()).unwrap_or(0) as u16;
        execute!(stdout(), Clear(ClearType::All), MoveTo(0, y)).unwrap();

        filtered
            .iter()
            .take(rows - 1)
            .for_each(|(key, _)| println!("{}", key));
        print!("> type filter (press Enter when done): {}", filter);
        stdout().flush().unwrap();

        match wait_key() {
            BACK => drop(filter.pop()),
            ESCAPE => panic!("refused to pick item"),
            '\n' => {
                if !filtered.is_empty() {
                    break filtered;
                }
            }
            c => filter.push(c),
        }
    };

    let index = if picked.len() > 1 {
        execute!(stdout(), Clear(ClearType::All), MoveTo(0, 0)).unwrap();
        picked
            .iter()
            .enumerate()
            .for_each(|(i, (key, _))| println!("{}. {}", i, key));

        prompt::<usize>("Which of the filtered items do you want?: ").unwrap()
    } else {
        println!();
        0
    };

    &items[*picked[index].1]
}

/// Prompt the user to perform a scan.
pub fn prompt_scan() -> Result<Scan, std::num::ParseIntError> {
    let mut input = String::new();
    loop {
        {
            let stdout = stdout();
            let mut stdout = stdout.lock();
            stdout.write_all("scan (? for help)> ".as_bytes()).unwrap();
            stdout.flush().unwrap();
        }
        input.clear();
        stdin().read_line(&mut input).unwrap();
        let value = input.trim();
        if value.is_empty() {
            panic!("must provide a value");
        }

        break Ok(match value.as_bytes()[0] {
            b'?' => {
                println!("= Scan interface =");
                println!("| Allowed prefixes:");
                println!("|   (empty): exact value scan");
                println!("|   u: unknown value");
                println!("|   =: unchanged value");
                println!("|   ~: changed value");
                println!("|   d: decreased value");
                println!("|   i: increased value");
                println!("|");
                println!("| Scan for range with no prefix LOW..HIGH (or inclusive ..=)");
                continue;
            }
            b'u' => Scan::Unknown,
            b'=' => Scan::Unchanged,
            b'~' => Scan::Changed,
            t @ b'd' | t @ b'i' => {
                let n = value[1..].trim();
                if n.is_empty() {
                    if t == b'd' {
                        Scan::Decreased
                    } else {
                        Scan::Increased
                    }
                } else {
                    let n = value.parse()?;
                    if t == b'd' {
                        Scan::DecreasedBy(n)
                    } else {
                        Scan::IncreasedBy(n)
                    }
                }
            }
            _ => {
                let (low, high) = if let Some(i) = value.find("..") {
                    (value[..i].parse()?, value[i + 2..].parse::<i32>()? - 1)
                } else if let Some(i) = value.find("..=") {
                    (value[..i].parse()?, value[i + 3..].parse()?)
                } else {
                    let n = value.parse()?;
                    (n, n)
                };

                if low == high {
                    Scan::Exact(low)
                } else {
                    Scan::InRange(low, high)
                }
            }
        });
    }
}
