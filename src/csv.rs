//! CSV as PAN-OS and FortiGate write it: commas, quoted cells with
//! doubled quotes, line breaks inside quotes (in exports).

/// The rows of `text`, each with the line it starts on (from 1); rows of
/// empty cells only are left out.
pub(crate) fn rows(text: &str) -> Vec<(usize, Vec<String>)> {
    let mut rows = Vec::new();
    let mut row = Vec::new();
    let mut cell = String::new();
    let mut quoted = false;
    let mut line = 1;
    let mut start = 1;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match (c, quoted) {
            ('"', true) if chars.peek() == Some(&'"') => {
                cell.push('"');
                chars.next();
            }
            ('"', true) => quoted = false,
            ('"', false) if cell.is_empty() => quoted = true,
            (',', false) => row.push(std::mem::take(&mut cell)),
            ('\r', false) => {}
            ('\n', false) => {
                row.push(std::mem::take(&mut cell));
                push_row(&mut rows, start, std::mem::take(&mut row));
                line += 1;
                start = line;
            }
            ('\n', true) => {
                cell.push('\n');
                line += 1;
            }
            (c, _) => cell.push(c),
        }
    }
    row.push(cell);
    push_row(&mut rows, start, row);
    rows
}

/// One line's cells.
pub(crate) fn cells(line: &str) -> Vec<String> {
    rows(line)
        .into_iter()
        .next()
        .map(|(_, row)| row)
        .unwrap_or_default()
}

fn push_row(rows: &mut Vec<(usize, Vec<String>)>, start: usize, row: Vec<String>) {
    if row.iter().any(|cell| !cell.is_empty()) {
        rows.push((start, row));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_and_line_breaks() {
        let rows = rows("a,b\r\n\"x,\"\"y\"\"\",\"1\n2\"\n\n3,4");
        assert_eq!(
            rows,
            [
                (1, vec!["a".to_owned(), "b".to_owned()]),
                (2, vec!["x,\"y\"".to_owned(), "1\n2".to_owned()]),
                (5, vec!["3".to_owned(), "4".to_owned()]),
            ]
        );
        assert_eq!(cells("1,,\"a,b\""), ["1", "", "a,b"]);
    }
}
