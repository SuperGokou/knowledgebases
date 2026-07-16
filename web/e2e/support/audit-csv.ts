export function parseRfc4180Csv(source: string): string[][] {
  const rows: string[][] = [];
  let currentRow: string[] = [];
  let currentField = "";
  let quoted = false;
  let quoteClosed = false;

  const pushField = () => {
    currentRow.push(currentField);
    currentField = "";
    quoteClosed = false;
  };
  const pushRow = () => {
    pushField();
    rows.push(currentRow);
    currentRow = [];
  };

  for (let index = 0; index < source.length; index += 1) {
    const character = source[index]!;
    if (quoted) {
      if (character === '"') {
        if (source[index + 1] === '"') {
          currentField += '"';
          index += 1;
        } else {
          quoted = false;
          quoteClosed = true;
        }
      } else {
        currentField += character;
      }
      continue;
    }
    if (character === '"') {
      if (currentField || quoteClosed) throw new Error("audit CSV contains an invalid quote");
      quoted = true;
      continue;
    }
    if (character === ",") {
      pushField();
      continue;
    }
    if (character === "\r") {
      if (source[index + 1] !== "\n") {
        throw new Error("audit CSV must use RFC 4180 CRLF records");
      }
      pushRow();
      index += 1;
      continue;
    }
    if (character === "\n") throw new Error("audit CSV contains a bare LF record");
    if (quoteClosed) throw new Error("audit CSV contains characters after a closing quote");
    currentField += character;
  }
  if (quoted) throw new Error("audit CSV contains an unterminated quoted field");
  if (currentField || currentRow.length > 0 || quoteClosed) pushRow();
  return rows;
}
