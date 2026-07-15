import type { ChatDataTable as ChatDataTableValue } from "@/lib/types";

export function ChatDataTable({ table }: { table: ChatDataTableValue }) {
  const hasRowSources =
    Array.isArray(table.row_citation_numbers) &&
    table.row_citation_numbers.length === table.rows.length;

  return (
    <section className="chat-data-card" aria-label={table.title}>
      <div className="chat-data-scroll" tabIndex={0} aria-label={`${table.title}，可横向滚动`}>
        <table>
          <caption>{table.title}</caption>
          <thead>
            <tr>
              {table.columns.map((column) => <th scope="col" key={column}>{column}</th>)}
              {hasRowSources ? <th scope="col">来源</th> : null}
            </tr>
          </thead>
          <tbody>
            {table.rows.map((row, rowIndex) => (
              <tr key={`${rowIndex}-${row.join("-")}`}>
                {row.map((cell, columnIndex) => <td key={`${columnIndex}-${cell}`}>{cell}</td>)}
                {hasRowSources ? (
                  <td>
                    <span
                      className="chat-row-sources"
                      aria-label={`第 ${rowIndex + 1} 行来源 ${table.row_citation_numbers?.[rowIndex]?.map((number) => `[${number}]`).join("、")}`}
                    >
                      {table.row_citation_numbers?.[rowIndex]?.map((number) => `[${number}]`).join("、")}
                    </span>
                  </td>
                ) : null}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p>{hasRowSources ? "逐行来源已核验" : "整表来源"}：{table.citation_numbers.map((number) => `[${number}]`).join("、")}</p>
    </section>
  );
}
