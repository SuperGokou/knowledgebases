import type { ChatDataTable as ChatDataTableValue } from "@/lib/types";

export function ChatDataTable({ table }: { table: ChatDataTableValue }) {
  return (
    <section className="chat-data-card" aria-label={table.title}>
      <div className="chat-data-scroll" tabIndex={0} aria-label={`${table.title}，可横向滚动`}>
        <table>
          <caption>{table.title}</caption>
          <thead>
            <tr>{table.columns.map((column) => <th scope="col" key={column}>{column}</th>)}</tr>
          </thead>
          <tbody>
            {table.rows.map((row, rowIndex) => (
              <tr key={`${rowIndex}-${row.join("-")}`}>
                {row.map((cell, columnIndex) => <td key={`${columnIndex}-${cell}`}>{cell}</td>)}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p>数据来源：{table.citation_numbers.map((number) => `[${number}]`).join("、")}</p>
    </section>
  );
}
