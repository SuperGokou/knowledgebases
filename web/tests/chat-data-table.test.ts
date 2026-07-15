import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { ChatDataTable } from "../src/components/chat-data-table";

describe("ChatDataTable", () => {
  it("renders a semantic, source-labelled data table", () => {
    const html = renderToStaticMarkup(
      createElement(ChatDataTable, {
        table: {
          title: "公司联系人信息",
          columns: ["项目", "信息"],
          rows: [["联系人", "张经理"], ["联系电话", "0514-00000000"]],
          citation_numbers: [1],
          row_citation_numbers: [[1], [1]],
        },
      }),
    );

    expect(html).toContain("<table");
    expect(html).toContain("<caption>公司联系人信息</caption>");
    expect(html).toContain('<th scope="col">项目</th>');
    expect(html).toContain('<th scope="col">来源</th>');
    expect(html).toContain("张经理");
    expect(html).toContain("第 1 行来源 [1]");
    expect(html).toContain("逐行来源已核验：[1]");
  });

  it("keeps legacy tables compatible without claiming row-level provenance", () => {
    const html = renderToStaticMarkup(
      createElement(ChatDataTable, {
        table: {
          title: "历史数据",
          columns: ["项目"],
          rows: [["旧记录"]],
          citation_numbers: [1, 2],
        },
      }),
    );

    expect(html).not.toContain('<th scope="col">来源</th>');
    expect(html).toContain("整表来源：[1]、[2]");
  });

  it("escapes untrusted table cells instead of interpreting markup", () => {
    const html = renderToStaticMarkup(
      createElement(ChatDataTable, {
        table: {
          title: "安全数据",
          columns: ["内容"],
          rows: [["<img src=x onerror=alert(1)>"]],
          citation_numbers: [1],
          row_citation_numbers: [[1]],
        },
      }),
    );

    expect(html).not.toContain("<img");
    expect(html).toContain("&lt;img src=x onerror=alert(1)&gt;");
  });
});
