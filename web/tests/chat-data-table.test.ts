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
        },
      }),
    );

    expect(html).toContain("<table");
    expect(html).toContain("<caption>公司联系人信息</caption>");
    expect(html).toContain('<th scope="col">项目</th>');
    expect(html).toContain("张经理");
    expect(html).toContain("数据来源：[1]");
  });
});
